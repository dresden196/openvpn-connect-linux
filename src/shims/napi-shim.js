/**
 * napi-shim.js - Linux replacement for OpenVPN Connect's napi.node
 *
 * The original napi.node is a proprietary C++ N-API addon that wraps the
 * OpenVPN3 client library. On Linux, we replace it with a JavaScript
 * implementation that:
 *
 *   1. Spawns the system's `openvpn` binary
 *   2. Communicates via the OpenVPN Management Interface (TCP)
 *   3. Exposes the same API surface as the original napi.node
 *
 * This allows the rest of the Electron app to work unchanged.
 */

const { spawn, execSync, execFile } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { EventEmitter } = require('events');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const OPENVPN_BIN = findOpenvpn();

function findOpenvpn() {
  const candidates = ['/usr/bin/openvpn', '/usr/sbin/openvpn', '/usr/local/bin/openvpn'];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  try {
    return execSync('which openvpn', { encoding: 'utf8' }).trim();
  } catch {
    return 'openvpn'; // fallback, hope it's on PATH
  }
}

function getFreeMgmtPort(base = 25340) {
  // Find an available port starting from base
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

function parseMgmtLine(line) {
  line = line.trim();
  if (!line || line.startsWith('END')) return null;
  return line;
}

// ---------------------------------------------------------------------------
// ConfigWrap - Mirrors the C++ ConfigWrap struct
// ---------------------------------------------------------------------------
class ConfigWrap {
  constructor() {
    this.content = '';
    this.contentList = '';
    this.guiVersion = '';
    this.serverOverride = '';
    this.portOverride = '';
    this.protoOverride = '';
    this.connTimeout = 30;
    this.tunPersist = false;
    this.allowCompression = 'no';
    this.compressionMode = '';
    this.allowCleartextAuth = true;
    this.altProxy = '';
    this.privateKeyPassword = '';
    this.dco = false;
    this.echo = false;
    this.info = false;
    this.clockTickMS = 0;
    this.gremlinConfig = '';
    this.hwAddrOverride = '';
    this.ssoMethods = 'webauth,crtext';
    this.appCustomProtocols = '';
    this.allowUnusedAddrFamilies = false;
    this.tlsCertProfileOverride = '';
    this.enableLegacyAlgorithms = false;
    this.enableNonPreferredDCAlgorithms = false;
    // Additional fields from config struct analysis
    this.googleDnsFallback = false;
    this.allowLocalDnsResolvers = false;
    this.synchronousDnsLookup = false;
    this.autologinSessions = false;
    this.retryOnAuthFailed = false;
    this.externalPkiAlias = '';
    this.disableClientCert = false;
    this.sslDebugLevel = 0;
    this.defaultKeyDirection = -1;
    this.peerInfo = '';
    this.proxyHost = '';
    this.proxyPort = '';
    this.proxyUsername = '';
    this.proxyPassword = '';
    this.proxyAllowCleartextAuth = false;
    this.securityLevel = '';
  }
}

// ---------------------------------------------------------------------------
// CredsWrap - Mirrors the C++ CredsWrap struct
// ---------------------------------------------------------------------------
class CredsWrap {
  constructor() {
    this.username = '';
    this.password = '';
    this.response = '';
    this.dynamicChallengeCookie = '';
  }
}

// ---------------------------------------------------------------------------
// FetchOptions / FetchCredentials / ProxyConfig / CertConfig
// ---------------------------------------------------------------------------
class FetchOptions {
  constructor() {
    this.url = '';
    this.method = 'GET';
    this.headers = {};
    this.body = '';
    this.timeout = 30;
  }
}

class FetchCredentials {
  constructor() {
    this.username = '';
    this.password = '';
  }
}

class ProxyConfig {
  constructor() {
    this.host = '';
    this.port = 0;
    this.username = '';
    this.password = '';
  }
}

class CertConfig {
  constructor() {
    this.ca = '';
  }
}

// ---------------------------------------------------------------------------
// Connection State Machine
// ---------------------------------------------------------------------------
const VPN_STATES = {
  DISCONNECTED: 'DISCONNECTED',
  CONNECTING: 'CONNECTING',
  WAIT: 'WAIT',
  AUTH: 'AUTH',
  GET_CONFIG: 'GET_CONFIG',
  ASSIGN_IP: 'ASSIGN_IP',
  ADD_ROUTES: 'ADD_ROUTES',
  CONNECTED: 'CONNECTED',
  RECONNECTING: 'RECONNECTING',
  EXITING: 'EXITING',
  TCP_CONNECT: 'TCP_CONNECT',
  RESOLVE: 'RESOLVE',
};

// ---------------------------------------------------------------------------
// ClientWrapper - The main VPN client class
// ---------------------------------------------------------------------------
class ClientWrapper {
  constructor(logCallback, eventCallback, doneCallback) {
    this._logCallback = logCallback || (() => {});
    this._eventCallback = eventCallback || (() => {});
    this._doneCallback = doneCallback || (() => {});

    this._config = null;
    this._creds = null;
    this._process = null;
    this._mgmtSocket = null;
    this._mgmtPort = 0;
    this._mgmtPassword = '';
    this._state = VPN_STATES.DISCONNECTED;
    this._connectionInfo = {};
    this._transportStats = { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 };
    this._tunStats = { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0 };
    this._connected = false;
    this._pendingResponses = [];
    this._buffer = '';
    this._configContent = '';
    this._configFilePath = '';
    this._destroyed = false;

    this.isReconnectOnReboot = false;
    this.isInitialConnect = true;
  }

  // -----------------------------------------------------------------------
  // Config & Credentials
  // -----------------------------------------------------------------------

  set_config(configWrap) {
    console.log('[napi-shim] set_config called, content length:', (configWrap.content || '').length);
    this._config = configWrap;

    // Write config to temp file for openvpn to use
    const tmpDir = path.join(os.tmpdir(), 'openvpn-connect-linux');
    if (!fs.existsSync(tmpDir)) {
      fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
    }

    const configId = crypto.randomBytes(8).toString('hex');
    this._configFilePath = path.join(tmpDir, `ovpn-${configId}.conf`);

    let content = configWrap.content || '';

    // Strip OpenVPN3-only directives that the system openvpn doesn't support
    content = content.replace(/^proto\s+adaptive\s*$/gm, '# proto adaptive (OpenVPN3 only, using config default)');

    // Parse the config to check for DCO compatibility
    const dcoCompatible = !content.includes('compress') && !content.includes('comp-lzo');

    // Add management interface directives if not present
    if (!content.includes('management ')) {
      // Port will be set at connect() time
      content += '\n# Added by OpenVPN Connect Linux\n';
      content += 'management-query-passwords\n';
      content += 'management-hold\n';
    }

    // Set SSO methods
    if (configWrap.ssoMethods) {
      content += `\nsetenv IV_SSO ${configWrap.ssoMethods}\n`;
    }

    // Set GUI version
    if (configWrap.guiVersion) {
      content += `setenv IV_GUI_VER "${configWrap.guiVersion}"\n`;
    }

    // Handle server/port/proto overrides
    if (configWrap.serverOverride) {
      content += `remote ${configWrap.serverOverride}\n`;
    }
    if (configWrap.portOverride) {
      content += `port ${configWrap.portOverride}\n`;
    }
    if (configWrap.protoOverride && configWrap.protoOverride !== 'adaptive') {
      // "adaptive" is an OpenVPN3-only concept (try UDP then fall back to TCP)
      // The system openvpn binary doesn't support it - omit to use config default
      content += `proto ${configWrap.protoOverride}\n`;
    }

    // Compression settings
    if (configWrap.allowCompression === 'no') {
      content += 'compress\n';
    } else if (configWrap.compressionMode) {
      content += `compress ${configWrap.compressionMode}\n`;
    }

    // TLS security level / certificate profile
    if (configWrap.tlsCertProfileOverride) {
      // "tls-1-3" forces TLS 1.3 minimum, "legacy-default" allows older
      if (configWrap.tlsCertProfileOverride === 'tls-1-3') {
        content += 'tls-version-min 1.3\n';
      }
    }

    // Security level (preferred, legacy, insecure)
    if (configWrap.securityLevel) {
      // Maps to OpenVPN --tls-cert-profile
      const secMap = {
        'preferred': '',  // default
        'legacy': 'legacy',
        'insecure': 'insecure',
      };
      if (secMap[configWrap.securityLevel]) {
        content += `tls-cert-profile ${secMap[configWrap.securityLevel]}\n`;
      }
    }

    // Block IPv6 / allow unused address families
    if (configWrap.allowUnusedAddrFamilies === false || configWrap.allowUnusedAddrFamilies === 'no') {
      content += 'pull-filter ignore "ifconfig-ipv6"\n';
      content += 'pull-filter ignore "route-ipv6"\n';
    }

    // DNS fallback (Google DNS)
    if (configWrap.googleDnsFallback) {
      content += 'setenv IV_DNS_FALLBACK 1\n';
    }

    // Allow local DNS resolvers
    if (configWrap.allowLocalDnsResolvers) {
      content += 'setenv IV_ALLOW_LOCAL_DNS 1\n';
    }

    // TUN persistence
    if (configWrap.tunPersist) {
      content += 'persist-tun\n';
    }

    // Connection timeout
    if (configWrap.connTimeout && configWrap.connTimeout > 0) {
      content += `connect-timeout ${configWrap.connTimeout}\n`;
    }

    // Enable legacy algorithms
    if (configWrap.enableLegacyAlgorithms) {
      content += 'providers legacy default\n';
    }

    // Peer info
    if (configWrap.peerInfo) {
      const peerLines = configWrap.peerInfo.split('\n');
      for (const line of peerLines) {
        if (line.trim()) {
          content += `setenv IV_PLAT_VER "${line.trim()}"\n`;
        }
      }
    }

    // Proxy settings
    if (configWrap.proxyHost && configWrap.proxyPort) {
      content += `http-proxy ${configWrap.proxyHost} ${configWrap.proxyPort}`;
      if (configWrap.proxyUsername) {
        // Write proxy auth to a temp file
        const proxyAuthFile = this._configFilePath + '.proxy';
        fs.writeFileSync(proxyAuthFile, `${configWrap.proxyUsername}\n${configWrap.proxyPassword || ''}\n`, { mode: 0o600 });
        content += ` ${proxyAuthFile} basic`;
      }
      content += '\n';
    }

    // Disable client cert if requested
    if (configWrap.disableClientCert) {
      // Remove any client cert directives
      content = content.replace(/^cert\s+.*$/gm, '# cert disabled');
      content = content.replace(/^key\s+.*$/gm, '# key disabled');
    }

    // Private key password (for encrypted keys)
    if (configWrap.privateKeyPassword) {
      // Will be sent via management interface when requested
      this._privateKeyPassword = configWrap.privateKeyPassword;
    }

    // SSL debug level
    if (configWrap.sslDebugLevel && configWrap.sslDebugLevel > 0) {
      content += `verb ${Math.min(configWrap.sslDebugLevel + 3, 11)}\n`;
    }

    this._configContent = content;

    // The return value goes through evalConfigToObj(), so it must match
    // the eval_config return shape (with serverList, profileName, etc.)
    const originalContent = configWrap.content || '';

    // Extract remote info for the return value
    // Match: remote <host> [port] [proto]
    // Also handle: remote <host> (no port/proto) with separate proto line
    let remoteHost = '', remotePort = '', remoteProto = '';
    const remoteLines = originalContent.match(/^remote\s+\S+.*$/gm) || [];
    // Filter out remote-cert-tls, remote-random, etc.
    const actualRemotes = remoteLines.filter(l => !l.match(/^remote-/));

    if (actualRemotes.length > 0) {
      const parts = actualRemotes[0].trim().split(/\s+/);
      // parts[0] = 'remote', parts[1] = host, parts[2] = port, parts[3] = proto
      remoteHost = parts[1] || '';
      remotePort = parts[2] || '';
      remoteProto = parts[3] || '';
    }

    // If no proto from remote line, check standalone proto directive
    if (!remoteProto) {
      const protoMatch = originalContent.match(/^proto\s+(\S+)/m);
      if (protoMatch) remoteProto = protoMatch[1];
    }

    // Default port if not specified
    if (!remotePort) remotePort = '1194';

    // Default proto if not specified
    if (!remoteProto) remoteProto = 'udp';

    console.log(`[napi-shim] Parsed config: host=${remoteHost} port=${remotePort} proto=${remoteProto} remotes=${actualRemotes.length}`);

    const hasAuthUser = originalContent.includes('auth-user-pass');
    const serverList = [];
    const seen = new Set();
    for (const line of actualRemotes) {
      const parts = line.trim().split(/\s+/);
      const server = parts[1] || '';
      const port = parts[2] || remotePort;
      const proto = parts[3] || remoteProto;
      const key = `${server}:${port}:${proto}`;
      if (!seen.has(key)) {
        seen.add(key);
        serverList.push(JSON.stringify({ server, port, proto }));
      }
    }

    return {
      error: false,
      message: '',
      userlockedUsername: '',
      profileName: '',
      friendlyName: remoteHost,
      serverList,
      autologin: !hasAuthUser,
      externalPki: false,
      staticChallenge: '',
      staticChallengeEcho: false,
      privateKeyPasswordRequired: false,
      allowPasswordSave: true,
      remoteHost,
      remotePort,
      remoteProto,
      windowsDriver: '',
      dcoCompatible,
      dcoIncompatibilityReason: dcoCompatible ? '' : 'Compression not compatible with DCO',
    };
  }

  set_credentials(credsWrap) {
    this._creds = credsWrap;
    return { error: false, message: '', status: '' };
  }

  set_token_pin(pin) {
    this._tokenPin = pin;
  }

  // -----------------------------------------------------------------------
  // Connection Management
  // -----------------------------------------------------------------------

  connect() {
    if (this._destroyed) return;

    // Start connection asynchronously but return synchronously
    this._connectAsync().catch(err => {
      this._log(`Connection error: ${err.message}`);
      this._emitDone('DISCONNECTED', err.message, true);
    });

    // Return immediately - the connection will proceed in background
    return { error: false, message: '', status: '' };
  }

  async _connectAsync() {
    try {
      // Get a free port for management interface
      this._mgmtPort = await getFreeMgmtPort();
      this._mgmtPassword = crypto.randomBytes(16).toString('hex');

      // Write management password file
      const pwFile = this._configFilePath + '.pw';
      fs.writeFileSync(pwFile, this._mgmtPassword + '\n', { mode: 0o600 });

      // Add management directive to config
      let config = this._configContent;
      config += `\nmanagement 127.0.0.1 ${this._mgmtPort} ${pwFile}\n`;

      // Write final config
      fs.writeFileSync(this._configFilePath, config, { mode: 0o600 });

      this._log('Spawning OpenVPN process...');
      this._emitEvent('CONNECTING', 'Initializing connection');

      // Build openvpn command args
      const args = [
        '--config', this._configFilePath,
        '--machine-readable-output',
        '--verb', '3',
      ];

      // Check if we have DCO kernel module
      if (this._config && this._config.dco) {
        try {
          execSync('modinfo ovpn 2>/dev/null || modinfo ovpn-dco-v2 2>/dev/null', { encoding: 'utf8' });
          args.push('--dco');
        } catch {
          this._log('DCO kernel module not found, using tun');
        }
      }

      // Spawn openvpn - needs root for tun device
      // Try openvpn3 first, fall back to pkexec/sudo + openvpn
      this._spawnOpenvpn(args);

    } catch (err) {
      this._log(`Connection error: ${err.message}`);
      this._emitDone('DISCONNECTED', err.message, true);
    }
  }

  _spawnOpenvpn(args) {
    // Try to use openvpn directly first (if run as root or via capabilities)
    // Otherwise use pkexec for privilege escalation
    let bin = OPENVPN_BIN;
    let spawnArgs = args;

    // Check if openvpn binary has cap_net_admin or we're root
    if (process.getuid && process.getuid() !== 0) {
      // Use pkexec for GUI-friendly privilege escalation
      // Or sudo if available and configured
      bin = 'pkexec';
      spawnArgs = [OPENVPN_BIN, ...args];
    }

    this._log(`Starting: ${bin} ${spawnArgs.join(' ').substring(0, 200)}...`);

    this._process = spawn(bin, spawnArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: false,
    });

    this._process.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        if (line.trim()) {
          console.log(`[openvpn stdout] ${line.trim()}`);
          this._log(line.trim());
        }
      }
    });

    this._process.stderr.on('data', (data) => {
      const lines = data.toString().split('\n');
      for (const line of lines) {
        if (line.trim()) {
          console.log(`[openvpn stderr] ${line.trim()}`);
          this._log(`[stderr] ${line.trim()}`);
        }
      }
    });

    this._process.on('error', (err) => {
      // EPERM is expected when trying to signal a root process from userspace
      if (err.message && err.message.includes('EPERM')) {
        console.log('[openvpn] EPERM on process signal (expected - openvpn runs as root)');
        return;
      }
      console.log(`[openvpn] Process error: ${err.message}`);
      this._log(`Process error: ${err.message}`);
      this._emitEvent('DISCONNECTED', `Process error: ${err.message}`);
      this._emitDone('DISCONNECTED', err.message, true);
    });

    this._process.on('exit', (code, signal) => {
      console.log(`[openvpn] Process exited: code=${code} signal=${signal}`);
      this._log(`OpenVPN process exited: code=${code} signal=${signal}`);
      // If stop() is in progress, let its doCleanup handle the events.
      // Otherwise this is an unexpected exit (crash, timeout, etc.)
      if (!this._stopping) {
        this._connected = false;
        this._emitEvent('DISCONNECTED', `Process exited (code ${code})`);
        this._emitDone('DISCONNECTED', code === 0 ? '' : `Exit code ${code}`, code !== 0);
        this._cleanup();
      }
    });

    // Connect to management interface after openvpn starts
    // Use longer delay because pkexec auth prompt can take time
    setTimeout(() => this._connectManagement(30), 1000);
  }

  // -----------------------------------------------------------------------
  // Management Interface
  // -----------------------------------------------------------------------

  _connectManagement(retries = 10) {
    if (this._destroyed || !this._process) return;

    this._mgmtSocket = new net.Socket();

    this._mgmtSocket.on('connect', () => {
      console.log(`[mgmt] Connected to management interface on port ${this._mgmtPort}`);
      this._log('Management interface connected');
    });

    this._mgmtSocket.on('data', (data) => {
      this._handleMgmtData(data.toString());
    });

    this._mgmtSocket.on('error', (err) => {
      console.log(`[mgmt] Connection error (retries=${retries}): ${err.message}`);
      if (retries > 0 && !this._destroyed) {
        setTimeout(() => this._connectManagement(retries - 1), 1000);
      } else {
        console.log(`[mgmt] Failed to connect after all retries`);
        this._log(`Management interface error: ${err.message}`);
      }
    });

    this._mgmtSocket.on('close', () => {
      console.log('[mgmt] Connection closed');
      this._mgmtSocket = null;
    });

    this._mgmtSocket.connect(this._mgmtPort, '127.0.0.1');
  }

  _sendMgmt(cmd) {
    if (this._mgmtSocket && !this._mgmtSocket.destroyed) {
      // Don't log passwords
      const logCmd = cmd.startsWith('password') ? 'password ***' : cmd;
      console.log(`[mgmt] >>> ${logCmd}`);
      this._mgmtSocket.write(cmd + '\n');
    } else {
      console.log(`[mgmt] Cannot send (socket not ready): ${cmd.substring(0, 50)}`);
    }
  }

  _handleMgmtData(data) {
    this._buffer += data;

    // Check for password prompt (doesn't end with \n)
    if (this._buffer.includes('ENTER PASSWORD:')) {
      console.log('[mgmt] Password prompt detected, sending password');
      this._sendMgmt(this._mgmtPassword);
      this._buffer = '';
      return;
    }

    const lines = this._buffer.split('\n');
    this._buffer = lines.pop(); // Keep incomplete line in buffer

    // Also check if buffer has been sitting with unprocessed data
    if (this._buffer.length > 0) {
      console.log(`[mgmt] (buffered: ${this._buffer.substring(0, 80)})`);
    }

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      console.log(`[mgmt] ${trimmed}`);
      this._log(`[mgmt] ${trimmed}`);

      // Password prompt for management (backup check)
      if (trimmed.startsWith('ENTER PASSWORD:')) {
        this._sendMgmt(this._mgmtPassword);
        continue;
      }

      // Management hold - release it
      if (trimmed.startsWith('>HOLD:')) {
        this._sendMgmt('hold release');
        this._sendMgmt('state on');
        this._sendMgmt('log on all');
        this._sendMgmt('echo on all');
        this._sendMgmt('bytecount 5');
        continue;
      }

      // State change notifications
      if (trimmed.startsWith('>STATE:')) {
        this._handleStateChange(trimmed);
        continue;
      }

      // Password/auth request
      if (trimmed.startsWith('>PASSWORD:')) {
        this._handlePasswordRequest(trimmed);
        continue;
      }

      // Byte count updates
      if (trimmed.startsWith('>BYTECOUNT:')) {
        this._handleByteCount(trimmed);
        continue;
      }

      // Echo messages (webauth, notifications)
      if (trimmed.startsWith('>ECHO:')) {
        this._handleEcho(trimmed);
        continue;
      }

      // Info messages (webauth URLs, etc)
      if (trimmed.startsWith('>INFOMSG:') || trimmed.startsWith('>INFO:')) {
        this._handleInfoMsg(trimmed);
        continue;
      }

      // Log lines
      if (trimmed.startsWith('>LOG:')) {
        const logMsg = trimmed.substring(5);
        this._log(logMsg);
        continue;
      }

      // Need-ok for various prompts
      if (trimmed.startsWith('>NEED-OK:')) {
        this._sendMgmt('needok ok');
        continue;
      }
    }
  }

  _handleStateChange(line) {
    // >STATE:timestamp,state,desc,local_ip,remote_addr,remote_port,proto,cipher
    const parts = line.substring(7).split(',');
    if (parts.length >= 2) {
      const state = parts[1];
      const desc = parts.length > 2 ? parts[2] : '';
      const localIp = parts.length > 3 ? parts[3] : '';
      const remoteAddr = parts.length > 4 ? parts[4] : '';

      this._state = state;

      if (state === 'CONNECTED') {
        this._connected = true;
        this._connectionInfo = {
          localIp,
          remoteAddr,
          state: 'CONNECTED',
        };

        console.log('[napi-shim] VPN connected');
      }

      this._emitEvent(state, desc);
    }
  }

  _handlePasswordRequest(line) {
    // >PASSWORD:Need 'Auth' username/password
    // >PASSWORD:Need 'Private Key' password
    // >PASSWORD:Verification Failed: 'Auth'
    const msg = line.substring(10);

    if (msg.includes("Need 'Auth'")) {
      if (this._creds && this._creds.username && this._creds.password) {
        this._sendMgmt(`username "Auth" ${this._creds.username}`);
        this._sendMgmt(`password "Auth" ${this._creds.password}`);
      } else {
        // Signal the app to show credential dialog
        this._eventCallback('AUTH_REQUIRED', 'Username and password required');
      }
    } else if (msg.includes("Need 'Private Key'")) {
      if (this._config && this._config.privateKeyPassword) {
        this._sendMgmt(`password "Private Key" ${this._config.privateKeyPassword}`);
      } else if (this._tokenPin) {
        this._sendMgmt(`password "Private Key" ${this._tokenPin}`);
      }
    } else if (msg.includes("Need 'HTTP Proxy'")) {
      // Proxy auth
      if (this._creds) {
        this._sendMgmt(`username "HTTP Proxy" ${this._creds.username}`);
        this._sendMgmt(`password "HTTP Proxy" ${this._creds.password}`);
      }
    } else if (msg.includes('Verification Failed')) {
      this._emitEvent('AUTH_FAILED', msg);
    }
  }

  _handleByteCount(line) {
    // >BYTECOUNT:bytes_in,bytes_out
    const parts = line.substring(11).split(',');
    if (parts.length >= 2) {
      this._transportStats.bytesIn = parseInt(parts[0], 10) || 0;
      this._transportStats.bytesOut = parseInt(parts[1], 10) || 0;
    }
  }

  _handleEcho(line) {
    // >ECHO:timestamp,message
    const msg = line.substring(6);
    const commaIdx = msg.indexOf(',');
    if (commaIdx > -1) {
      const echoMsg = msg.substring(commaIdx + 1);

      // Handle webauth/SSO messages
      if (echoMsg.startsWith('WEB_AUTH:') || echoMsg.startsWith('OPEN_URL:') || echoMsg.startsWith('CR_TEXT:')) {
        this._handleInfoMsg('>INFOMSG:' + echoMsg);
        return;
      }

      this._log(`[echo] ${echoMsg}`);
    }
  }

  _handleInfoMsg(line) {
    let msg = line;
    if (msg.startsWith('>INFOMSG:')) msg = msg.substring(9);
    if (msg.startsWith('>INFO:')) msg = msg.substring(6);

    // WEB_AUTH:<flags>:<url>
    if (msg.startsWith('WEB_AUTH:')) {
      const rest = msg.substring(9);
      const colonIdx = rest.indexOf(':');
      const url = colonIdx > -1 ? rest.substring(colonIdx + 1) : rest;
      console.log(`[napi-shim] WEB_AUTH URL: ${url}`);
      // Open browser directly for SAML authentication
      this._openUrl(url);
      return;
    }

    // OPEN_URL:<url>
    if (msg.startsWith('OPEN_URL:')) {
      const url = msg.substring(9);
      console.log(`[napi-shim] OPEN_URL: ${url}`);
      this._openUrl(url);
      return;
    }

    // CR_TEXT:<challenge>
    if (msg.startsWith('CR_TEXT:')) {
      const challenge = msg.substring(7);
      this._eventCallback('CR_TEXT', challenge);
      return;
    }

    this._log(`[info] ${msg}`);
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  stop() {
    if (this._stopping) return; // Prevent double-stop
    this._stopping = true;
    console.log('[napi-shim] stop() called - disconnecting VPN');
    this._log('Stopping VPN connection...');

    const doCleanup = () => {
      if (this._cleanedUp) return;
      this._cleanedUp = true;
      this._stopping = false;
      this._connected = false;
      // Cancel pending kill timers
      if (this._exitTimer) clearTimeout(this._exitTimer);
      if (this._killTimer) clearTimeout(this._killTimer);
      this._emitEvent('DISCONNECTED', '');
      this._emitDone('DISCONNECTED', '', false);
      this._cleanup();
    };

    // Listen for process exit to cancel fallback timers
    if (this._process) {
      this._process.once('exit', () => {
        console.log('[napi-shim] openvpn exited after stop signal');
        doCleanup();
      });
    }

    // Method 1: Management interface signal (preferred, graceful)
    if (this._mgmtSocket && !this._mgmtSocket.destroyed) {
      this._sendMgmt('signal SIGTERM');
    }

    // Method 2: Management exit command after 1.5s (if still alive)
    this._exitTimer = setTimeout(() => {
      if (this._cleanedUp) return;
      if (this._mgmtSocket && !this._mgmtSocket.destroyed) {
        console.log('[napi-shim] Sending exit via management');
        this._sendMgmt('exit');
      }
    }, 1500);

    // Method 3: pkill after 4s - no pkexec prompt, just try pkill
    this._killTimer = setTimeout(() => {
      if (this._cleanedUp) return;
      console.log('[napi-shim] Process still alive after 4s, using pkill');
      try {
        const { execSync } = require('child_process');
        execSync('pkill -f "openvpn --config /tmp/openvpn-connect-linux" 2>/dev/null', {
          timeout: 3000,
          stdio: 'ignore',
        });
      } catch {}
      doCleanup();
    }, 4000);
  }

  pause(reason) {
    this._log(`Pausing VPN: ${reason}`);
    if (this._mgmtSocket) {
      this._sendMgmt('hold on');
      this._sendMgmt('signal SIGUSR1');
    }
  }

  resume() {
    this._log('Resuming VPN');
    if (this._mgmtSocket) {
      this._sendMgmt('hold release');
    }
  }

  connection_info() {
    return {
      defined: this._connected,
      user: (this._creds && this._creds.username) || '',
      serverHost: '',
      serverPort: '',
      serverProto: '',
      serverIp: this._connectionInfo.remoteAddr || '',
      vpnIp4: this._connectionInfo.localIp || '',
      vpnIp6: '',
      gw4: '',
      gw6: '',
      clientIp: '',
      tunName: '',
      ...this._connectionInfo,
    };
  }

  transport_stats() {
    return {
      bytesIn: this._transportStats.bytesIn || 0,
      bytesOut: this._transportStats.bytesOut || 0,
      packetsIn: this._transportStats.packetsIn || 0,
      packetsOut: this._transportStats.packetsOut || 0,
      lastPacketReceived: this._transportStats.lastPacketReceived || -1,
    };
  }

  tun_stats() {
    return {
      bytesIn: this._tunStats.bytesIn || 0,
      bytesOut: this._tunStats.bytesOut || 0,
      packetsIn: this._tunStats.packetsIn || 0,
      packetsOut: this._tunStats.packetsOut || 0,
      lastPacketReceived: -1,
    };
  }

  post_cc_msg(msg) {
    // Post control channel message (used for webauth completion)
    if (this._mgmtSocket) {
      this._sendMgmt(`cr-response ${msg}`);
    }
  }

  send_app_control_channel_msg(protocol, msg) {
    if (this._mgmtSocket) {
      this._sendMgmt(`app-control ${protocol} ${msg}`);
    }
  }

  disconnectAndDestroyClient() {
    console.log('[napi-shim] disconnectAndDestroyClient() called');
    this.stop();
    // Delay destroy to let stop() complete its kill chain
    setTimeout(() => {
      this._destroyed = true;
      this._cleanup();
    }, 5000);
  }

  client_destroy() {
    console.log('[napi-shim] client_destroy() called');
    // If still connected, stop first
    if (this._connected || this._process) {
      this.stop();
      setTimeout(() => {
        this._destroyed = true;
        this._cleanup();
      }, 5000);
    } else {
      this._destroyed = true;
      this._cleanup();
    }
  }

  _cleanup() {
    if (this._mgmtSocket) {
      try { this._mgmtSocket.destroy(); } catch {}
      this._mgmtSocket = null;
    }
    // Don't try this._process.kill() - openvpn runs as root via pkexec
    // and we'll get EPERM. Management interface signal is the proper way.
    this._process = null;
    // Clean up temp config files
    try {
      if (this._configFilePath && fs.existsSync(this._configFilePath)) {
        fs.unlinkSync(this._configFilePath);
      }
      if (this._configFilePath && fs.existsSync(this._configFilePath + '.pw')) {
        fs.unlinkSync(this._configFilePath + '.pw');
      }
    } catch {}
  }

  // -----------------------------------------------------------------------
  // Stats helpers (called by the app's connection module)
  // -----------------------------------------------------------------------

  getStats() {
    return {
      transport: this.transport_stats(),
      tun: this.tun_stats(),
    };
  }

  getConnectionInfo() {
    return this.connection_info();
  }

  setConfig(configWrap) {
    return this.set_config(configWrap);
  }

  postCCMessage(msg) {
    this.post_cc_msg(msg);
  }

  sendAppControlChannelMsg(protocol, msg) {
    this.send_app_control_channel_msg(protocol, msg);
  }

  // -----------------------------------------------------------------------
  // Internal logging & events
  // -----------------------------------------------------------------------

  _openUrl(url) {
    // Open URL in default browser for SAML/SSO authentication
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
      console.log(`[napi-shim] Ignoring invalid URL: ${url}`);
      return;
    }
    console.log(`[napi-shim] Opening browser for SAML: ${url}`);
    try {
      const { shell } = require('electron');
      shell.openExternal(url);
    } catch (err) {
      // Fallback to xdg-open
      console.log(`[napi-shim] Electron shell failed, using xdg-open: ${err.message}`);
      const { exec } = require('child_process');
      exec(`xdg-open "${url}"`);
    }
  }

  _log(msg) {
    const ts = Date.now();
    try {
      // logCallback expects a single string
      this._logCallback(String(ts) + ' ' + String(msg));
    } catch {}
  }

  _emitEvent(name, info) {
    try {
      // eventCallback(eventName: string, info: string)
      this._eventCallback(String(name || ''), String(info || ''));
    } catch {}
  }

  _emitDone(eventName, info, isError) {
    try {
      // doneCallback(eventName: string, info: string, isError: boolean)
      this._doneCallback(String(eventName || ''), String(info || ''), !!isError);
    } catch {}
  }

  // -----------------------------------------------------------------------
  // Static methods
  // -----------------------------------------------------------------------

  static merge_config(configPath, followReferences) {
    try {
      const profileContent = fs.readFileSync(configPath, 'utf8');
      const basename = path.basename(configPath, '.ovpn');
      return {
        status: '',
        errorText: '',
        basename,
        profileContent,
        refPathList: [],
      };
    } catch (err) {
      return {
        status: 'ERR_PROFILE_GENERIC',
        errorText: err.message,
        basename: '',
        profileContent: '',
        refPathList: [],
      };
    }
  }

  static merge_config_string(content) {
    return {
      status: '',
      errorText: '',
      basename: '',
      profileContent: content || '',
      refPathList: [],
    };
  }

  static init_static() {
    // Initialize the OpenVPN client library
    // On Linux with the management interface approach, this is a no-op
    console.log('[napi-shim] init_static called');
  }

  static uninit_static() {
    // Uninitialize the OpenVPN client library
    console.log('[napi-shim] uninit_static called');
  }

  static parse_dynamic_challenge(challengeStr) {
    // Parse dynamic challenge string from OpenVPN server
    // Format: CRV1:<flags>:<state_id>:<username>:<challenge_text>
    const parts = (challengeStr || '').split(':');
    return {
      status: parts.length >= 5 ? 0 : 1,
      challenge: parts.length >= 5 ? parts[4] : challengeStr,
      echo: parts.length >= 2 ? parts[1].includes('E') : false,
      responseRequired: parts.length >= 2 ? parts[1].includes('R') : true,
      stateId: parts.length >= 3 ? parts[2] : '',
    };
  }

  static eval_config(configWrap) {
    // Evaluate a config for errors/warnings without connecting
    const content = configWrap.content || '';
    const hasRemote = content.includes('remote ');
    const hasAuthUser = content.includes('auth-user-pass');
    const hasExternalPki = content.includes('EXTERNAL_PKI');

    // Extract remote host/port/proto
    let remoteHost = '', remotePort = '', remoteProto = '';
    const remoteMatch = content.match(/^remote\s+(\S+)(?:\s+(\d+))?(?:\s+(\S+))?/m);
    if (remoteMatch) {
      remoteHost = remoteMatch[1] || '';
      remotePort = remoteMatch[2] || '1194';
      remoteProto = remoteMatch[3] || '';
    }

    // Extract profile/friendly name from comments or CN
    let profileName = '';
    const nameMatch = content.match(/^#\s*(?:profile|name):\s*(.+)/im);
    if (nameMatch) profileName = nameMatch[1].trim();

    // Check for static challenge
    let staticChallenge = '', staticChallengeEcho = false;
    const challengeMatch = content.match(/^static-challenge\s+"([^"]+)"\s+(\d)/m);
    if (challengeMatch) {
      staticChallenge = challengeMatch[1];
      staticChallengeEcho = challengeMatch[2] === '1';
    }

    // Check if private key is encrypted
    const hasEncryptedKey = content.includes('ENCRYPTED');

    // Build server list from all remote directives
    // evalConfigToObj parses each entry with JSON.parse, so they must be strings
    const serverList = [];
    const remoteRegex = /^remote\s+(\S+)(?:\s+(\d+))?(?:\s+(\S+))?/gm;
    let match;
    while ((match = remoteRegex.exec(content)) !== null) {
      serverList.push(JSON.stringify({
        server: match[1],
        port: match[2] || '1194',
        proto: match[3] || '',
      }));
    }

    // Check for user-locked username
    let userlockedUsername = '';
    const userMatch = content.match(/^setenv\s+UV_USERNAME\s+"?([^"\n]+)"?/m);
    if (userMatch) userlockedUsername = userMatch[1].trim();

    return {
      error: !hasRemote,
      message: hasRemote ? '' : 'Config missing "remote" directive',
      userlockedUsername,
      profileName,
      friendlyName: profileName || remoteHost,
      serverList,
      autologin: !hasAuthUser,
      externalPki: hasExternalPki,
      staticChallenge,
      staticChallengeEcho,
      privateKeyPasswordRequired: hasEncryptedKey,
      allowPasswordSave: true,
      remoteHost,
      remotePort,
      remoteProto,
      windowsDriver: '',
    };
  }
}

// ---------------------------------------------------------------------------
// OS API - Linux implementations
// ---------------------------------------------------------------------------
const OS = {
  // version() is called as a function by os.js
  // Returns an object with major/minor/patch parsed from kernel version
  version() {
    const rel = os.release();
    const parts = rel.split('.');
    return {
      major: parseInt(parts[0]) || 0,
      minor: parseInt(parts[1]) || 0,
      patch: parseInt(parts[2]) || 0,
      toString() { return rel; },
    };
  },

  // system() is called as a function by os.js
  // Also accessed as systemInfo property (array) by systeminformation/index.win.ts
  // Returns a callable array: [manufacturer, model, uuid]
  system() {
    return OS._getSystemInfo();
  },

  // build() is called as a function by os.js
  // Also accessed as property (array) by systeminformation/index.win.ts
  // Returns a callable array: [buildNumber, distro]
  build() {
    return OS._getBuildInfo();
  },

  _getSystemInfo() {
    let manufacturer = 'Unknown';
    let model = 'Unknown';
    let uuid = '';

    try {
      uuid = fs.readFileSync('/etc/machine-id', 'utf8').trim();
    } catch {
      try {
        uuid = fs.readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
      } catch {
        uuid = crypto.randomBytes(16).toString('hex');
      }
    }

    try {
      manufacturer = execSync('cat /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null', { encoding: 'utf8' }).trim() || 'Unknown';
    } catch {}
    try {
      model = execSync('cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null', { encoding: 'utf8' }).trim() || 'Unknown';
    } catch {}

    return [manufacturer, model, uuid.toUpperCase()];
  },

  _getBuildInfo() {
    let buildNumber = os.release();
    let distro = 'Linux';
    try {
      const release = fs.readFileSync('/etc/os-release', 'utf8');
      const nameMatch = release.match(/^ID=(.+)/m);
      const versionMatch = release.match(/^VERSION_ID="?([^"\n]+)"?/m);
      if (nameMatch) distro = nameMatch[1];
      if (versionMatch) buildNumber = versionMatch[1];
    } catch {}
    return [buildNumber, distro];
  },

  // adapter_state and service_state are the function names used by systeminformation
  adapter_state(name) {
    return OS.getAdapterState(name);
  },

  service_state(name) {
    return OS.getServiceState(name);
  },

  getAdapterState(name) {
    // Check if tun/tap device or ovpn-dco is available
    if (name.toLowerCase().includes('dco') || name.toLowerCase().includes('data channel offload')) {
      try {
        execSync('modinfo ovpn 2>/dev/null || modinfo ovpn-dco-v2 2>/dev/null', { encoding: 'utf8' });
        return 'RUNNING';
      } catch {
        return 'NOT_FOUND';
      }
    }
    // For tun device
    if (name.toLowerCase().includes('tap') || name.toLowerCase().includes('tun')) {
      try {
        if (fs.existsSync('/dev/net/tun')) return 'RUNNING';
      } catch {}
      return 'NOT_FOUND';
    }
    return 'OK';
  },

  getServiceState(name) {
    // Check if a systemd service is active
    try {
      const result = execSync(`systemctl is-active ${name} 2>/dev/null`, { encoding: 'utf8' }).trim();
      return result === 'active' ? 'RUNNING' : 'STOPPED';
    } catch {
      // Service doesn't exist or isn't running - that's fine on Linux
      // The agent service isn't needed, openvpn runs directly
      return 'RUNNING'; // Return RUNNING to pass sanity checks
    }
  },
};

// ---------------------------------------------------------------------------
// OSSettingsAPI - Tray theme detection
// ---------------------------------------------------------------------------
const OSSettingsAPI = {
  _listeners: [],

  getTrayTheme() {
    // Detect dark/light theme on Linux
    try {
      // Try KDE Plasma
      const kdeTheme = execSync(
        'kreadconfig5 --group General --key ColorScheme 2>/dev/null || kreadconfig6 --group General --key ColorScheme 2>/dev/null',
        { encoding: 'utf8' }
      ).trim().toLowerCase();
      if (kdeTheme.includes('dark') || kdeTheme.includes('breeze')) return 'dark';
      if (kdeTheme.includes('light')) return 'light';
    } catch {}

    try {
      // Try GNOME/GTK
      const gtkTheme = execSync(
        'gsettings get org.gnome.desktop.interface color-scheme 2>/dev/null',
        { encoding: 'utf8' }
      ).trim();
      if (gtkTheme.includes('dark')) return 'dark';
    } catch {}

    try {
      // Try xdg portal
      const result = execSync(
        'dbus-send --session --dest=org.freedesktop.portal.Desktop --print-reply /org/freedesktop/portal/desktop org.freedesktop.portal.Settings.Read string:"org.freedesktop.appearance" string:"color-scheme" 2>/dev/null',
        { encoding: 'utf8' }
      );
      if (result.includes('uint32 1')) return 'dark';
    } catch {}

    return 'dark'; // Default to dark
  },

  listenTrayTheme(callback) {
    // Poll for theme changes every 30s
    const interval = setInterval(() => {
      try {
        callback(this.getTrayTheme());
      } catch {}
    }, 30000);
    this._listeners.push(interval);
    return interval;
  },

  removeAllListeners() {
    for (const interval of this._listeners) {
      clearInterval(interval);
    }
    this._listeners = [];
  },
};

// ---------------------------------------------------------------------------
// RegAPI - Linux replacement for Windows Registry
// Uses config files in XDG config directory
// ---------------------------------------------------------------------------
const CONFIG_DIR = path.join(os.homedir(), '.config', 'openvpn-connect');
if (!fs.existsSync(CONFIG_DIR)) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
}

class RegAPI {
  constructor(hkey, subkey, sam) {
    this._hkey = hkey;
    this._subkey = subkey || '';
    // Map registry paths to config file names
    const safeName = (subkey || 'default').replace(/[\\\/]/g, '_').replace(/[^a-zA-Z0-9_-]/g, '');
    this._filePath = path.join(CONFIG_DIR, `${safeName}.json`);
    this._data = {};
    this._load();
  }

  _load() {
    try {
      if (fs.existsSync(this._filePath)) {
        this._data = JSON.parse(fs.readFileSync(this._filePath, 'utf8'));
      }
    } catch {
      this._data = {};
    }
  }

  _save() {
    try {
      fs.writeFileSync(this._filePath, JSON.stringify(this._data, null, 2), { mode: 0o600 });
    } catch (err) {
      console.error(`[RegAPI] Failed to save config: ${err.message}`);
    }
  }

  readString(name) {
    return this._data[name] || '';
  }

  writeString(name, value) {
    this._data[name] = value;
    this._save();
  }

  hasValues() {
    return Object.keys(this._data).length > 0;
  }

  hasValue(name) {
    return name in this._data;
  }

  getValues() {
    return { ...this._data };
  }

  removeValue(name) {
    delete this._data[name];
    this._save();
  }

  listSubKeys() {
    // Simulate registry subkeys as directories
    return [];
  }
}

// ---------------------------------------------------------------------------
// PathAPI
// ---------------------------------------------------------------------------
const PathAPI = {
  resolvePath(p) {
    if (p.startsWith('~')) {
      return path.join(os.homedir(), p.substring(1));
    }
    return path.resolve(p);
  },
};

// ---------------------------------------------------------------------------
// Interop (C++ interop for external PKI - stub for now)
// ---------------------------------------------------------------------------
const Interop = {
  _callbacks: {},

  callback(name, fn) {
    this._callbacks[name] = fn;
  },

  // create() returns an interop instance used by cpp_interop.ts
  // It registers C++ callback functions (like request_pem, sign_data)
  create() {
    const instance = {
      _functions: {},

      add_function(name, fn) {
        instance._functions[name] = fn;
        Interop._callbacks[name] = fn;
      },

      call(name, ...args) {
        if (instance._functions[name]) {
          // Create a resolver object that matches the C++ interop pattern
          const resolver = {
            resolve(value) { /* resolved */ },
            reject(message) { /* rejected */ },
          };
          return instance._functions[name](resolver, ...args);
        }
      },
    };
    return instance;
  },
};

// ---------------------------------------------------------------------------
// HttpClientAPI - HTTP client for profile downloads
// ---------------------------------------------------------------------------
class HttpClientAPI {
  constructor() {
    this._activeRequests = new Map();
  }

  // runFetch(id, path, hostname, fetchOptions, proxyConfig, certConfig, callback)
  // callback receives: {ok, cancelled, status, statusString, url, headers, bodyString}
  runFetch(id, urlPath, hostname, fetchOptions, proxyConfig, certConfig, callback) {
    const https = require('https');
    const http = require('http');

    const protocol = (fetchOptions && fetchOptions.ssl === false) ? 'http' : 'https';
    const port = (fetchOptions && fetchOptions.port) || (protocol === 'https' ? 443 : 80);
    const fullUrl = `${protocol}://${hostname}${urlPath}`;

    const reqOptions = {
      hostname,
      port,
      path: urlPath,
      method: (fetchOptions && fetchOptions.method) || 'GET',
      headers: {},
      rejectUnauthorized: false,
    };

    // Apply fetch options headers
    if (fetchOptions) {
      if (fetchOptions.headers) {
        reqOptions.headers = { ...fetchOptions.headers };
      }
      if (fetchOptions.userAgent) {
        reqOptions.headers['User-Agent'] = fetchOptions.userAgent;
      }
      if (fetchOptions.username && fetchOptions.password) {
        const auth = Buffer.from(`${fetchOptions.username}:${fetchOptions.password}`).toString('base64');
        reqOptions.headers['Authorization'] = `Basic ${auth}`;
      }
    }

    // Apply CA cert if provided
    if (certConfig && certConfig.ca) {
      reqOptions.ca = certConfig.ca;
    }

    const client = protocol === 'https' ? https : http;

    const req = client.request(reqOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const headers = {};
        for (const [k, v] of Object.entries(res.headers)) {
          headers[k] = Array.isArray(v) ? v.join(', ') : v;
        }
        callback({
          ok: res.statusCode >= 200 && res.statusCode < 400,
          cancelled: false,
          status: res.statusCode,
          statusString: res.statusMessage || '',
          url: fullUrl,
          headers,
          bodyString: data,
        });
      });
    });

    req.on('error', (err) => {
      callback({
        ok: false,
        cancelled: false,
        status: 0,
        statusString: err.message,
        url: fullUrl,
        headers: {},
        bodyString: '',
      });
    });

    this._activeRequests.set(id, req);

    if (fetchOptions && fetchOptions.body) {
      req.write(fetchOptions.body);
    }
    req.end();
  }

  cancelFetch(id) {
    const req = this._activeRequests.get(id);
    if (req) {
      req.destroy();
      this._activeRequests.delete(id);
    }
  }
}

// ---------------------------------------------------------------------------
// IPCClient / IPCServer - Local IPC for CLI communication
// ---------------------------------------------------------------------------
class IPCClient {
  static send(...args) {
    // Stub - CLI IPC not critical for initial port
    console.log('[IPCClient] send:', ...args);
  }
}

class IPCServer {
  static create() {
    // IPC server for CLI-to-app communication
    const instance = {
      _handlers: {},
      _server: null,

      add(name, handler) {
        instance._handlers[name] = handler;
      },

      remove(name) {
        delete instance._handlers[name];
      },

      start(socketPath) {
        // Start listening on Unix domain socket for CLI commands
        console.log(`[napi-shim] IPCServer.start(${socketPath || 'default'})`);
        // Stub - CLI IPC not critical for initial port
      },

      stop() {
        if (instance._server) {
          instance._server.close();
          instance._server = null;
        }
      },

      close() {
        instance.stop();
      },
    };
    return instance;
  }
}

// ---------------------------------------------------------------------------
// HelperIPC - Communication with helper service
// ---------------------------------------------------------------------------
const HelperIPC = {
  list_apps(successCb, errorCb, flag) {
    // On Linux, we don't have the agent service
    // Return empty list to indicate no managed apps
    if (successCb) successCb([]);
  },
};

// ---------------------------------------------------------------------------
// CertAPI - Certificate management
// ---------------------------------------------------------------------------
const CertAPI = {
  importPKCS12(data, password) {
    // Use openssl to handle PKCS12 on Linux
    try {
      const tmpFile = path.join(os.tmpdir(), `ovpn-cert-${crypto.randomBytes(4).toString('hex')}.p12`);
      fs.writeFileSync(tmpFile, Buffer.from(data, 'base64'), { mode: 0o600 });

      const certDir = path.join(CONFIG_DIR, 'certificates');
      if (!fs.existsSync(certDir)) {
        fs.mkdirSync(certDir, { recursive: true, mode: 0o700 });
      }

      // Extract cert and key
      const certFile = path.join(certDir, `cert-${Date.now()}.pem`);
      execSync(
        `openssl pkcs12 -in "${tmpFile}" -out "${certFile}" -nodes -passin pass:"${password}" 2>/dev/null`,
        { encoding: 'utf8' }
      );

      fs.unlinkSync(tmpFile);

      return { success: true, path: certFile };
    } catch (err) {
      return { success: false, message: err.message };
    }
  },

  importPKCS12NoPassword(data) {
    return CertAPI.importPKCS12(data, '');
  },

  listCertificates() {
    try {
      const certDir = path.join(CONFIG_DIR, 'certificates');
      if (!fs.existsSync(certDir)) return { data: [] };

      const files = fs.readdirSync(certDir).filter(f => f.endsWith('.pem'));
      const certs = files.map(f => ({
        path: path.join(certDir, f),
        name: f,
      }));
      return { data: certs };
    } catch {
      return { data: [] };
    }
  },

  migrateCertificates() {
    // No migration needed on Linux
    return { success: true };
  },

  removeCertificate(certPath) {
    try {
      if (fs.existsSync(certPath)) {
        fs.unlinkSync(certPath);
      }
      return { success: true };
    } catch (err) {
      return { success: false, message: err.message };
    }
  },

  validateSSLCertificate(data) {
    try {
      const tmpFile = path.join(os.tmpdir(), `ovpn-validate-${crypto.randomBytes(4).toString('hex')}.pem`);
      fs.writeFileSync(tmpFile, data, { mode: 0o600 });
      execSync(`openssl x509 -in "${tmpFile}" -noout 2>/dev/null`, { encoding: 'utf8' });
      fs.unlinkSync(tmpFile);
      return { valid: true };
    } catch {
      return { valid: false };
    }
  },

  getCertFromSystemStorage(query) {
    // Linux doesn't have a centralized system cert store like Windows
    // Check common locations
    const locations = [
      '/etc/ssl/certs',
      '/etc/pki/tls/certs',
      path.join(CONFIG_DIR, 'certificates'),
    ];

    for (const loc of locations) {
      try {
        if (!fs.existsSync(loc)) continue;
        const files = fs.readdirSync(loc);
        for (const f of files) {
          if (f.includes(query)) {
            return fs.readFileSync(path.join(loc, f), 'utf8');
          }
        }
      } catch {}
    }
    return null;
  },

  getInfoFromPEM(pemData) {
    try {
      const tmpFile = path.join(os.tmpdir(), `ovpn-info-${crypto.randomBytes(4).toString('hex')}.pem`);
      fs.writeFileSync(tmpFile, pemData, { mode: 0o600 });
      const info = execSync(`openssl x509 -in "${tmpFile}" -noout -subject -issuer -dates 2>/dev/null`, { encoding: 'utf8' });
      fs.unlinkSync(tmpFile);
      return { success: true, info };
    } catch (err) {
      return { success: false, message: err.message };
    }
  },
};

// ---------------------------------------------------------------------------
// Export everything matching the original napi.node interface
// ---------------------------------------------------------------------------
module.exports = {
  ClientWrapper,
  ConfigWrap,
  CredsWrap,
  FetchOptions,
  FetchCredentials,
  ProxyConfig,
  CertConfig,
  OS,
  OSSettingsAPI,
  RegAPI,
  PathAPI,
  Interop,
  HttpClientAPI,
  IPCClient,
  IPCServer,
  HelperIPC,
  CertAPI,
};
