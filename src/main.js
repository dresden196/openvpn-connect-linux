/**
 * OpenVPN Connect for Linux - Main Entry Point
 *
 * Strategy: The original app.js is a self-contained webpack bundle that
 * expects to be the Electron main process. It uses __dirname to find its
 * sibling assets (icons, HTML, fonts, native modules).
 *
 * Our approach:
 *   1. Intercept process.dlopen() to replace Windows/macOS .node binaries
 *      with our Linux-compatible JS shims
 *   2. Set __dirname in the original app's context to its actual location
 *   3. Load the original app.js directly
 *
 * The webpack bundle's internal module system handles everything else -
 * fancy-platform already detects Linux, tray icons already use .png on
 * non-Windows, and the UI (React Native Web) is platform-agnostic.
 */

const path = require('path');
const Module = require('module');

// Path to the original extracted app
const APP_DIR = path.join(__dirname, '..', 'resources', 'app');
const SHIMS_DIR = path.join(__dirname, 'shims');

// ------------------------------------------------------------------
// 1. Intercept native module loading (process.dlopen)
// ------------------------------------------------------------------
// The webpack bundle loads .node files via process.dlopen().
// We intercept this to replace Windows PE32 binaries with our JS shims.

const originalDlopen = process.dlopen;
process.dlopen = function (module, filename, flags) {
  if (!filename) return originalDlopen.call(this, module, filename, flags);

  const basename = path.basename(filename, '.node');

  // Intercept the proprietary OpenVPN3 native addon
  if (basename === 'napi' || filename.endsWith('napi.node')) {
    console.log('[Linux] Redirecting napi.node → napi-shim.js');
    module.exports = require(path.join(SHIMS_DIR, 'napi-shim.js'));
    return;
  }

  // Intercept keytar - try native Linux build first, fall back to shim
  if (basename === 'keytar' || filename.endsWith('keytar.node')) {
    console.log('[Linux] Redirecting keytar.node');
    try {
      // Try the npm-installed native keytar (built for Linux)
      const keytarPath = require.resolve('keytar');
      module.exports = require(keytarPath);
      console.log('[Linux] Using native keytar (libsecret)');
    } catch {
      module.exports = require(path.join(SHIMS_DIR, 'keytar-shim.js'));
      console.log('[Linux] Using keytar shim (encrypted file)');
    }
    return;
  }

  // Intercept pkcs11 - try native build, fall back to shim
  if (basename === 'pkcs11' || filename.endsWith('pkcs11.node')) {
    console.log('[Linux] Redirecting pkcs11.node');
    try {
      module.exports = require('pkcs11js');
      console.log('[Linux] Using native pkcs11js');
    } catch {
      module.exports = require(path.join(SHIMS_DIR, 'pkcs11-shim.js'));
      console.log('[Linux] Using pkcs11 shim (stub)');
    }
    return;
  }

  // All other native modules - try to load normally
  return originalDlopen.call(this, module, filename, flags);
};

// ------------------------------------------------------------------
// 2. Patch Module._resolveFilename for module resolution
// ------------------------------------------------------------------
// Some require() calls reference paths relative to the original app.
// We need to make sure they resolve correctly.

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  // Redirect electron require to our shim that patches BrowserWindow
  // Only redirect when called from the app bundle (not from our own code)
  if (request === 'electron' && parent && parent.filename &&
      parent.filename.includes('resources/app')) {
    return path.join(__dirname, 'shims', 'electron-shim.js');
  }

  // Intercept the napi.node require from core/napi.js
  if (request === './addon/build/Release/napi.node') {
    return path.join(SHIMS_DIR, 'napi-shim.js');
  }

  // If resolution fails for something in the app dir, try resolving
  // relative to our node_modules
  try {
    return originalResolveFilename.call(this, request, parent, isMain, options);
  } catch (err) {
    // Try from our project's node_modules
    try {
      return originalResolveFilename.call(this, request, module, isMain, options);
    } catch {
      throw err; // Re-throw original error
    }
  }
};

// ------------------------------------------------------------------
// 3. Patch child_process.exec for Linux-specific commands
// ------------------------------------------------------------------
// The app calls Windows commands (netsh, powershell, etc.)
// We need to intercept these and provide Linux equivalents.

const childProcess = require('child_process');
const originalExec = childProcess.exec;

childProcess.exec = function (command, options, callback) {
  // Normalize args (options is optional)
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  let linuxCommand = command;

  // SSID Detection: netsh → nmcli/iwgetid
  if (command.includes('netsh wlan show interfaces')) {
    linuxCommand = "nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | head -1 | cut -d: -f2 || iwgetid -r 2>/dev/null || echo ''";
    return originalExec.call(this, linuxCommand, options, function (err, stdout, stderr) {
      // Format output to look like netsh output so the parser works
      const ssid = (stdout || '').trim();
      if (ssid) {
        callback(err, `    SSID                   : ${ssid}\n`, stderr);
      } else {
        callback(err, '', stderr || 'No SSID found');
      }
    });
  }

  // SSID Detection: airport (macOS) → nmcli
  if (command.includes('airport -I')) {
    linuxCommand = "nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | head -1 | cut -d: -f2 || iwgetid -r 2>/dev/null || echo ''";
    return originalExec.call(this, linuxCommand, options, function (err, stdout, stderr) {
      const ssid = (stdout || '').trim();
      if (ssid) {
        callback(err, ` SSID: ${ssid}\n`, stderr);
      } else {
        callback(err, '', stderr || 'No SSID found');
      }
    });
  }

  // PowerShell Start-Process → pkexec/sudo
  if (command.includes('powershell') && command.includes('Start-Process')) {
    // Extract the actual command from PowerShell wrapping
    const match = command.match(/-FilePath\s+"'([^']+)'/);
    if (match) {
      linuxCommand = `pkexec ${match[1]}`;
    }
    return originalExec.call(this, linuxCommand, options, callback);
  }

  // tasklist → ps/pgrep
  if (command.includes('tasklist')) {
    linuxCommand = 'ps aux';
    return originalExec.call(this, linuxCommand, options, callback);
  }

  // Windows security (macOS keychain) commands - skip on Linux
  if (command.includes('security ') && (command.includes('keychain') || command.includes('set-keychain'))) {
    if (callback) callback(null, '', '');
    return;
  }

  // cmd.exe /c start URL → xdg-open URL
  if (command.includes('cmd.exe') && command.includes('/c start')) {
    const urlMatch = command.match(/start\s+""\s+"([^"]+)"/);
    if (urlMatch) {
      linuxCommand = `xdg-open "${urlMatch[1]}"`;
    }
    return originalExec.call(this, linuxCommand, options, callback);
  }

  return originalExec.call(this, command, options, callback);
};

// Also patch execSync for synchronous calls
const originalExecSync = childProcess.execSync;
childProcess.execSync = function (command, options) {
  // Catch Windows-specific commands that would fail
  if (command.includes('netsh') || command.includes('powershell') || command.includes('cmd.exe /c')) {
    return '';
  }
  return originalExecSync.call(this, command, options);
};

// ------------------------------------------------------------------
// 4. Patch electron module for Linux-specific behavior
// ------------------------------------------------------------------
// electron.shell.openExternal already works on Linux, but we need
// to make sure some other Electron APIs work correctly

const { app } = require('electron');

// Set proper app paths for Linux (XDG-compliant)
app.on('ready', () => {
  const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(require('os').homedir(), '.config');
  app.setPath('userData', path.join(xdgConfig, 'openvpn-connect'));
});

// Patch auto-start (login items) for Linux via XDG autostart
const autostartDir = path.join(
  process.env.XDG_CONFIG_HOME || path.join(require('os').homedir(), '.config'),
  'autostart'
);
const autostartFile = path.join(autostartDir, 'openvpn-connect.desktop');
const linuxFs = require('fs');

const originalSetLoginItemSettings = app.setLoginItemSettings.bind(app);
app.setLoginItemSettings = function(settings) {
  try {
    if (settings.openAtLogin) {
      if (!linuxFs.existsSync(autostartDir)) {
        linuxFs.mkdirSync(autostartDir, { recursive: true });
      }
      linuxFs.writeFileSync(autostartFile, [
        '[Desktop Entry]',
        'Type=Application',
        'Name=OpenVPN Connect',
        'Comment=OpenVPN Connect VPN Client',
        `Exec=${process.execPath} ${path.join(__dirname, '..')} --no-sandbox`,
        'Icon=openvpn-connect',
        'Terminal=false',
        'X-GNOME-Autostart-enabled=true',
        'StartupWMClass=openvpn-connect-linux',
      ].join('\n'));
      console.log('[Linux] Auto-start enabled');
    } else {
      if (linuxFs.existsSync(autostartFile)) {
        linuxFs.unlinkSync(autostartFile);
        console.log('[Linux] Auto-start disabled');
      }
    }
  } catch (err) {
    console.error('[Linux] Auto-start error:', err.message);
  }
};

const originalGetLoginItemSettings = app.getLoginItemSettings.bind(app);
app.getLoginItemSettings = function() {
  const enabled = linuxFs.existsSync(autostartFile);
  return {
    openAtLogin: enabled,
    openAsHidden: false,
    wasOpenedAtLogin: false,
    wasOpenedAsHidden: false,
    restoreState: false,
  };
};

// ------------------------------------------------------------------
// 5. Prevent the detach/relaunch flow
// ------------------------------------------------------------------
// The original app relaunches itself with --relaunch flag on first start.
// The relaunched process bypasses our main.js shims entirely.
// We prevent this by making the app think it's already been relaunched.

// Add file access flag
if (!app.commandLine.hasSwitch('allow-file-access-from-files')) {
  app.commandLine.appendSwitch('allow-file-access-from-files');
}

// CRITICAL: Acquire the single instance lock NOW before the app code runs.
// The store initialization checks hasSingleInstanceLock() and refuses to
// start if it returns false.
const gotLock = app.requestSingleInstanceLock();
console.log(`[Linux] Acquired single instance lock: ${gotLock}`);
if (!gotLock) {
  console.log('[Linux] Another instance is running. Quitting.');
  app.quit();
  process.exit(0);
}

// Set --relaunch flag to skip the first-launch relaunch flow entirely.
// Without this, the app tries to: create lockfile → relaunch → quit.
// The relaunched process wouldn't have our shims loaded.
if (!app.commandLine.hasSwitch('relaunch')) {
  app.commandLine.appendSwitch('relaunch');
}

// Prevent the app from relaunching itself (which would bypass our shims)
app.relaunch = function() {
  console.log('[Linux] app.relaunch() blocked');
};

// Also block releaseSingleInstanceLock - the store needs it
app.releaseSingleInstanceLock = function() {
  console.log('[Linux] releaseSingleInstanceLock() blocked - store needs it');
};

const electron = require('electron');

// ------------------------------------------------------------------
// 7. Ensure the window shows on Linux + inject controls
// ------------------------------------------------------------------
app.on('browser-window-created', (event, window) => {
  // Show the window after it finishes loading
  window.once('ready-to-show', () => {
    window.show();
    window.focus();
  });

  // Fallback: force show after a delay
  setTimeout(() => {
    if (!window.isDestroyed() && !window.isVisible()) {
      window.show();
      window.focus();
    }
  }, 3000);

  // Also intercept hide calls to prevent the window from disappearing
  // on first launch (the app hides after creating the window)
  const originalHide = window.hide.bind(window);
  let hasBeenShownOnce = false;
  const originalShow = window.show.bind(window);
  window.show = function() {
    hasBeenShownOnce = true;
    return originalShow();
  };
  window.hide = function() {
    // Allow hide only after window has been shown at least once
    // and user has interacted with it
    if (hasBeenShownOnce) {
      return originalHide();
    }
    // On first creation, don't hide - show instead
    console.log('[Linux] Prevented window hide on first show');
  };
});

// ------------------------------------------------------------------
// 7. Clean up stale lockfiles from previous crashes
// ------------------------------------------------------------------
const fs = require('fs');
const os = require('os');

// Clean OpenVPN management lockfile
const lockFile = path.join('/tmp', '.ovpn-connect-lockfile');
try {
  if (fs.existsSync(lockFile)) {
    const content = fs.readFileSync(lockFile, 'utf8');
    const pidMatch = content.match(/(\d+)/);
    if (pidMatch) {
      try {
        process.kill(parseInt(pidMatch[1]), 0);
      } catch {
        fs.unlinkSync(lockFile);
        console.log('[Linux] Removed stale lockfile');
      }
    }
  }
} catch (err) {
  console.log('[Linux] Lockfile check:', err.message);
}

// Clean Electron singleton locks (left from crashed processes)
const userDataDirs = [
  path.join(os.homedir(), '.config', 'OpenVPN Connect'),
  path.join(os.homedir(), '.config', 'openvpn-connect'),
];
for (const dir of userDataDirs) {
  for (const lockName of ['SingletonLock', 'SingletonSocket', 'SingletonCookie']) {
    const lockPath = path.join(dir, lockName);
    try {
      if (fs.existsSync(lockPath)) {
        // Check if the lock holder is still alive
        if (lockName === 'SingletonLock') {
          const linkTarget = fs.readlinkSync(lockPath);
          const pidMatch = linkTarget.match(/(\d+)/);
          if (pidMatch) {
            try {
              process.kill(parseInt(pidMatch[1]), 0);
              // Process alive - real instance running
              continue;
            } catch {
              // Dead process - remove stale lock
            }
          }
        }
        fs.unlinkSync(lockPath);
        console.log(`[Linux] Removed stale ${lockName}`);
      }
    } catch {}
  }
}

// ------------------------------------------------------------------
// 8. Set up environment and load the original app
// ------------------------------------------------------------------
console.log('[OpenVPN Connect Linux] Starting...');
console.log(`[OpenVPN Connect Linux] App dir: ${APP_DIR}`);
console.log(`[OpenVPN Connect Linux] Platform: ${process.platform} (${process.arch})`);
console.log(`[OpenVPN Connect Linux] Has single instance lock: ${app.hasSingleInstanceLock()}`);
console.log(`[OpenVPN Connect Linux] --relaunch flag: ${app.commandLine.hasSwitch('relaunch')}`);

// Kill openvpn on app exit (Ctrl+C, window close, etc.)
function killOpenvpn() {
  try {
    const { execSync } = require('child_process');
    execSync('pkill -f "openvpn --config /tmp/openvpn-connect-linux" 2>/dev/null', { timeout: 3000, stdio: 'ignore' });
    console.log('[Linux] Killed openvpn on exit');
  } catch {}
}
process.on('exit', killOpenvpn);
process.on('SIGINT', () => { killOpenvpn(); process.exit(0); });
process.on('SIGTERM', () => { killOpenvpn(); process.exit(0); });
app.on('will-quit', killOpenvpn);

// Set the working directory to the app dir so __dirname resolves correctly
// for the webpack bundle's asset references
process.chdir(APP_DIR);

// Intercept app.quit to prevent premature quit from timeout
const originalQuit = app.quit.bind(app);
let appReady = false;
app.on('ready', () => { appReady = true; });
app.quit = function() {
  if (!appReady) {
    console.log('[Linux] app.quit() called before app ready - allowing');
    return originalQuit();
  }
  // Check if this is from the quit timeout (app tries to quit if window
  // doesn't open fast enough). On Linux, window creation may be slower.
  const stack = new Error().stack;
  if (stack.includes('Timeout') || stack.includes('listOnTimeout')) {
    console.log('[Linux] Blocked premature quit from timeout - window may still be loading');
    return;
  }
  console.log('[Linux] app.quit() called');
  return originalQuit();
};

// Intercept app.releaseSingleInstanceLock
const originalRelease = app.releaseSingleInstanceLock.bind(app);
app.releaseSingleInstanceLock = function() {
  console.log('[Linux] WARNING: releaseSingleInstanceLock() called - this will break store init!');
  // Don't release it - the store needs it
  // return originalRelease();
};

// On the relaunch path, handleApp() from win7_hack.ts does nothing on Linux,
// so launchApp() is never called and no window appears.
// Fix: Intercept the webpack module system to patch win7_hack's handleApp.
// When the original app.js loads, we'll patch the exported handleApp to
// call launchApp on Linux.

// We'll use a post-load approach: after the webpack bundle runs,
// the 'activate' event or 'ready' event should trigger window creation.
// Since the app registers 'activate' to call launchApp, we can trigger it.
app.on('ready', () => {
  // Give the setup callback time to initialize IPC handlers
  setTimeout(() => {
    const { BrowserWindow } = require('electron');
    if (BrowserWindow.getAllWindows().length === 0) {
      console.log('[Linux] No window after init - emitting activate to trigger launchApp');
      app.emit('activate', {}, false);
    }
  }, 4000);
});

// Load the original webpack-bundled app
require(path.join(APP_DIR, 'app.js'));
