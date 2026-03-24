/**
 * keytar-shim.js - Fallback credential storage for Linux
 *
 * If the native keytar module can't be rebuilt, this provides
 * credential storage using an encrypted JSON file.
 * In production, the native keytar module with libsecret (KDE Wallet / GNOME Keyring)
 * is preferred and this is only a fallback.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const STORE_DIR = path.join(os.homedir(), '.config', 'openvpn-connect');
const STORE_FILE = path.join(STORE_DIR, '.credentials.enc');

// Derive key from machine-id + username for basic protection
function getKey() {
  let machineId = 'fallback-machine-id';
  try {
    machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim();
  } catch {
    try {
      machineId = fs.readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
    } catch {}
  }
  return crypto.scryptSync(machineId + os.userInfo().username, 'openvpn-connect-linux', 32);
}

function encrypt(text) {
  const key = getKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  const key = getKey();
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const tag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      const raw = fs.readFileSync(STORE_FILE, 'utf8');
      return JSON.parse(decrypt(raw));
    }
  } catch {}
  return {};
}

function saveStore(store) {
  if (!fs.existsSync(STORE_DIR)) {
    fs.mkdirSync(STORE_DIR, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(STORE_FILE, encrypt(JSON.stringify(store)), { mode: 0o600 });
}

function makeKey(service, account) {
  return `${service}::${account}`;
}

module.exports = {
  async getPassword(service, account) {
    const store = loadStore();
    return store[makeKey(service, account)] || null;
  },

  async setPassword(service, account, password) {
    const store = loadStore();
    store[makeKey(service, account)] = password;
    saveStore(store);
  },

  async deletePassword(service, account) {
    const store = loadStore();
    const key = makeKey(service, account);
    const existed = key in store;
    delete store[key];
    saveStore(store);
    return existed;
  },

  async findCredentials(service) {
    const store = loadStore();
    const prefix = service + '::';
    return Object.entries(store)
      .filter(([k]) => k.startsWith(prefix))
      .map(([k, v]) => ({
        account: k.substring(prefix.length),
        password: v,
      }));
  },

  async findPassword(service) {
    const store = loadStore();
    const prefix = service + '::';
    const entry = Object.entries(store).find(([k]) => k.startsWith(prefix));
    return entry ? entry[1] : null;
  },
};
