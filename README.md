# OpenVPN Connect for Linux

Community port of [OpenVPN Connect](https://openvpn.net/client/) to Linux. Same UI and feature set as the official Windows and macOS client.

![OpenVPN Connect](assets/icons/app-icon.png)

## About

OpenVPN Connect is the official VPN client from OpenVPN Inc., available on Windows, macOS, iOS, and Android — but not Linux. This project ports the Electron-based desktop client to Linux, providing the same interface and functionality including profile management, SAML/SSO web authentication, and all connection settings.

### How It Works

The official OpenVPN Connect app is built with Electron. This port:

- Extracts the existing Electron app from the official release
- Replaces the proprietary OpenVPN3 C++ native module (`napi.node`) with a JavaScript shim that uses the system `openvpn` binary via the [management interface](https://openvpn.net/community-resources/management-interface/)
- Adds Linux platform shims for Windows/macOS-specific APIs (credential storage, window decorations, system commands, auto-start)
- Patches the Electron shell for native KDE/GNOME window decorations

The VPN connection itself is handled by your system's `openvpn` package — this project provides the GUI and orchestration layer on top of it.

## Installation

### AppImage (Recommended)

Download the latest AppImage from [Releases](https://github.com/dresden196/openvpn-connect-linux/releases).

```bash
chmod +x openvpn-connect-linux-*-x86_64.AppImage
./openvpn-connect-linux-*-x86_64.AppImage
```

### Arch Linux (AUR)

```bash
yay -S openvpn-connect-linux
```

### Fedora / RHEL / CentOS / openSUSE (RPM)

Download the `.rpm` from [Releases](https://github.com/dresden196/openvpn-connect-linux/releases).

```bash
sudo dnf install openvpn-connect-linux-3.8.0-1.x86_64.rpm
```

### Ubuntu / Debian / Mint (deb)

Download the `.deb` from [Releases](https://github.com/dresden196/openvpn-connect-linux/releases).

```bash
sudo dpkg -i openvpn-connect-linux-3.8.0-amd64.deb
sudo apt-get install -f  # install dependencies
```

### Requirements

- Linux x86_64
- `openvpn` 2.5+ installed (`sudo pacman -S openvpn` / `sudo dnf install openvpn` / `sudo apt install openvpn`)
- `polkit` for privilege escalation (included in most desktop environments)
- `libsecret` for credential storage (included with KDE/GNOME)

### Tested On

- Arch Linux / KDE Plasma (Wayland + X11)
- Should work on any Linux distribution with a modern desktop environment

## Differences from Windows/macOS

| Feature | Windows/macOS | Linux Port |
|---|---|---|
| VPN Engine | OpenVPN3 C++ library (embedded) | System `openvpn` binary via management interface |
| Privilege Escalation | Windows Service / launchd | polkit (`pkexec`) |
| Credential Storage | Windows Credential Vault / macOS Keychain | libsecret (KDE Wallet / GNOME Keyring) |
| Window Decorations | Custom frameless (Windows) / native (macOS) | Native KDE/GNOME decorations |
| Protocol "Adaptive" | Supported (OpenVPN3 feature) | Stripped — uses profile's proto setting |
| Auto-Start | Windows Registry / macOS Login Items | XDG autostart `.desktop` file |
| System Tray | Native | Native (AppIndicator/StatusNotifierItem) |
| DCO (Data Channel Offload) | Windows kernel driver | Linux `ovpn-dco` kernel module (if available) |
| PKCS#11 Smart Cards | Full support | Native via `pkcs11js` + system `.so` modules (e.g. `opensc-pkcs11.so`) |

### Known Limitations

- The `disconnect` button uses the management interface to signal the openvpn process. If the management connection is lost, you may need to manually kill the openvpn process (`sudo pkill openvpn`).
- The "Adaptive" protocol option (try UDP then fall back to TCP) is an OpenVPN3-only feature. On Linux, the protocol from your `.ovpn` profile is used directly.
- Server-pushed options like `dhcp-pre-release`, `dhcp-renew`, and `register-dns` are Windows-specific and ignored by the Linux openvpn binary (harmless warnings).

## Building from Source

### Prerequisites

```bash
# Arch Linux
sudo pacman -S nodejs npm openvpn libsecret imagemagick

# Debian/Ubuntu
sudo apt install nodejs npm openvpn libsecret-1-dev libsecret-1-0
```

### Build

```bash
git clone https://github.com/dresden196/openvpn-connect-linux.git
cd openvpn-connect-linux
npm install
npm run build:appimage    # AppImage (universal)
npm run build:rpm         # RPM (Fedora/RHEL/openSUSE)
npm run build:deb         # deb (Ubuntu/Debian/Mint)
```

Packages will be in `dist/`.

RPM build requires `rpmbuild` (`sudo dnf install rpm-build` / `sudo pacman -S rpm-tools`).

### Development

```bash
npm install
npm start              # Run the app
npm run start:debug    # Run with DevTools inspector
```

## Updating to a New OpenVPN Connect Version

When OpenVPN Inc. releases a new version of OpenVPN Connect:

1. Download the new macOS DMG. (The Windows MSI also works, but see
   [Release Schedule](#release-schedule) for why macOS is preferred.)
2. Extract the `app.asar` file:
   ```bash
   # From DMG (preferred)
   7z x openvpn-connect-*.dmg
   7z x "OpenVPN Connect/OpenVPN_Connect_*_x86_64_Installer_signed.pkg" -opkg
   cd pkg/tmp-app.pkg && cat Payload | gzip -dc | cpio -idm
   npx @electron/asar extract Contents/Resources/app.asar resources/app

   # From MSI
   msiextract openvpn-connect-*.msi
   npx @electron/asar extract "OpenVPN Connect/resources/app.asar" resources/app
   ```
3. Keep the source maps somewhere outside the tree for reference, then drop them
   from the shipped app (they add roughly 16 MB):
   ```bash
   cp resources/app/*.map ~/openvpn-connect-maps/   # not committed
   rm -f resources/app/*.map
   ```
4. Diff `resources/app/preload.ts` against the previous release. Every new entry
   in `reactBridgeMethodNames` is an API the renderer can call, and the shim must
   implement or deliberately stub it.
5. Test: `npm start`
6. Build: `npm run build:appimage`

The shim layer (`src/`) is version-independent in most cases. If OpenVPN Inc. changes the internal API surface of `napi.node`, the shim may need updates.

## Release Schedule

Releases follow the official OpenVPN Connect release cycle with a short delay for testing, typically 2–4 weeks after a new official release.

**The port tracks the macOS builds.** The Windows and macOS streams have diverged: they no longer share version numbers or release dates, and neither is reliably ahead. Windows went 3.8.0 (Sep 2025) straight to 3.9.0 (Jun 2026), while macOS went 3.8.0 → 3.8.1 → 3.8.2 (May 2026). macOS is the better base for two reasons:

- **Less unusable surface.** Recent Windows releases add features that cannot work on Linux. 3.9.0's Pre-Login Connect (SBL) introduces nine `vpnSystemService_*` IPC methods tied to the Windows sign-in screen; tracking macOS keeps them out of the shim layer.
- **Source maps.** macOS builds ship `app.js.map` and `bundle.web.js.map` with full `sourcesContent` — the original TypeScript. Windows builds ship none. Reading upstream's real source makes tracking internal API changes between releases dramatically easier than diffing minified bundles.

Tracking macOS does not mean missing platform-neutral fixes. The same `app.asar` is shipped on both platforms — it carries Windows `.ico` assets and `Shortcut.exe` even in the macOS build — and branches on `Platform.OS` at runtime.

Current base: **3.8.2 (6009)**, taken from the macOS DMG.

## Project Structure

```
openvpn-connect-linux/
├── src/
│   ├── main.js              # Electron entry point with Linux platform patches
│   └── shims/
│       ├── napi-shim.js     # OpenVPN management interface client (replaces napi.node)
│       ├── electron-shim.js # BrowserWindow patches for native Linux decorations
│       ├── keytar-shim.js   # Fallback credential storage
│       └── pkcs11-shim.js   # PKCS#11 stub
├── resources/
│   └── app/                 # Extracted OpenVPN Connect Electron app (unmodified)
├── assets/
│   └── icons/               # App icons extracted from official release
├── package.json
└── run.sh                   # Quick launch script
```

## License

The shim layer (`src/`) is MIT licensed. The OpenVPN Connect app (`resources/app/`) is the property of OpenVPN Inc. and subject to their [terms of service](https://openvpn.net/terms/).
