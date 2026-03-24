#!/bin/bash
# Build RPM package from the electron-builder linux-unpacked output
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="3.8.0"
RELEASE="1"
NAME="openvpn-connect-linux"
UNPACKED="$PROJECT_DIR/dist/linux-unpacked"

if [ ! -d "$UNPACKED" ]; then
  echo "Error: dist/linux-unpacked not found. Run 'npm run build:appimage' first."
  exit 1
fi

# Set up RPM build tree
RPMDIR=$(mktemp -d)
mkdir -p "$RPMDIR"/{BUILD,RPMS,SPECS,SOURCES,SRPMS}

# Create spec file
cat > "$RPMDIR/SPECS/$NAME.spec" << SPEC
Name:           $NAME
Version:        $VERSION
Release:        $RELEASE%{?dist}
Summary:        OpenVPN Connect VPN Client for Linux with SAML/SSO support
License:        MIT
URL:            https://github.com/dresden196/openvpn-connect-linux

Requires:       openvpn
Requires:       libsecret
Requires:       polkit

%description
Community port of the official OpenVPN Connect client (Windows/macOS) to Linux.
Provides the same GUI experience with full SAML/SSO authentication support.

%install
mkdir -p %{buildroot}/opt/%{name}
cp -a $UNPACKED/* %{buildroot}/opt/%{name}/

mkdir -p %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/openvpn-connect << 'LAUNCHER'
#!/bin/bash
exec /opt/$NAME/openvpn-connect "\$@" --no-sandbox
LAUNCHER
chmod 755 %{buildroot}/usr/bin/openvpn-connect

mkdir -p %{buildroot}/usr/share/applications
cat > %{buildroot}/usr/share/applications/openvpn-connect.desktop << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=OpenVPN Connect
Comment=OpenVPN Connect VPN Client
Exec=/usr/bin/openvpn-connect %U
Icon=openvpn-connect
Terminal=false
Categories=Network;VPN;
Keywords=vpn;openvpn;network;security;saml;sso;
StartupWMClass=openvpn-connect-linux
MimeType=application/x-openvpn-profile;
DESKTOP

# Install icons
for size in 32 36 48 64 96 128 256; do
  icon="$PROJECT_DIR/assets/icons/\${size}x\${size}.png"
  if [ -f "\$icon" ]; then
    mkdir -p %{buildroot}/usr/share/icons/hicolor/\${size}x\${size}/apps
    cp "\$icon" %{buildroot}/usr/share/icons/hicolor/\${size}x\${size}/apps/openvpn-connect.png
  fi
done

%files
/opt/%{name}
/usr/bin/openvpn-connect
/usr/share/applications/openvpn-connect.desktop
/usr/share/icons/hicolor/*/apps/openvpn-connect.png

%post
update-desktop-database /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

%postun
update-desktop-database /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
SPEC

echo "Building RPM..."
rpmbuild -bb \
  --define "_topdir $RPMDIR" \
  "$RPMDIR/SPECS/$NAME.spec"

# Copy RPM to dist/
cp "$RPMDIR/RPMS/x86_64/"*.rpm "$PROJECT_DIR/dist/" 2>/dev/null || \
cp "$RPMDIR/RPMS/"*/*.rpm "$PROJECT_DIR/dist/"

echo "---"
ls -lh "$PROJECT_DIR/dist/"*.rpm
echo "Done!"

# Cleanup
rm -rf "$RPMDIR"
