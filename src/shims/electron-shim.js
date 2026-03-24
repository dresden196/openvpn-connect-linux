/**
 * electron-shim.js - Wraps the real electron module to patch BrowserWindow
 * for native Linux window decorations (frame: true).
 */
const electron = require('electron');
const path = require('path');

// Wrap BrowserWindow to force native frame on Linux
const OrigBW = electron.BrowserWindow;

// App icon path
const APP_ICON = path.join(__dirname, '..', '..', 'assets', 'icons', 'app-icon.png');

class LinuxBrowserWindow extends OrigBW {
  constructor(options = {}) {
    // Force native window frame for proper KDE/GNOME decorations
    options.frame = true;
    delete options.titleBarStyle;
    options.skipTaskbar = false;
    options.resizable = true;
    options.autoHideMenuBar = true;
    options.minWidth = 380;
    options.minHeight = 500;
    // Set the proper OpenVPN icon for taskbar/window
    try {
      options.icon = electron.nativeImage.createFromPath(APP_ICON);
    } catch {}

    console.log('[Linux] BrowserWindow: using native frame (KDE/GNOME decorations)');
    super(options);

    // After content loads, fix visual issues from the frameless-mode design
    this.webContents.on('did-finish-load', () => {
      this.webContents.insertCSS(`
        /* Remove Windows-style border around the app */
        .root-border {
          border: none !important;
        }

        /* Disable drag regions - native frame handles window dragging */
        [style*="-webkit-app-region: drag"],
        [style*="app-region: drag"] {
          -webkit-app-region: no-drag !important;
        }
        .windowsNoDraggable {
          -webkit-app-region: no-drag !important;
        }
      `);

      // After React renders, find and hide just the title text
      // but keep the hamburger/help icons in the bar
      const fixTitleBar = () => {
        this.webContents.executeJavaScript(`
          (function() {
            // Find the drag region bar (contains title + hamburger + help)
            const allEls = document.querySelectorAll('*');
            for (const el of allEls) {
              if (el.style && el.style.webkitAppRegion === 'drag') {
                // This is the title bar container - keep it but shrink it
                el.style.webkitAppRegion = 'no-drag';

                // Find the title text inside and hide it
                // The title is usually in a text node or span
                const children = el.querySelectorAll('*');
                for (const child of children) {
                  const text = child.textContent?.trim();
                  if (text === 'OpenVPN Connect' && !child.querySelector('*')) {
                    // This is the title text element - hide it
                    child.style.display = 'none';
                    console.log('[Linux] Hidden title text element');
                  }
                }

                // Reduce the top padding/height of the bar since
                // we no longer need space for the frameless drag area
                el.style.paddingTop = '4px';
                el.style.minHeight = 'auto';
                console.log('[Linux] Adjusted title bar');
                break;
              }
            }
          })();
        `).catch(() => {});
      };

      // Run after React mounts (needs time to render)
      setTimeout(fixTitleBar, 2000);
      setTimeout(fixTitleBar, 4000);

      console.log('[Linux] Applied CSS fixes');
    });
  }
}

// Re-export everything from electron, replacing BrowserWindow
module.exports = new Proxy(electron, {
  get(target, prop) {
    if (prop === 'BrowserWindow') return LinuxBrowserWindow;
    return target[prop];
  },
});
