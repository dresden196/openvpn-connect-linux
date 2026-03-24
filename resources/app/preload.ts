import { contextBridge, webUtils, ipcRenderer, IpcRendererEvent } from 'electron';

import * as ipcHelper from '../ipc/ipcHelper';

const createDynamicBridge = (methodNames: string[]): { [key: string]: (...args: any[]) => Promise<any> } => {
    return methodNames.reduce((api, methodName) => {
        api[methodName] = async (...args: any[]) => {
            const packedResult = await ipcRenderer.invoke('dynamic-api-bridge', { methodName, args });
            if (packedResult.success) {
                return ipcHelper.unpackData(packedResult.data);
            } else {
                const unpackedError = ipcHelper.unpackData(JSON.parse(packedResult.error));
                throw unpackedError;
            }
        };
        return api;
    }, {});
};

const reactBridgeMethodNames: string[] = [
    'getExternalFilesDirs',
    'getLogData',
    'clearLogFile',
    'connectUsingProfile',
    'resumeVPN',
    'sendAppControlChannelMsg',
    'postChallengeMessage',
    'disconnect',
    'dismissLastEvent',
    'getStats',
    'getConnectionInfo',
    'getSpeedStats',
    'importProfileFromContent',
    'importProfileFromPath',
    'deleteProfile',
    'readProfileFromFile',
    'parseProfileContent',
    'updateProfileContent',
    'renameProfile',
    'profileExists',
    'fetch',
    'cancelFetch',
    'downloadProfile',
    'downloadProfileCertPinned',
    'saveSettingString',
    'saveSettingBoolean',
    'checkConnectionStatus',
    'executeScripts',
    'getConnectionStatus',
    'getSettings',
    'requestVPNRights',
    'showImportDialog',
    'showSaveLogsDialog',
    'savePassword',
    'savePrivateKeyPassword',
    'deletePassword',
    'deletePendingImport',
    'deletePrivateKeyPassword',
    'checkStartupParams',
    'migrateWin32ReconnectProfileID',
    'getDeviceInfo',
    'changePassProfile',
    'getPassword',
    'changePkpProfile',
    'minimizeApp',
    'closeApp',
    'importPKCS12',
    'removeCertificate',
    'migrateCertificates',
    'getIdentityList',
    'createAndUnlockKeychain',
    'createConnectShortcut',
    'createDisconnectShortcut',
    'migrateProfileToId',
    'setReconnectOnReboot',
    'getIsInitialConnect',
    'os',
    'sendReview',
    'getConnectorStatus',
    'checkIfCaptivePortalEnabled',
    'handleNetworkStateChange',
    'UIIsReady',
    'getCertFromSystemStorage',
    'getInfoFromPEM',
    'openURL',
    'pkcs11_getTokens',
    'pkcs11_getToken',
    'pkcs11_composeAlias',
    'pkcs11_parseAlias',
    'pkcs11_getCerts',
    'pkcs11_getCert',
    'pkcs11_getPEM',
    'pkcs11_getPKeys',
    'pkcs11_getPKey',
    'pkcs11_validatePin',
    'addProxy',
    'editProxy',
    'removeProxy',
    'resolvePath'
];

const fsMethodNames: string[] = [
    'getPaths',
    'writeFile',
    'readFile',
    'unlink',
    'readDir',
    'mkdir',
    'exists',
    'stat',
    'readFileSync',
    'isFile',
    'getFileInfo',
    'doesPathExist'
];

const electronAPI = {
    redux: {
        getInitialState: () => ipcRenderer.invoke('reduxGetInitialState'),
        forwardAction: (action: any) => ipcRenderer.send('reduxForwardAction', action),
        onActionReplay: (callback: (action: any) => void) =>
            ipcRenderer.on('reduxActionReplay', (event, action) => callback(action))
    },

    events: {
        emit: (channel: string, ...args: any[]) => ipcRenderer.send(channel, ...args),
        on: (channel: string, callback: (...args: any[]) => void) => {
            const subscription = (event: IpcRendererEvent, ...args: any[]) => callback(...args);
            ipcRenderer.on(channel, subscription);
            return () => ipcRenderer.removeListener(channel, subscription);
        }
    },

    getFilePath: (file: File) => webUtils.getPathForFile(file),
    env: { ENABLE_QA_MODE: process.env.ENABLE_QA_MODE },
    clipboard: {
        writeText: (text): Promise<void> => {
            return ipcRenderer.invoke('clipboard:write-text', text);
        },
        readText: (): Promise<string> => {
            return ipcRenderer.invoke('clipboard:read-text');
        }
    },

    ReactBridge: {
        ...createDynamicBridge(reactBridgeMethodNames),
        getSoftwareUpdate: (silent: boolean): Promise<any> => {
            return ipcRenderer.invoke('software-update:check', silent);
        },

        handleUpdateLink: (): Promise<void> => {
            return ipcRenderer.invoke('software-update:handle-link');
        },

        resetSoftwareUpdateSchedule: (): Promise<void> => {
            return ipcRenderer.invoke('software-update:reset');
        },

        watchThemeChanges: (): Promise<void> => {
            return ipcRenderer.invoke('theme:watch');
        },

        applyTheme: (): Promise<void> => {
            return ipcRenderer.invoke('theme:apply');
        },
        getWebAuthData: (url: string): Promise<any> => {
            return ipcRenderer.invoke('web-auth:get', url);
        },
        openWindow: (): Promise<void> => {
            return ipcRenderer.invoke('window:open');
        },
        showStatusNotification: (status: string): Promise<any> => {
            return ipcRenderer.invoke('notification:show-status', status);
        },
        showMFANotification: (): Promise<void> => {
            return ipcRenderer.invoke('notification:show-mfa');
        },
        showWebAuthNotification: (): Promise<void> => {
            return ipcRenderer.invoke('notification:show-web-auth');
        },
        updateProfileConfig: (profileId: string, newChunk: string): Promise<void> => {
            return ipcRenderer.invoke('patch-api-bridge', profileId, newChunk);
        },
        onDisconnectVpn: (callback) => ipcRenderer.on('disconnect-vpn', callback),
        onVpnConnect: (callback) => ipcRenderer.on('connect-vpn', callback)
    },
    fs: createDynamicBridge(fsMethodNames)
};

contextBridge.exposeInMainWorld('electronAPI', electronAPI);
