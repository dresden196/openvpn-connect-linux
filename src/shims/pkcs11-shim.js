/**
 * pkcs11-shim.js - PKCS#11 stub for Linux
 *
 * Fallback if native pkcs11js can't be rebuilt.
 * The real pkcs11js module works on Linux and should be preferred.
 * This stub allows the app to start without PKCS#11 hardware token support.
 */

class PKCS11 {
  constructor() {
    this._initialized = false;
    this._modules = [];
  }

  load(libraryPath) {
    console.log(`[PKCS11 Shim] Would load library: ${libraryPath}`);
    // On Linux, PKCS#11 modules are .so files, e.g.:
    // /usr/lib/opensc-pkcs11.so
    // /usr/lib/softhsm/libsofthsm2.so
  }

  C_Initialize(initArgs) {
    this._initialized = true;
  }

  C_Finalize() {
    this._initialized = false;
  }

  C_GetInfo() {
    return {
      cryptokiVersion: { major: 2, minor: 40 },
      manufacturerID: 'Linux PKCS#11 Shim',
      libraryDescription: 'OpenVPN Connect Linux PKCS#11',
      libraryVersion: { major: 1, minor: 0 },
    };
  }

  C_GetSlotList(tokenPresent) {
    return [];
  }

  C_GetSlotInfo(slotId) {
    return null;
  }

  C_GetTokenInfo(slotId) {
    return null;
  }

  C_OpenSession(slotId, flags) {
    return null;
  }

  C_CloseSession(session) {}

  C_CloseAllSessions(slotId) {}

  C_Login(session, userType, pin) {}

  C_Logout(session) {}

  C_FindObjectsInit(session, template) {}

  C_FindObjects(session, maxCount) {
    return [];
  }

  C_FindObjectsFinal(session) {}

  C_GetAttributeValue(session, objectHandle, template) {
    return template;
  }

  C_SignInit(session, mechanism, key) {}

  C_Sign(session, data, outputLen) {
    return Buffer.alloc(0);
  }

  C_GetMechanismList(slotId) {
    return [];
  }

  C_GetMechanismInfo(slotId, mechanism) {
    return {};
  }
}

module.exports = { PKCS11 };
