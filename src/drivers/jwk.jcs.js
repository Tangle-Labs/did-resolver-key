"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.keyToDidDoc = void 0;
var index_1 = require("../index");
var ssi_sdk_ext_key_utils_1 = require("@sphereon/ssi-sdk-ext.key-utils");
var keyToDidDoc = function (_a) {
    var pubKeyBytes = _a.pubKeyBytes, fingerprint = _a.fingerprint, contentType = _a.contentType;
    var did = "did:key:".concat(fingerprint);
    var keyId = "".concat(did, "#").concat(fingerprint);
    var publicKeyJwk = (0, ssi_sdk_ext_key_utils_1.jwkJcsDecode)(pubKeyBytes);
    return __assign(__assign({}, (contentType === index_1.DID_LD_JSON && {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    })), { id: did, verificationMethod: [
            {
                id: keyId,
                type: 'JsonWebKey2020',
                controller: did,
                publicKeyJwk: publicKeyJwk,
            },
        ], authentication: [keyId], assertionMethod: [keyId], capabilityDelegation: [keyId], capabilityInvocation: [keyId] });
};
exports.keyToDidDoc = keyToDidDoc;
exports.default = { keyToDidDoc: exports.keyToDidDoc };
//# sourceMappingURL=jwk.jcs.js.map