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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.keyToDidDoc = void 0;
var u8a = __importStar(require("uint8arrays"));
// import { edwardsToMontgomery } from '@noble/curves/ed25519'
var ed25519_1 = require("@stablelib/ed25519");
var types_1 = require("../types");
function encodeKey(key, encodeKey) {
    var bytes = new Uint8Array(key.length + 2);
    bytes[0] = encodeKey !== null && encodeKey !== void 0 ? encodeKey : 0xec;
    // The multicodec is encoded as a varint so we need to add this.
    // See js-multicodec for a general implementation
    bytes[1] = 0x01;
    bytes.set(key, 2);
    return "z".concat(u8a.toString(bytes, 'base58btc'));
}
var keyToDidDoc = function (args) {
    var options = args.options;
    if (!(options === null || options === void 0 ? void 0 : options.publicKeyFormat)) {
        return keyToDidDoc2020(args);
    }
    switch (options.publicKeyFormat) {
        case 'Ed25519VerificationKey2018':
        case 'X25519KeyAgreementKey2019':
            return keyToDidDoc2018_2019(args);
        case 'Ed25519VerificationKey2020':
        case 'X25519KeyAgreementKey2020':
        case 'Multikey':
            return keyToDidDoc2020(args);
        default:
            throw Error("".concat(options.publicKeyFormat, " not supported yet for the ed25519 driver"));
    }
};
exports.keyToDidDoc = keyToDidDoc;
var keyToDidDoc2018_2019 = function (_a) {
    var pubKeyBytes = _a.pubKeyBytes, fingerprint = _a.fingerprint, contentType = _a.contentType;
    var did = "did:key:".concat(fingerprint);
    var keyId = "".concat(did, "#").concat(fingerprint);
    //todo: Move to noble lib. x25519 values differ between below methods. Current implementation is correct according to DID:key spec
    // const pubKeyHex = u8a.toString(pubKeyBytes, 'base16')
    // const x25519PubBytes = edwardsToMontgomery(pubKeyHex)
    var x25519PubBytes = (0, ed25519_1.convertPublicKeyToX25519)(pubKeyBytes);
    var x25519KeyId = "".concat(did, "#").concat(encodeKey(x25519PubBytes));
    return __assign(__assign({}, (contentType === types_1.DID_LD_JSON && {
        '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/ed25519-2018/v1',
            'https://w3id.org/security/suites/x25519-2019/v1',
        ],
    })), { id: did, verificationMethod: [
            {
                id: keyId,
                type: 'Ed25519VerificationKey2018',
                controller: did,
                publicKeyBase58: u8a.toString(pubKeyBytes, 'base58btc'),
            },
            {
                id: x25519KeyId,
                type: 'X25519KeyAgreementKey2019',
                controller: did,
                publicKeyBase58: u8a.toString(x25519PubBytes, 'base58btc'),
            },
        ], authentication: [keyId], assertionMethod: [keyId], capabilityDelegation: [keyId], capabilityInvocation: [keyId], keyAgreement: [x25519KeyId] });
};
var keyToDidDoc2020 = function (_a) {
    var pubKeyBytes = _a.pubKeyBytes, fingerprint = _a.fingerprint, contentType = _a.contentType;
    var did = "did:key:".concat(fingerprint);
    var keyId = "".concat(did, "#").concat(fingerprint);
    //todo: Move to noble lib. x25519 values differ between below methods. Current implementation is correct according to DID:key spec
    // const pubKeyHex = u8a.toString(pubKeyBytes, 'base16')
    // const x25519PubBytes = edwardsToMontgomery(pubKeyBytes)
    var x25519PubBytes = (0, ed25519_1.convertPublicKeyToX25519)(pubKeyBytes);
    var x25519KeyId = "".concat(did, "#").concat(encodeKey(x25519PubBytes));
    return __assign(__assign({}, (contentType === types_1.DID_LD_JSON && {
        '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/ed25519-2020/v1',
            'https://w3id.org/security/suites/x25519-2020/v1',
        ],
    })), { id: did, verificationMethod: [
            {
                id: keyId,
                type: 'Ed25519VerificationKey2020',
                controller: did,
                publicKeyMultibase: encodeKey(pubKeyBytes, 0xed),
            },
        ], authentication: [keyId], assertionMethod: [keyId], capabilityDelegation: [keyId], capabilityInvocation: [keyId], keyAgreement: [
            {
                id: x25519KeyId,
                type: 'X25519KeyAgreementKey2020',
                controller: did,
                publicKeyMultibase: encodeKey(x25519PubBytes, 0xec),
            },
        ] });
};
exports.default = { keyToDidDoc: exports.keyToDidDoc };
//# sourceMappingURL=ed25519.js.map