"use strict";
// Brent Shambaugh <brent.shambaugh@gmail.com>. 2021.
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
exports.pubKeyBytesToXY = exports.keyToDidDoc = void 0;
var u8a = __importStar(require("uint8arrays"));
var nist_weierstrauss = __importStar(require("nist-weierstrauss"));
/**
 * Constructs the document based on the method key
 */
function keyToDidDoc(_a) {
    var pubKeyBytes = _a.pubKeyBytes, fingerprint = _a.fingerprint;
    var did = "did:key:".concat(fingerprint);
    var keyId = "".concat(did, "#").concat(fingerprint);
    var key = pubKeyBytesToXY(pubKeyBytes);
    return {
        id: did,
        verificationMethod: [
            {
                id: keyId,
                type: 'JsonWebKey2020',
                controller: did,
                publicKeyJwk: {
                    kty: 'EC',
                    crv: 'P-521',
                    x: key.xm,
                    y: key.ym,
                },
            },
        ],
        authentication: [keyId],
        assertionMethod: [keyId],
        capabilityDelegation: [keyId],
        capabilityInvocation: [keyId],
    };
}
exports.keyToDidDoc = keyToDidDoc;
/**
 *
 * @param pubKeyBytes - public key as compressed with 0x02 prefix if even and 0x03 prefix if odd.
 * @returns point x,y with coordinates as multibase encoded base64urls
 *
 * See the the did:key specification: https://w3c-ccg.github.io/did-method-key/#p-521.
 * For compression see: https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#rfc.section.3
 * @throws TypeError: input cannot be null or undefined.
 * @throws Error: Unexpected pubKeyBytes
 * @internal
 */
function pubKeyBytesToXY(pubKeyBytes) {
    if (!nist_weierstrauss.nist_weierstrauss_common.testUint8Array(pubKeyBytes)) {
        throw new TypeError('input must be a Uint8Array');
    }
    var publicKeyHex = nist_weierstrauss.nist_weierstrauss_common.pubKeyBytesToHex(pubKeyBytes);
    // compressed p-521 key, SEC format
    // publicKeyHex.length / 2.0 = 67.0 bytes
    if (132 <= publicKeyHex.length && publicKeyHex.length <= 134) {
        if (publicKeyHex.slice(0, 2) == '03' || publicKeyHex.slice(0, 2) == '02') {
            var publicKey = u8a.fromString(publicKeyHex, 'base16');
            var point = nist_weierstrauss.secp521r1.ECPointDecompress(publicKey);
            return nist_weierstrauss.nist_weierstrauss_common.publicKeyIntToXY(point);
        }
    }
    throw new Error('Unexpected pubKeyBytes');
}
exports.pubKeyBytesToXY = pubKeyBytesToXY;
exports.default = { keyToDidDoc: keyToDidDoc };
//# sourceMappingURL=secp521r1.js.map