"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getResolver = void 0;
var varint_1 = require("varint");
var base58_1 = require("multiformats/bases/base58");
var ed25519_1 = __importDefault(require("./drivers/ed25519"));
var bls12381g2_1 = __importDefault(require("./drivers/bls12381g2"));
var secp256k1_1 = __importDefault(require("./drivers/secp256k1"));
var secp256r1_1 = __importDefault(require("./drivers/secp256r1"));
var secp384r1_1 = __importDefault(require("./drivers/secp384r1"));
var secp521r1_1 = __importDefault(require("./drivers/secp521r1"));
var jwk_jcs_1 = __importDefault(require("./drivers/jwk.jcs"));
var types_1 = require("./types");
__exportStar(require("./types"), exports);
var prefixToDriverMap = {
    0xe7: secp256k1_1.default,
    0xed: ed25519_1.default,
    0x1200: secp256r1_1.default,
    0x1201: secp384r1_1.default,
    0x1202: secp521r1_1.default,
    0xeb: bls12381g2_1.default,
    0xeb51: jwk_jcs_1.default,
};
var getResolver = function () {
    return {
        key: function (did, parsed, r, options) { return __awaiter(void 0, void 0, void 0, function () {
            var contentType, response, multicodecPubKey, keyType, pubKeyBytes, args, doc, e_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        contentType = options.accept || types_1.DID_LD_JSON;
                        response = {
                            didResolutionMetadata: { contentType: contentType },
                            didDocument: null,
                            didDocumentMetadata: {},
                        };
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        multicodecPubKey = base58_1.base58btc.decode(parsed.id);
                        keyType = (0, varint_1.decode)(multicodecPubKey);
                        pubKeyBytes = multicodecPubKey.slice(varint_1.decode.bytes);
                        args = { pubKeyBytes: pubKeyBytes, fingerprint: parsed.id, contentType: contentType, options: options };
                        return [4 /*yield*/, prefixToDriverMap[keyType].keyToDidDoc(args)];
                    case 2:
                        doc = _a.sent();
                        if (contentType === types_1.DID_LD_JSON) {
                            if (!doc['@context']) {
                                doc['@context'] = 'https://w3id.org/did/v1';
                            }
                            else if (Array.isArray(doc['@context']) &&
                                !doc['@context'].includes('https://w3id.org/did/v1') &&
                                !doc['@context'].includes('https://www.w3.org/ns/did/v1')) {
                                doc['@context'].push('https://w3id.org/did/v1');
                            }
                            response.didDocument = doc;
                        }
                        else if (contentType === types_1.DID_JSON) {
                            response.didDocument = doc;
                        }
                        else {
                            delete response.didResolutionMetadata.contentType;
                            response.didResolutionMetadata.error = 'representationNotSupported';
                        }
                        return [3 /*break*/, 4];
                    case 3:
                        e_1 = _a.sent();
                        response.didResolutionMetadata.error = 'invalidDid';
                        response.didResolutionMetadata.message = e_1.toString();
                        return [3 /*break*/, 4];
                    case 4: return [2 /*return*/, response];
                }
            });
        }); },
    };
};
exports.getResolver = getResolver;
exports.default = { getResolver: exports.getResolver };
//# sourceMappingURL=index.js.map