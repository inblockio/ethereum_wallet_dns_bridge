"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateProof = generateProof;
exports.generateProofFromSignature = generateProofFromSignature;
exports.createMessageToSign = createMessageToSign;
exports.formatTxtRecord = formatTxtRecord;
const { ethers } = require('ethers');
// Default expiration period in days
const DEFAULT_EXPIRATION_DAYS = 90;
function generateProof(domain_1, privateKey_1) {
    return __awaiter(this, arguments, void 0, function* (domain, privateKey, expirationDays = DEFAULT_EXPIRATION_DAYS) {
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const expiration = Math.floor(Date.now() / 1000 + (expirationDays * 24 * 60 * 60)).toString();
        // Message format: unix_timestamp|domain_name|expiration_timestamp
        const message = `${timestamp}|${domain}|${expiration}`;
        // Sign with EIP-191 compliant personal_sign format
        // ethers.js automatically applies: "\x19Ethereum Signed Message:\n" + len(message) + message
        // This matches MetaMask's personal_sign behavior (EIP-191 version 0x45)
        const wallet = new ethers.Wallet(privateKey);
        const signature = yield wallet.signMessage(message);
        return {
            walletAddress: wallet.address,
            domainName: domain,
            timestamp,
            expiration,
            signature
        };
    });
}
// Function for MetaMask signatures with expiration
function generateProofFromSignature(domain, walletAddress, timestamp, expiration, signature) {
    return {
        walletAddress,
        domainName: domain,
        timestamp,
        expiration,
        signature
    };
}
function createMessageToSign(domain, timestamp, expiration) {
    return `${timestamp}|${domain}|${expiration}`;
}
function formatTxtRecord(proof) {
    return `wallet=${proof.walletAddress}&timestamp=${proof.timestamp}&expiration=${proof.expiration}&sig=${proof.signature}`;
}
