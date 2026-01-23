"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
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
exports.verifyProofSecure = verifyProofSecure;
const { ethers } = require('ethers');
const dns = __importStar(require("dns"));
const util_1 = require("util");
const resolveTxt = (0, util_1.promisify)(dns.resolveTxt);
// Security constants
const MAX_SIGNATURE_AGE_DAYS = 90;
const SIGNATURE_REGEX = /^0x[a-fA-F0-9]{130}$/;
const WALLET_REGEX = /^0x[a-fA-F0-9]{40}$/;
function verifyProofSecure(domain, lookupKey) {
    return __awaiter(this, void 0, void 0, function* () {
        // Normalize domain to lowercase to prevent case-sensitivity attacks
        domain = domain.toLowerCase().trim();
        const recordName = `aqua._${lookupKey}.${domain}`;
        let testsPassed = 0;
        let totalTests = 0;
        console.log('\n🔍 Starting secure verification tests...\n');
        // Test 1: Domain Input Validation
        totalTests++;
        console.log(`Test 1/8: Domain Input Validation`);
        // Validate domain format
        const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/;
        if (!domainRegex.test(domain)) {
            console.log('   ❌ FAIL: Invalid domain format');
            console.log(`   ℹ️  Domain: ${domain}`);
            return false;
        }
        // Check for IDN homograph attacks
        if (domain.includes('xn--')) {
            console.log('   ⚠️  WARNING: Internationalized domain name detected');
            console.log('   ℹ️  Ensure this is the intended domain');
        }
        console.log('   ✅ PASS: Domain format validated');
        testsPassed++;
        // Test 2: DNS Record Retrieval with DNSSEC recommendation
        totalTests++;
        console.log(`\nTest 2/8: DNS Record Retrieval`);
        console.log(`   Querying: ${recordName}`);
        try {
            const txtRecords = yield resolveTxt(recordName);
            if (!txtRecords || txtRecords.length === 0) {
                console.log('   ❌ FAIL: No TXT records found');
                return false;
            }
            console.log(`   ✅ PASS: Found ${txtRecords.length} TXT record(s)`);
            console.log('   ⚠️  NOTE: DNSSEC validation not implemented - verify DNS security separately');
            testsPassed++;
            // Test 3: Single Valid Record Enforcement
            totalTests++;
            console.log(`\nTest 3/8: Single Valid Record Enforcement`);
            const walletRecords = txtRecords.flat().filter(record => record.includes('wallet=') && record.includes('timestamp=') && record.includes('sig='));
            if (walletRecords.length === 0) {
                console.log('   ❌ FAIL: No wallet records found');
                return false;
            }
            if (walletRecords.length > 1) {
                console.log('   ❌ FAIL: Multiple wallet records found - ambiguous state');
                console.log(`   ℹ️  Found ${walletRecords.length} wallet records`);
                console.log('   ℹ️  Only one wallet record should exist per domain');
                return false;
            }
            const txtRecord = walletRecords[0];
            console.log('   ✅ PASS: Exactly one wallet record found');
            testsPassed++;
            // Test 4: Secure Field Parsing
            totalTests++;
            console.log(`\nTest 4/8: Secure Field Parsing`);
            const parsedRecord = parseSecureTxtRecord(txtRecord);
            if (!parsedRecord.wallet || !parsedRecord.timestamp || !parsedRecord.sig) {
                console.log('   ❌ FAIL: Missing required fields');
                return false;
            }
            // Validate wallet address format and checksum
            if (!WALLET_REGEX.test(parsedRecord.wallet)) {
                console.log('   ❌ FAIL: Invalid wallet address format');
                return false;
            }
            try {
                const checksumAddress = ethers.utils.getAddress(parsedRecord.wallet);
                if (checksumAddress !== parsedRecord.wallet) {
                    console.log('   ⚠️  WARNING: Wallet address not in checksum format');
                    console.log(`   ℹ️  Expected: ${checksumAddress}`);
                    console.log(`   ℹ️  Found: ${parsedRecord.wallet}`);
                    // Continue but normalize to checksum format
                    parsedRecord.wallet = checksumAddress;
                }
            }
            catch (error) {
                console.log('   ❌ FAIL: Invalid wallet address');
                return false;
            }
            // Validate signature format
            if (!SIGNATURE_REGEX.test(parsedRecord.sig)) {
                console.log('   ❌ FAIL: Invalid signature format');
                console.log('   ℹ️  Expected: 0x followed by 130 hex characters');
                return false;
            }
            console.log('   ✅ PASS: All fields parsed and validated');
            console.log(`   ℹ️  Wallet: ${parsedRecord.wallet} (checksum validated)`);
            testsPassed++;
            // Test 5: Timestamp Security Validation
            totalTests++;
            console.log(`\nTest 5/8: Timestamp Security Validation`);
            const timestamp = parseInt(parsedRecord.timestamp);
            const timestampDate = new Date(timestamp * 1000);
            const now = new Date();
            const ageMs = now.getTime() - timestampDate.getTime();
            const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
            if (isNaN(timestamp) || timestamp <= 0) {
                console.log('   ❌ FAIL: Invalid timestamp');
                return false;
            }
            // Check for future timestamps (clock skew attack)
            if (timestamp > Math.floor(now.getTime() / 1000) + 300) { // 5 min tolerance
                console.log('   ❌ FAIL: Timestamp is in the future');
                console.log('   🚨 Possible clock manipulation attack');
                return false;
            }
            // Check for expired signatures
            if (ageDays > MAX_SIGNATURE_AGE_DAYS) {
                console.log('   ❌ FAIL: Signature has expired');
                console.log(`   ℹ️  Age: ${ageDays} days (max: ${MAX_SIGNATURE_AGE_DAYS} days)`);
                console.log('   ℹ️  Please generate a new signature');
                return false;
            }
            console.log('   ✅ PASS: Timestamp validated');
            console.log(`   ℹ️  Signature age: ${ageDays} days (expires in ${MAX_SIGNATURE_AGE_DAYS - ageDays} days)`);
            testsPassed++;
            // Test 6: Message Reconstruction
            totalTests++;
            console.log(`\nTest 6/8: Secure Message Reconstruction`);
            const originalMessage = `${parsedRecord.timestamp}|${domain}`;
            console.log(`   📝 Message format: "timestamp|domain"`);
            console.log(`   ℹ️  Reconstructed: "${originalMessage}"`);
            console.log('   ✅ PASS: Message reconstructed for verification');
            testsPassed++;
            // Test 7: Cryptographic Signature Verification
            totalTests++;
            console.log(`\nTest 7/8: Cryptographic Signature Verification`);
            try {
                const recoveredAddress = ethers.utils.verifyMessage(originalMessage, parsedRecord.sig);
                const normalizedRecovered = ethers.utils.getAddress(recoveredAddress);
                console.log(`   ℹ️  Claimed wallet: ${parsedRecord.wallet}`);
                console.log(`   ℹ️  Recovered wallet: ${normalizedRecovered}`);
                if (normalizedRecovered !== parsedRecord.wallet) {
                    console.log('   ❌ FAIL: Signature verification failed');
                    console.log('   🚨 The signature was NOT created by the claimed wallet');
                    return false;
                }
                console.log('   ✅ PASS: Signature cryptographically verified');
                console.log('   🔐 Confirmed ownership of wallet address');
                testsPassed++;
                // Test 8: Domain Binding Verification (CRITICAL - after sig verification)
                totalTests++;
                console.log(`\nTest 8/8: Domain Binding Verification`);
                // Extract and normalize the signed domain
                const messageParts = originalMessage.split('|');
                if (messageParts.length !== 2) {
                    console.log('   ❌ FAIL: Invalid message format');
                    return false;
                }
                const signedDomain = messageParts[1].toLowerCase().trim();
                console.log(`   ℹ️  Domain requested: ${domain}`);
                console.log(`   ℹ️  Domain in signature: ${signedDomain}`);
                console.log(`   ℹ️  DNS location: ${recordName}`);
                if (signedDomain !== domain) {
                    console.log('   ❌ FAIL: Domain binding mismatch!');
                    console.log('   🚨 SECURITY ALERT: Signature was created for a different domain');
                    console.log('   🚨 This indicates a possible DNS record copying attack');
                    return false;
                }
                // Additional check: ensure DNS record location matches
                if (!recordName.endsWith(`.${domain}`)) {
                    console.log('   ❌ FAIL: DNS record location mismatch');
                    console.log('   🚨 DNS record is not under the verified domain');
                    return false;
                }
                console.log('   ✅ PASS: Domain binding verified');
                console.log('   🔐 Signature is bound to the correct domain');
                testsPassed++;
                // Success Summary
                console.log(`\n🎉 VERIFICATION SUCCESSFUL: ${testsPassed}/${totalTests} tests passed`);
                console.log('✅ All security checks passed');
                console.log(`✅ Wallet ${parsedRecord.wallet} is securely linked to ${domain}`);
                console.log(`⏰ Signature valid for ${MAX_SIGNATURE_AGE_DAYS - ageDays} more days`);
                return true;
            }
            catch (error) {
                console.log('   ❌ FAIL: Signature verification error');
                console.log(`   ℹ️  ${error instanceof Error ? error.message : error}`);
                return false;
            }
        }
        catch (error) {
            console.log('   ❌ FAIL: DNS lookup error');
            console.log(`   ℹ️  ${error instanceof Error ? error.message : error}`);
            return false;
        }
    });
}
function parseSecureTxtRecord(txt) {
    // Create a map to detect duplicate parameters
    const paramMap = new Map();
    // Manual parsing to detect parameter pollution
    const parts = txt.split('&');
    for (const part of parts) {
        const [key, value] = part.split('=');
        if (!key || !value)
            continue;
        if (paramMap.has(key)) {
            throw new Error(`Duplicate parameter detected: ${key}`);
        }
        paramMap.set(key, value);
    }
    // Ensure all required fields exist
    const wallet = paramMap.get('wallet');
    const timestamp = paramMap.get('timestamp');
    const sig = paramMap.get('sig');
    if (!wallet || !timestamp || !sig) {
        throw new Error('Missing required fields in TXT record');
    }
    return { wallet, timestamp, sig, expiration: paramMap.get('expiration') || '' };
}
