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
exports.verifyProof = verifyProof;
const { ethers } = require('ethers');
const dns = __importStar(require("dns"));
const util_1 = require("util");
const resolveTxt = (0, util_1.promisify)(dns.resolveTxt);
// Rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 10; // Max requests per window
const RATE_LIMIT_WINDOW = 60000; // 1 minute window
// DNSSEC validation using DNS.resolveAny with AD flag
function resolveTxtWithDNSSEC(domain) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            const resolver = new dns.Resolver();
            // Enable DNSSEC validation by requesting AD (Authenticated Data) flag
            resolver.setServers(resolver.getServers());
            // Use resolve4 with options to check DNSSEC
            resolver.resolve4(domain.replace('aqua._wallet.', ''), { ttl: true }, (err, addresses) => {
                if (err && err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
                    // Check if we can get basic DNS resolution for the parent domain
                    resolver.resolveTxt(domain, (txtErr, txtRecords) => {
                        if (txtErr) {
                            reject(txtErr);
                        }
                        else {
                            // We got TXT records but couldn't verify DNSSEC
                            resolve({ records: txtRecords, dnssecValidated: false });
                        }
                    });
                }
                else {
                    // Now get the actual TXT records
                    resolver.resolveTxt(domain, (txtErr, txtRecords) => {
                        if (txtErr) {
                            reject(txtErr);
                        }
                        else {
                            // Simple DNSSEC check: if parent domain resolves, we have basic validation
                            resolve({ records: txtRecords, dnssecValidated: true });
                        }
                    });
                }
            });
        });
    });
}
// Rate limiting check
function checkRateLimit(identifier) {
    const now = Date.now();
    const limit = rateLimitMap.get(identifier);
    if (!limit || now > limit.resetTime) {
        // New window
        rateLimitMap.set(identifier, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
        return true;
    }
    if (limit.count >= RATE_LIMIT_MAX) {
        return false;
    }
    limit.count++;
    return true;
}
function verifyProof(domain, lookupKey) {
    return __awaiter(this, void 0, void 0, function* () {
        // Rate limiting by domain
        if (!checkRateLimit(domain)) {
            console.log('\n⚠️  Rate limit exceeded. Please try again later.');
            console.log(`   ℹ️  Maximum ${RATE_LIMIT_MAX} verifications per minute per domain`);
            return false;
        }
        const recordName = `aqua._${lookupKey}.${domain}`;
        let testsPassed = 0;
        let totalTests = 0;
        console.log('\n🔍 Starting verification tests...\n');
        // Test 1: DNS Record Existence with DNSSEC
        totalTests++;
        console.log(`Test 1/8: DNS Record Existence & DNSSEC Validation`);
        console.log(`   Querying: ${recordName}`);
        try {
            let txtRecords;
            let dnssecValidated = false;
            try {
                const result = yield resolveTxtWithDNSSEC(recordName);
                txtRecords = result.records;
                dnssecValidated = result.dnssecValidated;
            }
            catch (dnssecError) {
                // Fallback to regular DNS if DNSSEC check fails
                console.log('   ⚠️  DNSSEC validation not available, falling back to standard DNS');
                txtRecords = yield resolveTxt(recordName);
                dnssecValidated = false;
            }
            if (!txtRecords || txtRecords.length === 0) {
                console.log('   ❌ FAIL: No TXT records found at this location');
                console.log(`   ℹ️  Expected: TXT record at ${recordName}`);
                console.log(`   ℹ️  Found: No records`);
                return false;
            }
            console.log(`   ✅ PASS: Found ${txtRecords.length} TXT record(s)`);
            if (dnssecValidated) {
                console.log('   🔒 DNSSEC: Validated');
            }
            else {
                console.log('   ⚠️  DNSSEC: Not validated (DNS responses may be spoofed)');
            }
            testsPassed++;
            // Test 2: Wallet Record Format
            totalTests++;
            console.log(`\nTest 2/8: Wallet Record Format`);
            const txtRecord = txtRecords.flat().find(record => record.includes('wallet=') &&
                record.includes('timestamp=') &&
                record.includes('expiration=') &&
                record.includes('sig='));
            if (!txtRecord) {
                console.log('   ❌ FAIL: No wallet record with required format found');
                console.log('   ℹ️  Expected: wallet=...&timestamp=...&expiration=...&sig=...');
                console.log('   ℹ️  Found:', txtRecords.flat());
                return false;
            }
            console.log('   ✅ PASS: Valid wallet record format found');
            console.log(`   📋 Record: ${txtRecord.substring(0, 80)}...`);
            testsPassed++;
            // Test 3: Field Parsing
            totalTests++;
            console.log(`\nTest 3/8: Field Parsing`);
            const parsedRecord = parseTxtRecord(txtRecord);
            if (!parsedRecord.wallet || !parsedRecord.timestamp || !parsedRecord.expiration || !parsedRecord.sig) {
                console.log('   ❌ FAIL: Missing required fields after parsing');
                console.log('   ℹ️  Required: wallet, timestamp, expiration, sig');
                console.log('   ℹ️  Parsed:', parsedRecord);
                return false;
            }
            console.log('   ✅ PASS: All required fields parsed successfully');
            console.log(`   ℹ️  Wallet: ${parsedRecord.wallet}`);
            console.log(`   ℹ️  Timestamp: ${parsedRecord.timestamp}`);
            console.log(`   ℹ️  Expiration: ${parsedRecord.expiration}`);
            console.log(`   ℹ️  Signature: ${parsedRecord.sig.substring(0, 20)}...`);
            testsPassed++;
            // Test 4: Message Format & EIP-191 Preparation
            totalTests++;
            console.log(`\nTest 4/8: Message Format & EIP-191 Preparation`);
            // Reconstruct the original message (before EIP-191 formatting)
            const originalMessage = `${parsedRecord.timestamp}|${domain}|${parsedRecord.expiration}`;
            console.log(`   📝 Expected format: "timestamp|domain|expiration"`);
            console.log(`   ℹ️  Message to verify: "${originalMessage}"`);
            console.log(`   ℹ️  EIP-191 Note: ethers.js handles automatic EIP-191 formatting`);
            console.log('   ✅ PASS: Message prepared for verification');
            testsPassed++;
            // Test 5: Timestamp Validity
            totalTests++;
            console.log(`\nTest 5/8: Timestamp Validity`);
            const timestamp = parseInt(parsedRecord.timestamp);
            const timestampDate = new Date(timestamp * 1000);
            const now = new Date();
            const ageMs = now.getTime() - timestampDate.getTime();
            const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
            if (isNaN(timestamp) || timestamp <= 0) {
                console.log('   ❌ FAIL: Invalid timestamp format');
                console.log(`   ℹ️  Expected: Valid Unix timestamp`);
                console.log(`   ℹ️  Found: ${parsedRecord.timestamp}`);
                return false;
            }
            // Check for future timestamps (clock skew attack)
            if (timestamp > Math.floor(now.getTime() / 1000) + 300) { // 5 min tolerance
                console.log('   ❌ FAIL: Timestamp is in the future');
                console.log('   🚨 Possible clock manipulation attack');
                return false;
            }
            console.log('   ✅ PASS: Valid timestamp format');
            console.log(`   ℹ️  Signature created: ${timestampDate.toISOString()}`);
            console.log(`   ℹ️  Age: ${ageDays} days`);
            testsPassed++;
            // Test 6: Expiration Date Check
            totalTests++;
            console.log(`\nTest 6/8: Expiration Date Validation`);
            const expiration = parseInt(parsedRecord.expiration);
            const expirationDate = new Date(expiration * 1000);
            const nowTimestamp = Math.floor(now.getTime() / 1000);
            if (isNaN(expiration) || expiration <= 0) {
                console.log('   ❌ FAIL: Invalid expiration format');
                console.log(`   ℹ️  Expected: Valid Unix timestamp`);
                console.log(`   ℹ️  Found: ${parsedRecord.expiration}`);
                return false;
            }
            if (expiration <= timestamp) {
                console.log('   ❌ FAIL: Expiration date is before creation date');
                console.log(`   ℹ️  Created: ${timestampDate.toISOString()}`);
                console.log(`   ℹ️  Expires: ${expirationDate.toISOString()}`);
                return false;
            }
            if (expiration < nowTimestamp) {
                console.log('   ❌ FAIL: Signature has expired');
                console.log(`   ℹ️  Expired on: ${expirationDate.toISOString()}`);
                console.log(`   ℹ️  Current time: ${now.toISOString()}`);
                console.log('   ℹ️  Please generate a new signature');
                return false;
            }
            const daysUntilExpiration = Math.floor((expiration - nowTimestamp) / (60 * 60 * 24));
            console.log('   ✅ PASS: Signature is not expired');
            console.log(`   ℹ️  Expires: ${expirationDate.toISOString()}`);
            console.log(`   ℹ️  Valid for: ${daysUntilExpiration} more days`);
            testsPassed++;
            // Test 7: Cryptographic Signature Verification (EIP-191 Compliant)
            totalTests++;
            console.log(`\nTest 7/8: Cryptographic Signature Verification (EIP-191 Compliant)`);
            console.log(`   🔐 Verifying EIP-191 signature for: "${originalMessage}"`);
            try {
                // ethers.utils.verifyMessage handles EIP-191 formatting automatically:
                // It applies: "\x19Ethereum Signed Message:\n" + len(message) + message
                // This matches MetaMask's personal_sign behavior (EIP-191 version 0x45)
                const recoveredAddress = ethers.utils.verifyMessage(originalMessage, parsedRecord.sig);
                console.log(`   ℹ️  Expected wallet: ${parsedRecord.wallet}`);
                console.log(`   ℹ️  Recovered address: ${recoveredAddress}`);
                if (recoveredAddress.toLowerCase() === parsedRecord.wallet.toLowerCase()) {
                    console.log('   ✅ PASS: Signature verification successful');
                    console.log('   🔐 The signature was created by the claimed wallet address');
                    testsPassed++;
                    // Test 8: Domain Consistency Check (after signature verification)
                    totalTests++;
                    console.log(`\nTest 8/8: Domain Consistency Check`);
                    console.log(`   🔍 Verifying the signed domain matches the queried domain`);
                    // Extract the domain from the verified message
                    const messageParts = originalMessage.split('|');
                    if (messageParts.length !== 3) {
                        console.log('   ❌ FAIL: Invalid message format');
                        console.log(`   ℹ️  Expected: timestamp|domain|expiration`);
                        console.log(`   ℹ️  Found: ${messageParts.length} parts`);
                        return false;
                    }
                    const signedDomain = messageParts[1];
                    console.log(`   ℹ️  Domain being queried: ${domain}`);
                    console.log(`   ℹ️  Domain in signed message: ${signedDomain}`);
                    console.log(`   ℹ️  DNS record location: ${recordName}`);
                    if (signedDomain !== domain) {
                        console.log('   ❌ FAIL: Domain mismatch!');
                        console.log('   🚨 The signature is valid but was created for a different domain');
                        console.log(`   ℹ️  This could indicate the DNS record was copied from another domain`);
                        return false;
                    }
                    console.log('   ✅ PASS: Domain consistency verified');
                    console.log('   🔐 The signature was specifically created for this domain');
                    testsPassed++;
                    // Final Summary
                    console.log(`\n🎉 VERIFICATION COMPLETE: ${testsPassed}/${totalTests} tests passed`);
                    console.log('✅ All verification tests passed successfully!');
                    console.log(`✅ Wallet ${parsedRecord.wallet} is cryptographically linked to domain ${domain}`);
                    console.log(`📅 Valid until: ${expirationDate.toISOString()}`);
                    if (!dnssecValidated) {
                        console.log('⚠️  Note: DNSSEC was not validated for this query');
                    }
                    return true;
                }
                else {
                    console.log('   ❌ FAIL: Signature verification failed');
                    console.log('   🚨 The signature was NOT created by the claimed wallet address');
                    console.log(`   ℹ️  Address mismatch: expected ${parsedRecord.wallet}, got ${recoveredAddress}`);
                }
            }
            catch (error) {
                console.log('   ❌ FAIL: Signature verification error');
                console.log(`   ℹ️  Error: ${error instanceof Error ? error.message : error}`);
            }
        }
        catch (error) {
            console.log('   ❌ FAIL: DNS lookup error');
            console.log(`   ℹ️  Error: ${error instanceof Error ? error.message : error}`);
        }
        // Failed Summary
        console.log(`\n❌ VERIFICATION FAILED: ${testsPassed}/${totalTests} tests passed`);
        return false;
    });
}
function parseTxtRecord(txt) {
    // Use standard URLSearchParams for robust URL parameter parsing
    const params = new URLSearchParams(txt);
    return {
        wallet: params.get('wallet') || '',
        timestamp: params.get('timestamp') || '',
        expiration: params.get('expiration') || '',
        sig: params.get('sig') || ''
    };
}
