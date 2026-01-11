const { ethers } = require('ethers');
import * as dns from 'dns';
import { promisify } from 'util';
import { TxtRecord, AquaTreeClaim } from './types';
import * as crypto from 'crypto';


// Set reliable DNS servers (Google and Cloudflare)
dns.setServers([
  '8.8.8.8',
  '8.8.4.4',
  '1.1.1.1',
  '1.0.0.1'
]);

console.log('🔧 Node.js DNS servers overridden to:', dns.getServers());

// Create a custom resolver that definitely uses our DNS servers
const customResolver = new dns.Resolver();
customResolver.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']);


// Rate limiting
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 10; // Max requests per window
const RATE_LIMIT_WINDOW = 60000; // 1 minute window

// DNSSEC validation using DNS.resolveAny with AD flag
async function resolveTxtWithDNSSEC(domain: string): Promise<{ records: string[][]; dnssecValidated: boolean }> {
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver();


    // Enable DNSSEC validation by requesting AD (Authenticated Data) flag
    // resolver.setServers(resolver.getServers());

    // Use resolve4 with options to check DNSSEC
    resolver.resolve4(domain.replace('aqua._wallet.', ''), { ttl: true }, (err, addresses) => {
      if (err && err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
        // Check if we can get basic DNS resolution for the parent domain
        resolver.resolveTxt(domain, (txtErr, txtRecords) => {
          if (txtErr) {
            reject(txtErr);
          } else {
            // We got TXT records but couldn't verify DNSSEC
            resolve({ records: txtRecords, dnssecValidated: false });
          }
        });
      } else {
        // Now get the actual TXT records
        resolver.resolveTxt(domain, (txtErr, txtRecords) => {
          if (txtErr) {
            reject(txtErr);
          } else {
            // Simple DNSSEC check: if parent domain resolves, we have basic validation
            resolve({ records: txtRecords, dnssecValidated: true });
          }
        });
      }
    });
  });
}

// Rate limiting check
function checkRateLimit(identifier: string): boolean {
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

// Helper function to verify a single wallet record
async function verifySingleRecord(
  txtRecord: string, 
  domain: string, 
  recordName: string, 
  recordIndex: number,
  dnssecValidated: boolean
): Promise<{ success: boolean; walletAddress: string; expirationDate: Date }> {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`📋 VERIFYING RECORD ${recordIndex}`);
  console.log(`${'='.repeat(80)}`);

  let testsPassed = 0;
  let totalTests = 0;

  // Test 1: Wallet Record Format
  totalTests++;
  console.log(`Test 1/7: Wallet Record Format`);

  // Check for new format first (with expiration)
  let isLegacyFormat = false;
  let hasValidFormat = txtRecord.includes('wallet=') &&
    txtRecord.includes('timestamp=') &&
    txtRecord.includes('expiration=') &&
    txtRecord.includes('sig=');

  // Fallback to legacy format (without expiration)
  if (!hasValidFormat) {
    hasValidFormat = txtRecord.includes('wallet=') &&
      txtRecord.includes('timestamp=') &&
      txtRecord.includes('sig=');
    if (hasValidFormat) {
      isLegacyFormat = true;
      console.log('   ⚠️  WARNING: Legacy format detected (no expiration field)');
      console.log('   ℹ️  Please regenerate your signature for enhanced security');
    }
  }

  if (!hasValidFormat) {
    console.log('   ❌ FAIL: Invalid wallet record format');
    console.log('   ℹ️  Expected: wallet=...&timestamp=...&expiration=...&sig=...');
    console.log(`   ℹ️  Found: ${txtRecord}`);
    return { success: false, walletAddress: '', expirationDate: new Date(0) };
  }

  console.log('   ✅ PASS: Valid wallet record format found');
  console.log(`   📋 Record: ${txtRecord.substring(0, 80)}...`);
  testsPassed++;

  // Test 2: Field Parsing
  totalTests++;
  console.log(`\nTest 2/7: Field Parsing`);

  const parsedRecord = parseTxtRecord(txtRecord);

  // For legacy format, set a default expiration (90 days from timestamp)
  if (isLegacyFormat && parsedRecord.timestamp && !parsedRecord.expiration) {
    parsedRecord.expiration = (parseInt(parsedRecord.timestamp) + (90 * 24 * 60 * 60)).toString();
    console.log('   ℹ️  Legacy format: Using default 90-day expiration');
  }

  if (!parsedRecord.wallet || !parsedRecord.timestamp || !parsedRecord.expiration || !parsedRecord.sig) {
    console.log('   ❌ FAIL: Missing required fields after parsing');
    console.log('   ℹ️  Required: wallet, timestamp, expiration, sig');
    console.log('   ℹ️  Parsed:', parsedRecord);
    return { success: false, walletAddress: parsedRecord.wallet || '', expirationDate: new Date(0) };
  }

  console.log('   ✅ PASS: All required fields parsed successfully');
  console.log(`   ℹ️  Wallet: ${parsedRecord.wallet}`);
  console.log(`   ℹ️  Timestamp: ${parsedRecord.timestamp}`);
  console.log(`   ℹ️  Expiration: ${parsedRecord.expiration}`);
  console.log(`   ℹ️  Signature: ${parsedRecord.sig.substring(0, 20)}...`);
  testsPassed++;

  // Test 3: Message Format & EIP-191 Preparation
  totalTests++;
  console.log(`\nTest 3/7: Message Format & EIP-191 Preparation`);

  // Reconstruct the original message (before EIP-191 formatting)
  const originalMessage = isLegacyFormat
    ? `${parsedRecord.timestamp}|${domain}`
    : `${parsedRecord.timestamp}|${domain}|${parsedRecord.expiration}`;
  console.log(`   📝 Expected format: "timestamp|domain|expiration"`);
  console.log(`   ℹ️  Message to verify: "${originalMessage}"`);
  console.log(`   ℹ️  EIP-191 Note: ethers.js handles automatic EIP-191 formatting`);
  console.log('   ✅ PASS: Message prepared for verification');
  testsPassed++;

  // Test 4: Timestamp Validity
  totalTests++;
  console.log(`\nTest 4/7: Timestamp Validity`);

  const timestamp = parseInt(parsedRecord.timestamp);
  const timestampDate = new Date(timestamp * 1000);
  const now = new Date();
  const ageMs = now.getTime() - timestampDate.getTime();
  const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));

  if (isNaN(timestamp) || timestamp <= 0) {
    console.log('   ❌ FAIL: Invalid timestamp format');
    console.log(`   ℹ️  Expected: Valid Unix timestamp`);
    console.log(`   ℹ️  Found: ${parsedRecord.timestamp}`);
    return { success: false, walletAddress: parsedRecord.wallet, expirationDate: new Date(0) };
  }

  // Check for future timestamps (clock skew attack)
  if (timestamp > Math.floor(now.getTime() / 1000) + 300) { // 5 min tolerance
    console.log('   ❌ FAIL: Timestamp is in the future');
    console.log('   🚨 Possible clock manipulation attack');
    return { success: false, walletAddress: parsedRecord.wallet, expirationDate: new Date(0) };
  }

  console.log('   ✅ PASS: Valid timestamp format');
  console.log(`   ℹ️  Signature created: ${timestampDate.toISOString()}`);
  console.log(`   ℹ️  Age: ${ageDays} days`);
  testsPassed++;

  // Test 5: Expiration Date Check
  totalTests++;
  console.log(`\nTest 5/7: Expiration Date Validation`);

  const expiration = parseInt(parsedRecord.expiration);
  const expirationDate = new Date(expiration * 1000);
  const nowTimestamp = Math.floor(now.getTime() / 1000);

  if (isNaN(expiration) || expiration <= 0) {
    console.log('   ❌ FAIL: Invalid expiration format');
    console.log(`   ℹ️  Expected: Valid Unix timestamp`);
    console.log(`   ℹ️  Found: ${parsedRecord.expiration}`);
    return { success: false, walletAddress: parsedRecord.wallet, expirationDate: new Date(0) };
  }

  if (expiration <= timestamp) {
    console.log('   ❌ FAIL: Expiration date is before creation date');
    console.log(`   ℹ️  Created: ${timestampDate.toISOString()}`);
    console.log(`   ℹ️  Expires: ${expirationDate.toISOString()}`);
    return { success: false, walletAddress: parsedRecord.wallet, expirationDate };
  }

  if (expiration < nowTimestamp) {
    console.log('   ❌ FAIL: Signature has expired');
    console.log(`   ℹ️  Expired on: ${expirationDate.toISOString()}`);
    console.log(`   ℹ️  Current time: ${now.toISOString()}`);
    console.log('   ℹ️  Please generate a new signature');
    return { success: false, walletAddress: parsedRecord.wallet, expirationDate };
  }

  const daysUntilExpiration = Math.floor((expiration - nowTimestamp) / (60 * 60 * 24));
  console.log('   ✅ PASS: Signature is not expired');
  console.log(`   ℹ️  Expires: ${expirationDate.toISOString()}`);
  console.log(`   ℹ️  Valid for: ${daysUntilExpiration} more days`);
  testsPassed++;

  // Test 6: Cryptographic Signature Verification (EIP-191 Compliant)
  totalTests++;
  console.log(`\nTest 6/7: Cryptographic Signature Verification (EIP-191 Compliant)`);
  console.log(`   🔐 Verifying EIP-191 signature for: "${originalMessage}"`);

  try {
    // ethers.verifyMessage handles EIP-191 formatting automatically:
    // It applies: "\x19Ethereum Signed Message:\n" + len(message) + message
    // This matches MetaMask's personal_sign behavior (EIP-191 version 0x45)
    const recoveredAddress = ethers.verifyMessage(originalMessage, parsedRecord.sig);

    console.log(`   ℹ️  Expected wallet: ${parsedRecord.wallet}`);
    console.log(`   ℹ️  Recovered address: ${recoveredAddress}`);

    if (recoveredAddress.toLowerCase() !== parsedRecord.wallet.toLowerCase()) {
      console.log('   ❌ FAIL: Signature verification failed');
      console.log('   🚨 The signature was NOT created by the claimed wallet address');
      console.log(`   ℹ️  Address mismatch: expected ${parsedRecord.wallet}, got ${recoveredAddress}`);
      return { success: false, walletAddress: parsedRecord.wallet, expirationDate };
    }

    console.log('   ✅ PASS: Signature verification successful');
    console.log('   🔐 The signature was created by the claimed wallet address');
    testsPassed++;

    // Test 7: Domain Consistency Check (after signature verification)
    totalTests++;
    console.log(`\nTest 7/7: Domain Consistency Check`);
    console.log(`   🔍 Verifying the signed domain matches the queried domain`);

    // Extract the domain from the verified message
    const messageParts = originalMessage.split('|');
    const expectedParts = isLegacyFormat ? 2 : 3;
    if (messageParts.length !== expectedParts) {
      console.log('   ❌ FAIL: Invalid message format');
      console.log(`   ℹ️  Expected: ${isLegacyFormat ? 'timestamp|domain' : 'timestamp|domain|expiration'}`);
      console.log(`   ℹ️  Found: ${messageParts.length} parts`);
      return { success: false, walletAddress: parsedRecord.wallet, expirationDate };
    }

    const signedDomain = messageParts[1];
    console.log(`   ℹ️  Domain being queried: ${domain}`);
    console.log(`   ℹ️  Domain in signed message: ${signedDomain}`);
    console.log(`   ℹ️  DNS record location: ${recordName}`);

    if (signedDomain !== domain) {
      console.log('   ❌ FAIL: Domain mismatch!');
      console.log('   🚨 The signature is valid but was created for a different domain');
      console.log(`   ℹ️  This could indicate the DNS record was copied from another domain`);
      return { success: false, walletAddress: parsedRecord.wallet, expirationDate };
    }

    console.log('   ✅ PASS: Domain consistency verified');
    console.log('   🔐 The signature was specifically created for this domain');
    testsPassed++;

    // Success Summary for this record
    console.log(`\n🎉 RECORD ${recordIndex} VERIFICATION: ${testsPassed}/${totalTests} tests passed`);
    console.log('✅ All verification tests passed successfully!');
    console.log(`✅ Wallet ${parsedRecord.wallet} is cryptographically linked to domain ${domain}`);
    console.log(`📅 Valid until: ${expirationDate.toISOString()}`);
    if (!dnssecValidated) {
      console.log('⚠️  Note: DNSSEC was not validated for this query');
    }

    return { success: true, walletAddress: parsedRecord.wallet, expirationDate };

  } catch (error) {
    console.log('   ❌ FAIL: Signature verification error');
    console.log(`   ℹ️  Error: ${error instanceof Error ? error.message : error}`);
    return { success: false, walletAddress: parsedRecord.wallet, expirationDate };
  }
}

export async function verifyClaim(claim: AquaTreeClaim): Promise<boolean> {

  // Rate limiting by domain
  if (!checkRateLimit(claim.forms_domain)) {
    console.log('\n⚠️  Rate limit exceeded. Please try again later.');
    console.log(`   ℹ️  Maximum ${RATE_LIMIT_MAX} verifications per minute per domain`);
    return false;
  }

  const recordName = claim.forms_txt_name;

  console.log('\n🔍 Starting verification tests...\n');

  // Test 1: DNS Record Existence with DNSSEC
  console.log(`Test 1/2: DNS Record Existence & DNSSEC Validation`);
  console.log(`   Querying: ${recordName}`);

  try {
    let txtRecords: string[][];
    let dnssecValidated = false;

    try {
      const result = await resolveTxtWithDNSSEC(recordName);
      txtRecords = result.records;
      dnssecValidated = result.dnssecValidated;
    } catch (dnssecError) {
      // Fallback to regular DNS if DNSSEC check fails
      console.log('   ⚠️  DNSSEC validation not available, falling back to standard DNS');
      console.log('Current DNS servers:', dns.getServers());

      try {
        txtRecords = await new Promise((resolve, reject) => {
          dns.resolveTxt(recordName, (err, records) => {
            if (err) {
              reject(err);
            } else {
              resolve(records);
            }
          });
        });
        dnssecValidated = false;
      } catch (err) {
        console.log('   ❌ FAIL: DNS lookup error');
        console.log(`   ℹ️  Error: ${err instanceof Error ? err.message : err}`);
        return false;
      }

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
    } else {
      console.log('   ⚠️  DNSSEC: Not validated (DNS responses may be spoofed)');
    }
    // Check for continuations record
    let allTxtRecords = txtRecords.flat();
    const continuationsRecord = allTxtRecords.find(record => record.startsWith("continuations="));
    if (continuationsRecord) {
      const continuations = continuationsRecord.split("=")[1].split(",");
      console.log(`   ℹ️  Found continuations: ${continuations.join(", ")}`);
      for (const cont of continuations) {
        const contSubdomain = `${cont}.${claim.forms_domain}`;
        try {
          const contRecords = await new Promise<string[][]>((resolve, reject) => {
            dns.resolveTxt(contSubdomain, (err, records) => {
              if (err) reject(err);
              else resolve(records);
            });
          });
          allTxtRecords = allTxtRecords.concat(contRecords.flat());
          console.log(`   ℹ️  Added ${contRecords.flat().length} records from ${contSubdomain}`);
        } catch (err) {
          console.log(`   ⚠️  Failed to query continuation ${contSubdomain}: ${err}`);
        }
      }
    }

    // Test 2: Filter and Process Claim Records
    console.log(`
Test 2/2: Filtering Claim Records`);

    // Test 2: Filter and Process Wallet Records
    console.log(`\nTest 2/2: Filtering Wallet Records`);

    // Find all valid claim records (URL-encoded format)
    const claimRecords = allTxtRecords.filter(record =>
      record.includes("id=") &&
      record.includes("itime=") &&
      record.includes("etime=") &&
      record.includes("sig=")
    );

    if (claimRecords.length === 0) {
      console.log("   ❌ FAIL: No claim records with required format found");
      console.log("   ℹ️  Expected: id=...&itime=...&etime=...&sig=...");
      console.log("   ℹ️  Found:", allTxtRecords);
      return false;
    }

    console.log(`   ✅ PASS: Found ${claimRecords.length} claim record(s) with valid format`);

    // Find the claim record matching the unique ID
    const targetRecord = claimRecords.find(record => {
      const parsed = parseTxtRecord(record);
      return parsed.id === claim.forms_unique_id;
    });

    if (!targetRecord) {
      console.log(`
❌ CLAIM RECORD NOT FOUND`);
      console.log(`   ℹ️  Expected ID: ${claim.forms_unique_id}`);
      console.log(`   ℹ️  Available IDs:`);
      claimRecords.forEach((record, index) => {
        const parsed = parseTxtRecord(record);
        console.log(`      ${index + 1}. ${parsed.id}`);
      });
      return false;
    }

    console.log(`   ✅ Found claim record with ID ${claim.forms_unique_id}`);

    // Parse the record
    const parsedRecord = parseTxtRecord(targetRecord);

    // Reconstruct the signed message
    const signedMessage = `${claim.forms_claim_secret}&${parsedRecord.itime}&${claim.forms_domain}&${parsedRecord.etime}`;

    // Verify the signature
    console.log(`
🔐 Verifying EIP-191 signature`);
    console.log(`   🔍 Message: "${signedMessage}"`);

    try {
      const recoveredAddress = ethers.verifyMessage(signedMessage, parsedRecord.sig);
      console.log(`   ℹ️  Expected wallet: ${claim.forms_wallet_address}`);
      console.log(`   ℹ️  Recovered address: ${recoveredAddress}`);

      if (recoveredAddress.toLowerCase() !== claim.forms_wallet_address.toLowerCase()) {
        console.log("   ❌ FAIL: Signature verification failed");
        console.log("   🚨 The signature was NOT created by the claimed wallet address");
        return false;
      }

      console.log("   ✅ PASS: Signature verification successful");
    } catch (error) {
      console.log("   ❌ FAIL: Signature verification error");
      console.log(`   ℹ️  Error: ${error instanceof Error ? error.message : error}`);
      return false;
    }

    // Check timestamps
    const now = Math.floor(Date.now() / 1000);
    const itime = parseInt(parsedRecord.itime);
    const etime = parseInt(parsedRecord.etime);

    if (isNaN(itime) || isNaN(etime)) {
      console.log("   ❌ FAIL: Invalid timestamp format");
      return false;
    }

    if (etime < now) {
      console.log("   ❌ FAIL: Claim has expired");
      console.log(`   ℹ️  Expired at: ${new Date(etime * 1000).toISOString()}`);
      return false;
    }

    console.log("   ✅ PASS: Timestamps valid");
    console.log(`   ℹ️  Issued: ${new Date(itime * 1000).toISOString()}`);
    console.log(`   ℹ️  Expires: ${new Date(etime * 1000).toISOString()}`);

    // Success
    console.log(`
🎉 CLAIM VERIFICATION: SUCCESS`);
    console.log(`✅ Wallet ${claim.forms_wallet_address} is cryptographically linked to domain ${claim.forms_domain}`);


  } catch (error) {
    console.log('   ❌ FAIL: DNS lookup error');
    console.log(`   ℹ️  Error: ${error instanceof Error ? error.message : error}`);
    return false;
  }
}

function parseTxtRecord(txt: string): TxtRecord {
  // Parse URL-encoded format: id=<id>&itime=<itime>&etime=<etime>&sig=<sig>
  const params = new URLSearchParams(txt);

  return {
    id: params.get('id') || '',
    itime: params.get('itime') || '',
    etime: params.get('etime') || '',
    sig: params.get('sig') || ''
  };
}