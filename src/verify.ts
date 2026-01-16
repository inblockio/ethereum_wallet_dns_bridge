import { ethers } from 'ethers';
import * as dns from 'dns';
import { TxtRecord, AquaTreeClaim } from './types';

const DNS_SERVERS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'];

/**
 * Verify a claim against DNS records
 */
export async function verifyClaim(claim: AquaTreeClaim, verbose = false): Promise<boolean> {
  const log = verbose ? console.log : () => {};

  console.log(`Verifying claim ${claim.forms_unique_id} for ${claim.forms_domain}...`);

  try {
    // 1. Resolve DNS
    const { records, dnssecValidated } = await resolveTxt(claim.forms_txt_name);

    if (!records || records.length === 0) {
      console.log(`✗ No DNS record at ${claim.forms_txt_name}`);
      return false;
    }

    console.log(`✓ DNS record found${dnssecValidated ? ' (DNSSEC: yes)' : ' (DNSSEC: no)'}`);
    log(`  Records: ${records.length}`);

    // 2. Handle continuations
    let allRecords = records;
    const contRecord = records.find(r => r.startsWith('continuations='));
    if (contRecord) {
      const continuations = contRecord.split('=')[1].split(',');
      for (const cont of continuations) {
        try {
          const { records: contRecords } = await resolveTxt(`${cont}.${claim.forms_domain}`);
          allRecords = allRecords.concat(contRecords);
        } catch {}
      }
    }

    // 3. Find matching claim record
    const claimRecords = allRecords.filter(r =>
      r.includes('id=') && r.includes('itime=') && r.includes('etime=') && r.includes('sig=')
    );

    const targetRecord = claimRecords.find(r => {
      const parsed = parseTxtRecord(r);
      return parsed.id === claim.forms_unique_id;
    });

    if (!targetRecord) {
      console.log(`✗ Claim ID ${claim.forms_unique_id} not found in DNS`);
      return false;
    }

    // 4. Parse and verify signature
    const parsed = parseTxtRecord(targetRecord);
    const isPublic = !!parsed.wallet;

    // Construct message based on mode
    let message: string;
    if (isPublic) {
      // Public mode: use wallet address from DNS record
      message = `${parsed.wallet}&${parsed.itime}&${claim.forms_domain}&${parsed.etime}`;
      log(`  Mode: public (wallet in DNS)`);
    } else {
      // Private mode: use secret from claim file
      message = `${claim.forms_claim_secret}&${parsed.itime}&${claim.forms_domain}&${parsed.etime}`;
      log(`  Mode: private (secret required)`);
    }

    log(`  Message: ${message}`);

    const recoveredAddress = ethers.verifyMessage(message, parsed.sig);

    // For public mode, also verify wallet in DNS matches recovered address
    if (isPublic && parsed.wallet!.toLowerCase() !== recoveredAddress.toLowerCase()) {
      console.log(`✗ Signature invalid (DNS wallet doesn't match signer)`);
      return false;
    }

    if (recoveredAddress.toLowerCase() !== claim.forms_wallet_address.toLowerCase()) {
      console.log(`✗ Signature invalid (recovered: ${recoveredAddress})`);
      return false;
    }

    console.log(`✓ Signature valid${isPublic ? ' (public)' : ' (private)'}`);

    // 5. Check expiration
    const now = Math.floor(Date.now() / 1000);
    const etime = parseInt(parsed.etime);

    if (isNaN(etime) || etime < now) {
      console.log(`✗ Claim expired (${new Date(etime * 1000).toISOString()})`);
      return false;
    }

    console.log(`✓ Not expired (until ${new Date(etime * 1000).toISOString().split('T')[0]})`);

    // Success
    console.log(`✓ Wallet ${claim.forms_wallet_address} linked to ${claim.forms_domain}`);

    if (!dnssecValidated) {
      console.log(`\x1b[31m⚠ ALERT: DNSSEC not validated. MITM or spoofing possible.\x1b[0m`);
      console.log(`\x1b[31m  Mitigation: Set up DNSSEC for ${claim.forms_domain}\x1b[0m`);
    }

    return true;

  } catch (error) {
    console.log(`✗ Error: ${error instanceof Error ? error.message : error}`);
    return false;
  }
}

/**
 * Resolve TXT records with optional DNSSEC validation via dig
 */
async function resolveTxt(domain: string): Promise<{ records: string[]; dnssecValidated: boolean }> {
  // Try dig for DNSSEC validation
  try {
    const result = await tryDigDNSSEC(domain);
    if (result) return result;
  } catch {}

  // Fallback to Node DNS
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver();
    resolver.setServers(DNS_SERVERS);
    resolver.resolveTxt(domain, (err, records) => {
      if (err) reject(err);
      else resolve({ records: records.flat(), dnssecValidated: false });
    });
  });
}

/**
 * Verify public claims directly from DNS without needing a claim file
 * Only works for public mode claims (wallet address in DNS record)
 */
export async function verifyFromDNS(domain: string, claimId?: string, verbose = false): Promise<{
  valid: boolean;
  wallets: string[];
  claims: Array<{ id: string; wallet: string; expires: string }>;
}> {
  const log = verbose ? console.log : () => {};
  const txtName = `_aw.${domain}`;

  console.log(`Verifying public claims for ${domain}...`);

  try {
    // 1. Resolve DNS
    const { records, dnssecValidated } = await resolveTxt(txtName);

    if (!records || records.length === 0) {
      console.log(`✗ No DNS record at ${txtName}`);
      return { valid: false, wallets: [], claims: [] };
    }

    console.log(`✓ DNS record found${dnssecValidated ? ' (DNSSEC: yes)' : ' (DNSSEC: no)'}`);

    // 2. Handle continuations
    let allRecords = records;
    const contRecord = records.find(r => r.startsWith('continuations='));
    if (contRecord) {
      const continuations = contRecord.split('=')[1].split(',');
      for (const cont of continuations) {
        try {
          const { records: contRecords } = await resolveTxt(`${cont}.${domain}`);
          allRecords = allRecords.concat(contRecords);
        } catch {}
      }
    }

    // 3. Find public claim records (those with wallet=)
    const claimRecords = allRecords.filter(r =>
      r.includes('id=') && r.includes('wallet=') && r.includes('itime=') && r.includes('etime=') && r.includes('sig=')
    );

    if (claimRecords.length === 0) {
      console.log(`✗ No public claims found (no records with wallet=)`);
      return { valid: false, wallets: [], claims: [] };
    }

    // Show what we're verifying
    if (claimId) {
      const targetExists = claimRecords.some(r => r.includes(`id=${claimId}`));
      if (!targetExists) {
        console.log(`✗ Claim ID ${claimId} not found in public claims`);
        console.log(`  Found ${claimRecords.length} public claim(s), but none match the specified ID`);
        return { valid: false, wallets: [], claims: [] };
      }
      console.log(`Verifying specific claim: ${claimId}`);
    } else {
      console.log(`Found ${claimRecords.length} public claim(s) to verify`);
    }

    // 4. Verify each public claim
    const validClaims: Array<{ id: string; wallet: string; expires: string }> = [];
    const invalidClaims: Array<{ id: string; reason: string }> = [];
    const wallets: string[] = [];
    const now = Math.floor(Date.now() / 1000);

    for (const record of claimRecords) {
      const parsed = parseTxtRecord(record);

      // Skip if looking for specific ID and this isn't it
      if (claimId && parsed.id !== claimId) continue;

      // Verify signature
      const message = `${parsed.wallet}&${parsed.itime}&${domain}&${parsed.etime}`;

      try {
        const recoveredAddress = ethers.verifyMessage(message, parsed.sig);

        if (recoveredAddress.toLowerCase() !== parsed.wallet!.toLowerCase()) {
          console.log(`  ✗ Claim ${parsed.id}: Signature invalid`);
          invalidClaims.push({ id: parsed.id, reason: 'Invalid signature' });
          continue;
        }

        // Check expiration
        const etime = parseInt(parsed.etime);
        if (isNaN(etime) || etime < now) {
          console.log(`  ✗ Claim ${parsed.id}: Expired`);
          invalidClaims.push({ id: parsed.id, reason: 'Expired' });
          continue;
        }

        console.log(`  ✓ Claim ${parsed.id}: Valid`);
        console.log(`    Wallet: ${parsed.wallet}`);
        console.log(`    Expires: ${new Date(etime * 1000).toISOString().split('T')[0]}`);

        validClaims.push({
          id: parsed.id,
          wallet: parsed.wallet!,
          expires: new Date(etime * 1000).toISOString().split('T')[0]
        });

        if (!wallets.includes(parsed.wallet!.toLowerCase())) {
          wallets.push(parsed.wallet!.toLowerCase());
        }
      } catch (error) {
        console.log(`  ✗ Claim ${parsed.id}: ${error instanceof Error ? error.message : error}`);
        invalidClaims.push({ id: parsed.id, reason: error instanceof Error ? error.message : 'Unknown error' });
      }
    }

    // Summary
    console.log(`\n--- Summary ---`);
    if (validClaims.length === 0) {
      console.log(`✗ No valid public claims found`);
      if (invalidClaims.length > 0) {
        console.log(`  ${invalidClaims.length} claim(s) failed verification`);
      }
      return { valid: false, wallets: [], claims: [] };
    }

    console.log(`✓ ${validClaims.length} valid public claim(s):`);
    for (const claim of validClaims) {
      console.log(`  ID: ${claim.id}`);
      console.log(`    Wallet: ${claim.wallet}`);
      console.log(`    Expires: ${claim.expires}`);
    }

    if (invalidClaims.length > 0) {
      console.log(`\n✗ ${invalidClaims.length} invalid claim(s):`);
      for (const claim of invalidClaims) {
        console.log(`  ID: ${claim.id} - ${claim.reason}`);
      }
    }

    if (!dnssecValidated) {
      console.log(`\x1b[31m⚠ ALERT: DNSSEC not validated. MITM or spoofing possible.\x1b[0m`);
      console.log(`\x1b[31m  Mitigation: Set up DNSSEC for ${domain}\x1b[0m`);
    }

    return { valid: true, wallets, claims: validClaims };

  } catch (error) {
    console.log(`✗ Error: ${error instanceof Error ? error.message : error}`);
    return { valid: false, wallets: [], claims: [] };
  }
}

/**
 * Try DNSSEC validation using dig command
 */
async function tryDigDNSSEC(domain: string): Promise<{ records: string[]; dnssecValidated: boolean } | null> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  try {
    const { stdout } = await execAsync(`dig +dnssec +noall +answer +comments ${domain} TXT`, { timeout: 10000 });

    const hasADFlag = stdout.includes('flags:') && stdout.includes(' ad');
    const records: string[] = [];

    for (const match of stdout.matchAll(/TXT\s+"([^"]+)"/g)) {
      records.push(match[1]);
    }

    if (records.length === 0) return null;

    return { records, dnssecValidated: hasADFlag };
  } catch {
    return null;
  }
}

function parseTxtRecord(txt: string): TxtRecord {
  const params = new URLSearchParams(txt);
  const wallet = params.get('wallet');
  return {
    id: params.get('id') || '',
    wallet: wallet || undefined,
    itime: params.get('itime') || '',
    etime: params.get('etime') || '',
    sig: params.get('sig') || ''
  };
}
