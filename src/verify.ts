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
    const message = `${claim.forms_claim_secret}&${parsed.itime}&${claim.forms_domain}&${parsed.etime}`;

    log(`  Message: ${message}`);

    const recoveredAddress = ethers.verifyMessage(message, parsed.sig);

    if (recoveredAddress.toLowerCase() !== claim.forms_wallet_address.toLowerCase()) {
      console.log(`✗ Signature invalid (recovered: ${recoveredAddress})`);
      return false;
    }

    console.log(`✓ Signature valid`);

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
  return {
    id: params.get('id') || '',
    itime: params.get('itime') || '',
    etime: params.get('etime') || '',
    sig: params.get('sig') || ''
  };
}
