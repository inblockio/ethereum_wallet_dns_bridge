import { ethers } from 'ethers';
import { randomBytes } from 'crypto';
import * as dns from 'dns';
import { AquaTreeClaim } from './types';

const DEFAULT_EXPIRATION_DAYS = 90;
const MAX_CLAIMS_PER_SUBDOMAIN = 49;
const DNS_SERVERS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'];

const resolver = new dns.Resolver();
resolver.setServers(DNS_SERVERS);

/**
 * Generate a new claim
 * @param publicAssociation - If true, wallet address is included in DNS record (no secret)
 */
export async function generateClaim(
  domain: string,
  privateKey: string,
  txtName: string,
  expirationDays = DEFAULT_EXPIRATION_DAYS,
  publicAssociation = false
): Promise<AquaTreeClaim> {
  const uniqueId = await generateUniqueId(txtName);
  const wallet = new ethers.Wallet(privateKey);

  // In public mode, use wallet address instead of secret
  const claimSecret = publicAssociation ? '' : randomBytes(8).toString('hex');
  const messagePrefix = publicAssociation ? wallet.address : claimSecret;

  const itime = Math.floor(Date.now() / 1000);
  const etime = itime + expirationDays * 86400;

  const message = `${messagePrefix}&${itime}&${domain}&${etime}`;
  const signature = await wallet.signMessage(message);

  return {
    forms_unique_id: uniqueId,
    forms_claim_secret: claimSecret,
    forms_txt_name: txtName,
    forms_txt_record: formatClaimTxtRecord(
      uniqueId, itime, etime, signature,
      publicAssociation ? wallet.address : undefined
    ),
    forms_wallet_address: wallet.address,
    forms_domain: domain,
    forms_type: 'dns_claim',
    signature_type: 'ethereum:eip-191',
    itime: itime.toString(),
    etime: etime.toString(),
    sig: signature,
    public_association: publicAssociation
  };
}

/**
 * Generate a claim with automatic subdomain overflow handling
 */
export async function generateClaimWithOverflow(
  domain: string,
  privateKey: string,
  expirationDays = DEFAULT_EXPIRATION_DAYS,
  publicAssociation = false
): Promise<{ claim: AquaTreeClaim; continuationsUpdate: string | null; isNewSubdomain: boolean }> {
  const { subdomain, isNewSubdomain, continuationsUpdate } = await findAvailableSubdomain(domain);
  const claim = await generateClaim(domain, privateKey, subdomain, expirationDays, publicAssociation);
  return { claim, continuationsUpdate, isNewSubdomain };
}

/**
 * Find available subdomain, handling overflow to _aw2, _aw3, etc.
 */
export async function findAvailableSubdomain(domain: string): Promise<{
  subdomain: string;
  isNewSubdomain: boolean;
  continuationsUpdate: string | null;
}> {
  let subdomain = `_aw.${domain}`;
  let count = await countClaims(subdomain);

  if (count < MAX_CLAIMS_PER_SUBDOMAIN) {
    return { subdomain, isNewSubdomain: count === 0, continuationsUpdate: null };
  }

  // Check existing continuations
  const continuations = await getContinuations(subdomain);

  for (const cont of continuations) {
    subdomain = `${cont}.${domain}`;
    count = await countClaims(subdomain);
    if (count < MAX_CLAIMS_PER_SUBDOMAIN) {
      return { subdomain, isNewSubdomain: false, continuationsUpdate: null };
    }
  }

  // Create new overflow subdomain
  const nextIndex = continuations.length + 2;
  const newSubdomain = `_aw${nextIndex}.${domain}`;
  const newContinuation = `_aw${nextIndex}`;
  const updatedContinuations = continuations.length > 0
    ? `continuations=${[...continuations, newContinuation].join(',')}`
    : `continuations=${newContinuation}`;

  return { subdomain: newSubdomain, isNewSubdomain: true, continuationsUpdate: updatedContinuations };
}

export function formatClaimTxtRecord(
  uniqueId: string,
  itime: number,
  etime: number,
  signature: string,
  walletAddress?: string
): string {
  if (walletAddress) {
    // Public mode: include wallet address in record
    return `id=${uniqueId}&wallet=${walletAddress}&itime=${itime}&etime=${etime}&sig=${signature}`;
  }
  // Private mode: no wallet in record
  return `id=${uniqueId}&itime=${itime}&etime=${etime}&sig=${signature}`;
}

// --- Private helpers ---

async function generateUniqueId(subdomain: string, maxRetries = 10): Promise<string> {
  const existingIds = await getExistingIds(subdomain);

  for (let i = 0; i < maxRetries; i++) {
    const id = randomBytes(4).toString('hex');
    if (!existingIds.includes(id.toLowerCase())) {
      return id;
    }
  }

  throw new Error('Failed to generate unique ID after retries');
}

async function getExistingIds(subdomain: string): Promise<string[]> {
  return new Promise(resolve => {
    resolver.resolveTxt(subdomain, (err, records) => {
      if (err) return resolve([]);
      const ids: string[] = [];
      for (const record of records.flat()) {
        const match = record.match(/id=([a-f0-9]+)/i);
        if (match) ids.push(match[1].toLowerCase());
      }
      resolve(ids);
    });
  });
}

async function countClaims(subdomain: string): Promise<number> {
  return new Promise(resolve => {
    resolver.resolveTxt(subdomain, (err, records) => {
      if (err) return resolve(0);
      const count = records.flat().filter(r =>
        r.includes('id=') && r.includes('itime=') && r.includes('etime=') && r.includes('sig=')
      ).length;
      resolve(count);
    });
  });
}

async function getContinuations(subdomain: string): Promise<string[]> {
  return new Promise(resolve => {
    resolver.resolveTxt(subdomain, (err, records) => {
      if (err) return resolve([]);
      const cont = records.flat().find(r => r.startsWith('continuations='));
      if (cont) {
        resolve(cont.split('=')[1].split(',').map(c => c.trim()));
      } else {
        resolve([]);
      }
    });
  });
}
