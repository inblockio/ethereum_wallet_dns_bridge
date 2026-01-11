const { ethers } = require('ethers');
import { randomBytes } from 'crypto';
import { Proof, AquaTreeClaim } from './types';

// Default expiration period in days
const DEFAULT_EXPIRATION_DAYS = 90;

export async function generateProof(domain: string, privateKey: string, expirationDays: number = DEFAULT_EXPIRATION_DAYS): Promise<Proof> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const expiration = Math.floor(Date.now() / 1000 + (expirationDays * 24 * 60 * 60)).toString();
  
  // Message format: unix_timestamp|domain_name|expiration_timestamp
  const message = `${timestamp}|${domain}|${expiration}`;
  
  // Sign with EIP-191 compliant personal_sign format
  // ethers.js automatically applies: "\x19Ethereum Signed Message:\n" + len(message) + message
  // This matches MetaMask's personal_sign behavior (EIP-191 version 0x45)
  const wallet = new ethers.Wallet(privateKey);
  const signature = await wallet.signMessage(message);
  
  return {
    walletAddress: wallet.address,
    domainName: domain,
    timestamp,
    expiration,
    signature
  };
}

// Function for MetaMask signatures with expiration
export function generateProofFromSignature(domain: string, walletAddress: string, timestamp: string, expiration: string, signature: string): Proof {
  return {
    walletAddress,
    domainName: domain,
    timestamp,
    expiration,
    signature
  };
}

export function createMessageToSign(domain: string, timestamp: string, expiration: string): string {
  return `${timestamp}|${domain}|${expiration}`;
}

export function formatTxtRecord(proof: Proof): string {
  return `wallet=${proof.walletAddress}&timestamp=${proof.timestamp}&expiration=${proof.expiration}&sig=${proof.signature}`;
}

export async function generateClaim(domain: string, privateKey: string, txtName: string, expirationDays: number = DEFAULT_EXPIRATION_DAYS): Promise<AquaTreeClaim> {
  const uniqueId = generateUniqueId();
  const claimSecret = generateClaimSecret();
  const itime = Math.floor(Date.now() / 1000);
  const etime = itime + (expirationDays * 24 * 60 * 60);

  // Message format: claim_secret&itime&domain&etime
  const message = `${claimSecret}&${itime}&${domain}&${etime}`;

  // Sign with EIP-191
  const wallet = new ethers.Wallet(privateKey);
  const signature = await wallet.signMessage(message);

  return {
    forms_unique_id: uniqueId,
    forms_claim_secret: claimSecret,
    forms_txt_name: txtName,
    forms_wallet_address: wallet.address,
    forms_domain: domain,
    forms_type: 'dns_claim',
    signature_type: 'ethereum:eip-191'
  };
}

function generateUniqueId(): string {
  return randomBytes(4).toString('hex'); // 8 hex chars
}

function generateClaimSecret(): string {
  return randomBytes(8).toString('hex'); // 16 hex chars
}

export function formatClaimTxtRecord(uniqueId: string, itime: number, etime: number, signature: string): string {
  return `id=${uniqueId}&itime=${itime}&etime=${etime}&sig=${signature}`;
}