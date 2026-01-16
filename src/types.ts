/**
 * TXT record format per specification
 * Private format: id=<unique_id>&itime=<issuing_timestamp>&etime=<expiration_timestamp>&sig=<signature>
 * Public format: id=<unique_id>&wallet=<address>&itime=<issuing_timestamp>&etime=<expiration_timestamp>&sig=<signature>
 */
export interface TxtRecord {
  id: string;       // Unique claim identifier (8 hex chars)
  wallet?: string;  // Wallet address (only in public mode)
  itime: string;    // Issuing timestamp (Unix)
  etime: string;    // Expiration timestamp (Unix)
  sig: string;      // EIP-191 signature
}

/**
 * AquaTree claim structure per specification
 * Contains all fields needed for claim generation and verification
 */
export interface AquaTreeClaim {
  forms_unique_id: string;       // Random 8 hex chars
  forms_claim_secret: string;    // Random 16 hex chars (private mode) or empty string (public mode)
  forms_txt_name: string;        // DNS subdomain (e.g., "_aw.example.com")
  forms_txt_record: string;      // The TXT record content
  forms_wallet_address: string;  // Ethereum address
  forms_domain: string;          // Domain name (lowercase FQDN)
  forms_type: string;            // Always "dns_claim"
  signature_type: string;        // Always "ethereum:eip-191"
  itime: string;                 // Issuing timestamp (Unix)
  etime: string;                 // Expiration timestamp (Unix)
  sig: string;                   // EIP-191 signature
  public_association?: boolean;  // If true, wallet address is in DNS record (no secret)
}
