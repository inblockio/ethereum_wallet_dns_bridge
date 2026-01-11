export interface Proof {
  walletAddress: string;
  domainName: string;
  timestamp: string;
  expiration: string;
  signature: string;
}

export interface TxtRecord {
  id: string;
  itime: string;
  etime: string;
  sig: string;
}

export interface SignatureMethod {
  type: 'metamask' | 'mnemonic' | 'interactive';
  data?: string; // mnemonic or credential file path
}

export interface WalletConfig {
  mnemonic?: string;
  derivationPath?: string;
  credentialsFile?: string;
}

export interface SignatureRequest {
  message: string;
  address: string;
  method: SignatureMethod;
} export interface AquaTreeClaim {
  forms_unique_id: string;
  forms_claim_secret: string;
  forms_txt_name: string;
  forms_wallet_address: string;
  forms_domain: string;
  forms_type: string;
  signature_type: string;
}
