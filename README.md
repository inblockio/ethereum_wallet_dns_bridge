# Wallet-to-Domain DNS Bridge

A cryptographic tool for establishing verifiable associations between Ethereum wallets and domain names using DNS TXT records. Designed for secure, decentralized identity verification without exposing wallet addresses publicly.

## Overview

This system enables domain owners to cryptographically prove ownership of an Ethereum wallet by publishing a signed claim to DNS. The claim contains only a unique identifier, timestamps, and an EIP-191 signature—the wallet address remains private until selectively disclosed via the claim file.

**Key Properties:**
- Wallet address is never exposed in DNS records
- Claims are independently verifiable by any party with the claim file
- Revocation is simple: delete the DNS TXT record
- Supports multiple claims per domain (overflow handling included)

## Prerequisites

- Node.js v18 or higher
- MetaMask browser extension (for claim generation)
- Administrative access to your domain's DNS settings

## Installation

```bash
npm install
npm run build
```

## Usage

### Step 1: Generate a Claim

Start the signing server and open the browser interface:

```bash
node dist/wallet-tool.js generate <domain>
```

Example:
```bash
node dist/wallet-tool.js generate example.com
```

This opens a browser window with the signing interface:

1. **Connect MetaMask** — Click "Connect Wallet" and approve the connection
2. **Generate Claim** — Click "Generate Claim" and sign the message in MetaMask
3. **Download Claim File** — Save the generated JSON file securely
4. **Copy DNS Record** — Copy the TXT record value for DNS configuration

### Step 2: Configure DNS

Add a TXT record to your domain's DNS:

| Field | Value |
|-------|-------|
| **Name** | `_aw` (or `_aw.example.com` depending on your DNS provider) |
| **Type** | `TXT` |
| **Value** | The generated record (e.g., `id=a1b2c3d4&itime=...&etime=...&sig=0x...`) |

**DNS Propagation:** Changes may take 1-24 hours to propagate globally.

### Step 3: Verify a Claim

Verify a claim against DNS:

```bash
node dist/wallet-tool.js verify <claim-file>
```

Example:
```bash
node dist/wallet-tool.js verify ./claims/a1b2c3d4.json
```

**Output:**
```
Verifying claim a1b2c3d4 for example.com...
✓ DNS record found (DNSSEC: yes)
✓ Signature valid
✓ Not expired (until 2026-04-16)
✓ Wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e linked to example.com
```

### Additional Commands

**Start the signing server manually:**
```bash
node dist/wallet-tool.js server
```

**View help:**
```bash
node dist/wallet-tool.js --help
```

## Claim File Structure

The generated claim file contains all data required for verification:

```json
{
  "forms_unique_id": "a1b2c3d4",
  "forms_claim_secret": "1234567890abcdef",
  "forms_txt_name": "_aw.example.com",
  "forms_txt_record": "id=a1b2c3d4&itime=1768168912&etime=1775944912&sig=0x...",
  "forms_wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "forms_domain": "example.com",
  "forms_type": "dns_claim",
  "signature_type": "ethereum:eip-191",
  "itime": "1768168912",
  "etime": "1775944912",
  "sig": "0x..."
}
```

**Fields:**
- `forms_unique_id` — 8 hex character claim identifier
- `forms_claim_secret` — 16 hex character secret (used in signature, not published)
- `forms_txt_name` — Full DNS subdomain for the TXT record
- `forms_txt_record` — The exact value to publish in DNS
- `forms_wallet_address` — The Ethereum address being claimed
- `itime` — Issuing timestamp (Unix epoch)
- `etime` — Expiration timestamp (Unix epoch)
- `sig` — EIP-191 signature

---

## Specification

### Mechanism

This system associates an Ethereum wallet with a domain via a public DNS TXT record under a subdomain (e.g., `_aw.example.com`), without exposing the wallet publicly. The TXT record contains only a unique ID, timestamps, and an EIP-191 signature. The association is proven via a selectively shared claim structure containing the wallet address, a secret (used in signing), and a pointer to the DNS record.

Verification reconstructs the signed message from the claim and DNS data, recovering the wallet address if valid.

### Components

| Component | Format | Description |
|-----------|--------|-------------|
| **Unique ID** | 8 hex chars (e.g., `a1b2c3d4`) | Random identifier; ~4.29 billion namespace |
| **Claim Secret** | 16 hex chars (e.g., `1234567890abcdef`) | High-entropy secret for brute-force resistance |
| **Signed Message** | `<secret>&<itime>&<domain>&<etime>` | Concatenated with `&` delimiters |
| **DNS TXT Record** | `id=<id>&itime=<itime>&etime=<etime>&sig=<sig>` | Published under `_aw.<domain>` |

### DNS Record Format

**Primary subdomain:** `_aw.<domain>`

**TXT Record:** `id=<unique_id>&itime=<issuing_timestamp>&etime=<expiration_timestamp>&sig=0x<signature>`

**Example:**
```
_aw.inblock.io IN TXT "id=e6e655fc&itime=1768164226&etime=1775940226&sig=0xadbd6ffd..."
```

**Record length:** Target under 175 characters (max 255).

### Overflow Handling

Each subdomain supports approximately 49 claims (limited by DNS response size). This allows multiple different wallets to be linked to a single domain, as well as multiple claims from the same wallet. When capacity is reached:

1. Create overflow subdomain: `_aw2.<domain>`, `_aw3.<domain>`, etc.
2. Add continuations record to base subdomain: `continuations=_aw2,_aw3`

The continuations record enables automated discovery during verification without sequential probing.

### Signature Method

- **Standard:** EIP-191 (Ethereum personal_sign)
- **Message:** `<secret>&<itime>&<domain>&<etime>`
- **Hash:** keccak256 with prefix `\x19Ethereum Signed Message:\n<length>`

### Verification Process

1. Extract `wallet_address`, `unique_id`, `claim_secret`, `forms_txt_name` from claim file
2. Query DNS TXT at `forms_txt_name`
3. If continuations record exists, query additional subdomains
4. Filter records for matching `id=<unique_id>`
5. Extract `itime`, `etime`, `sig` from matched record
6. Rebuild message: `claim_secret&itime&domain&etime`
7. Recover address from signature using EIP-191
8. Validate: address matches, current time < etime, record exists

### Revocation

Delete the corresponding TXT record from DNS. Verification will fail when the record is not found.

---

## Known Limitations

### DNSSEC Requirement

**DNSSEC is strongly recommended for production use.**

Without DNSSEC, DNS queries are vulnerable to:

| Attack | Risk |
|--------|------|
| **Response Forgery** | Attacker alters TXT records to invalidate legitimate claims |
| **Record Injection** | Attacker provides spoofed records that don't exist in the zone |
| **Negative Response Spoofing** | Attacker fakes NXDOMAIN, falsely indicating revocation |
| **Cache Poisoning** | Malicious data injected into DNS resolver caches |

**Mitigation:** Enable DNSSEC on your domain. Use a DNS provider that supports DNSSEC (e.g., Cloudflare, Route 53, Google Cloud DNS). Generate DS records and configure at your registrar.

The verification tool checks for DNSSEC validation and displays:
- `(DNSSEC: yes)` — Record authenticated
- `(DNSSEC: no)` — **ALERT: MITM or spoofing possible**

### Additional Considerations

- **DNS Propagation:** TXT record changes may take 1-24 hours to propagate globally
- **Expiration:** Claims have a default 90-day expiration; renew by generating a new claim with the same wallet
- **Claim File Security:** The claim file contains the secret used in signature verification. If leaked, the wallet address association to the domain becomes publicly known. Store claim files securely.
- **DNS Server Security:** If DNS server is compromised, new associations can be created and existing ones can be revoked. Ensure to secure the DNS server against unauthorized access.

---

## Project Structure

```
src/
├── index.ts            # CLI entry point
├── proof.ts            # Claim generation logic
├── verify.ts           # Verification logic
├── types.ts            # TypeScript interfaces
├── server.ts           # HTTP server for browser signing
└── browser-signer.html # MetaMask signing interface
```

## Build

```bash
npm run build     # Compile TypeScript to dist/
npm run dev       # Development mode with watch
```

---

Built with TypeScript and ethers.js. Uses EIP-191 for Ethereum signature verification.
