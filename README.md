# Wallet-to-Domain DNS Bridge

A cryptographic tool for establishing verifiable associations between Ethereum wallets and domain names using DNS TXT records. Supports both private and public association modes for flexible identity verification.

## Overview

This system enables domain owners to cryptographically prove ownership of an Ethereum wallet by publishing a signed claim to DNS. Two modes are available:

- **Private Mode** (default): The wallet address remains hidden in DNS. Only parties with the claim file can verify the association.
- **Public Mode**: The wallet address is included in the DNS record. Anyone can verify the association directly from DNS.

**Key Properties:**
- Choose between private or public wallet-domain association
- Claims are independently verifiable via EIP-191 signatures
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

**Options:**
- `-p, --public` — Make association public (wallet visible in DNS record)

**Examples:**
```bash
# Private mode (default) - wallet address hidden in DNS
node dist/wallet-tool.js generate example.com

# Public mode - wallet address visible in DNS
node dist/wallet-tool.js generate --public example.com
```

This opens a browser window with the signing interface:

1. **Connect MetaMask** — Click "Connect Wallet" and approve the connection
2. **Choose Mode** — Check "Make association public" if you want the wallet visible in DNS
3. **Generate Claim** — Click "Generate Claim" and sign the message in MetaMask
4. **Download Claim File** — Save the generated JSON file securely
5. **Copy DNS Record** — Copy the TXT record value for DNS configuration

### Step 2: Configure DNS

Add a TXT record to your domain's DNS:

| Field | Value |
|-------|-------|
| **Name** | `_aw` (or `_aw.example.com` depending on your DNS provider) |
| **Type** | `TXT` |
| **Value** | The generated record (see formats below) |

**Record Formats:**

- **Private mode:** `id=a1b2c3d4&itime=...&etime=...&sig=0x...`
- **Public mode:** `id=a1b2c3d4&wallet=0x...&itime=...&etime=...&sig=0x...`

**DNS Propagation:** Changes may take 1-24 hours to propagate globally.

### Step 3: Verify a Claim

#### Option A: Verify with Claim File (Private or Public)

Verify a claim using the claim file:

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
✓ Signature valid (private)
✓ Not expired (until 2026-04-16)
✓ Wallet 0x742d35Cc6634C0532925a3b844Bc454e4438f44e linked to example.com
```

#### Option B: Verify Public Claims from DNS (No Claim File Needed)

For public claims, verify directly from DNS without needing the claim file:

```bash
node dist/wallet-tool.js verify-dns <domain> [claimId]
```

Examples:
```bash
# Verify all public claims for a domain
node dist/wallet-tool.js verify-dns example.com

# Verify a specific public claim by ID
node dist/wallet-tool.js verify-dns example.com a1b2c3d4
```

**Output (all public claims):**
```
Verifying public claims for example.com...
✓ DNS record found (DNSSEC: yes)
Found 2 public claim(s) to verify
  ✓ Claim a1b2c3d4: Valid
    Wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    Expires: 2026-04-16
  ✓ Claim b2c3d4e5: Valid
    Wallet: 0x1234567890abcdef1234567890abcdef12345678
    Expires: 2026-05-20

--- Summary ---
✓ 2 valid public claim(s):
  ID: a1b2c3d4
    Wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    Expires: 2026-04-16
  ID: b2c3d4e5
    Wallet: 0x1234567890abcdef1234567890abcdef12345678
    Expires: 2026-05-20
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

**Private Mode:**
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
  "sig": "0x...",
  "public_association": false
}
```

**Public Mode:**
```json
{
  "forms_unique_id": "a1b2c3d4",
  "forms_claim_secret": "",
  "forms_txt_name": "_aw.example.com",
  "forms_txt_record": "id=a1b2c3d4&wallet=0x742d...&itime=1768168912&etime=1775944912&sig=0x...",
  "forms_wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "forms_domain": "example.com",
  "forms_type": "dns_claim",
  "signature_type": "ethereum:eip-191",
  "itime": "1768168912",
  "etime": "1775944912",
  "sig": "0x...",
  "public_association": true
}
```

**Fields:**
- `forms_unique_id` — 8 hex character claim identifier
- `forms_claim_secret` — 16 hex character secret (private mode) or empty string (public mode)
- `forms_txt_name` — Full DNS subdomain for the TXT record
- `forms_txt_record` — The exact value to publish in DNS
- `forms_wallet_address` — The Ethereum address being claimed
- `itime` — Issuing timestamp (Unix epoch)
- `etime` — Expiration timestamp (Unix epoch)
- `sig` — EIP-191 signature
- `public_association` — Whether wallet is visible in DNS record

---

## Specification

### Mechanism

This system associates an Ethereum wallet with a domain via a public DNS TXT record under a subdomain (e.g., `_aw.example.com`). Two modes are supported:

**Private Mode:** The TXT record contains only a unique ID, timestamps, and an EIP-191 signature. The wallet address is kept secret and only revealed via a selectively shared claim file containing a secret used in signing.

**Public Mode:** The TXT record includes the wallet address directly. Anyone can verify the association by querying DNS and validating the signature.

Verification reconstructs the signed message from available data and recovers the wallet address using EIP-191 signature verification.

### Components

| Component | Format | Description |
|-----------|--------|-------------|
| **Unique ID** | 8 hex chars (e.g., `a1b2c3d4`) | Random identifier; ~4.29 billion namespace |
| **Claim Secret** | 16 hex chars (private mode only) | High-entropy secret for brute-force resistance |
| **Signed Message (Private)** | `<secret>&<itime>&<domain>&<etime>` | Secret-based message |
| **Signed Message (Public)** | `<wallet>&<itime>&<domain>&<etime>` | Wallet-based message |
| **DNS TXT Record (Private)** | `id=<id>&itime=...&etime=...&sig=...` | No wallet in record |
| **DNS TXT Record (Public)** | `id=<id>&wallet=<addr>&itime=...&etime=...&sig=...` | Wallet in record |

### DNS Record Format

**Primary subdomain:** `_aw.<domain>`

**Private Mode TXT Record:**
```
id=<unique_id>&itime=<issuing_timestamp>&etime=<expiration_timestamp>&sig=0x<signature>
```

**Public Mode TXT Record:**
```
id=<unique_id>&wallet=<wallet_address>&itime=<issuing_timestamp>&etime=<expiration_timestamp>&sig=0x<signature>
```

**Examples:**
```
# Private mode
_aw.example.com IN TXT "id=e6e655fc&itime=1768164226&etime=1775940226&sig=0xadbd6ffd..."

# Public mode
_aw.example.com IN TXT "id=a1b2c3d4&wallet=0x742d35Cc...&itime=1768164226&etime=1775940226&sig=0x..."
```

**Record length:** Target under 175 characters for private mode, ~220 for public mode (max 255).

### Overflow Handling

Each subdomain supports approximately 49 claims (limited by DNS response size). This allows multiple different wallets to be linked to a single domain, as well as multiple claims from the same wallet. When capacity is reached:

1. Create overflow subdomain: `_aw2.<domain>`, `_aw3.<domain>`, etc.
2. Add continuations record to base subdomain: `continuations=_aw2,_aw3`

The continuations record enables automated discovery during verification without sequential probing.

### Signature Method

- **Standard:** EIP-191 (Ethereum personal_sign)
- **Message (Private):** `<secret>&<itime>&<domain>&<etime>`
- **Message (Public):** `<wallet>&<itime>&<domain>&<etime>`
- **Hash:** keccak256 with prefix `\x19Ethereum Signed Message:\n<length>`

### Verification Process

**With Claim File (Private or Public):**
1. Extract `wallet_address`, `unique_id`, `claim_secret`, `forms_txt_name` from claim file
2. Query DNS TXT at `forms_txt_name`
3. If continuations record exists, query additional subdomains
4. Filter records for matching `id=<unique_id>`
5. Extract `itime`, `etime`, `sig` (and `wallet` if public mode) from matched record
6. Detect mode: if `wallet` present in DNS record, it's public mode
7. Rebuild message:
   - Private: `claim_secret&itime&domain&etime`
   - Public: `wallet&itime&domain&etime`
8. Recover address from signature using EIP-191
9. Validate: address matches, current time < etime, record exists

**DNS-Only Verification (Public Mode):**
1. Query DNS TXT at `_aw.<domain>`
2. If continuations record exists, query additional subdomains
3. Filter for public records (those containing `wallet=`)
4. For each record, rebuild message: `wallet&itime&domain&etime`
5. Recover address from signature using EIP-191
6. Validate: recovered address matches wallet in record, current time < etime

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
- **Claim File Security (Private Mode):** The claim file contains the secret used in signature verification. If leaked, the wallet address association to the domain becomes publicly known. Store claim files securely.
- **Public Mode Privacy:** In public mode, the wallet address is visible in DNS to anyone. Use this mode only when you want the association to be publicly discoverable.
- **DNS Server Security:** If DNS server is compromised, new associations can be created and existing ones can be revoked. Ensure to secure the DNS server against unauthorized access.
- **Mode Selection:** Choose private mode when you want selective disclosure (share claim file only with specific parties). Choose public mode when you want anyone to verify the wallet-domain link without requiring a claim file.

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
