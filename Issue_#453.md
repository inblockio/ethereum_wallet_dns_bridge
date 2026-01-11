# Overview
This mechanism associates an Ethereum wallet with a domain via a public DNS TXT record under a subdomain (e.g., _aw.example.com), without exposing the wallet publicly. The TXT contains only a unique ID, timestamps, and EIP-191 signature. The association is proven via a selectively shared Aqua-Tree structure containing the wallet, a secret (used in signing), and a pointer to the DNS record. Verification reconstructs the signed message from Aqua-Tree and DNS data, recovering the wallet if valid. Supports multiple claims per subdomain (up to ~49, validated by querying response size limits per DNS provider; use _aw2, _aw3, etc., for overflow). 

**Revocation: Delete the corresponding TXT record.**

## Key Components
- **Unique Claim Identifier (ID)**: Random 8 hexadecimal characters (lowercase, e.g., "a1b2c3d4"). Namespace: 16^8 ≈ 4.29 billion; low collision risk for per-domain use
- **Claim Secret**: Random 16 hexadecimal characters (8 bytes, e.g., "1234567890abcdef"). Provides high entropy against brute-force.
- **Signed Message Structure**: Concatenation with "&" delimiters: <secret>&<issuing_timestamp>&<fqdn>&<expiration_timestamp>
  - Secret: Hex string.
  - Timestamps: Unix integers as strings (e.g., "1760015725").
  - FQDN: Lowercase domain without trailing dot (e.g., "inblock.io").
- **DNS TXT Record Format**: Single string under subdomain (e.g., _aw.inblock.io IN TXT "id=<unique_id>&itime=<issuing_timestamp>&etime=<expiration_timestamp>&sig=<0xsignature>").
  - Length: Keep under 255 chars (target ~175).
- **Continuations TXT Record**: Optional metadata record under the base subdomain (e.g., _aw.inblock.io IN TXT "continuations=_aw2,_aw3"). Contains a comma-separated list of subsequent subdomains (without domain suffix) for overflow handling.
  - **Justification**: Enables automated discoverability of iterated subdomains during verification without requiring sequential probing or prior knowledge of the total count. This reduces query overhead, prevents unnecessary NXDOMAIN errors, and simplifies client logic—especially useful if the number of subdomains varies or grows unpredictably. Include only if overflows exist; update dynamically as new subdomains are added.
- **Aqua-Tree Updates**: In the initial "form" revision's "forms" object:
  - Add forms_unique_id: Unique ID (string).
  - Add forms_claim_secret: Secret (string).
  - Add forms_txt_name: DNS pointer, e.g., "_aw.inblock.io" (full name for query usability).
  - Update forms_txt_record: To new anonymized format.
  - Retain forms_wallet_address (internal), forms_domain, forms_type="dns_claim", etc.
  - Note signature_type="ethereum:eip-191".
- **Signature**: Ethereum EIP-191 personal sign over keccak256 hash of the message (prefixed with "\x19Ethereum Signed Message:\n<length>").

# Implementation Instructions
1. **Claim Generation**:
   - Generate unique ID: Secure random 8 hex chars; check against existing domain claims and retry if duplicate.
   - Generate secret: Secure random 16 hex chars.
   - Set timestamps: Issuing as current Unix; expiration as issuing + duration (e.g., 90 days).
   - Build message: Concatenate with "&" as specified.
   - Hash: keccak256(UTF-8 message).
   - Sign: EIP-191 personal_sign with wallet private key.
   - Format TXT: "id=<id>&itime=<issuing>&etime=<expiration>&sig=0x<sig>".
   - Select subdomain: Use _aw.<domain>; if ~49 records reached (query and count existing TXT), increment to _aw2, etc.
   - If adding to a new subdomain and it's not the base, update the "continuations" TXT in the base subdomain to include the new one (append to the comma-separated list).
   - Update Aqua-Tree: Add new fields under "forms"; compute leaves/hashes per schema; proceed with link and signature revisions.
   - Publish TXT to DNS.

2. **Verification**:
   - From Aqua-Tree: Extract wallet_address, unique_id, claim_secret, forms_txt_name, domain.
   - Query DNS TXT at forms_txt_name; if a "continuations" record exists, also query the listed subdomains (appending .<domain>) and aggregate all TXT records.
   - Filter aggregated TXT records for matching "id=<unique_id>".
   - Extract itime, etime, sig from matched TXT.
   - Rebuild message: claim_secret&itime&domain&etime.
   - Hash and prefix per EIP-191.
   - Recover address from sig; validate matches wallet_address, timestamps align, current time < etime, and not expired/revoked (TXT exists).

3. **Additional considerations**
   - Security: Use CSPRNG for ID/secret; enforce timestamp checks; handle errors (e.g., missing TXT = revoked/invalid).
- **DNSSEC Recommendation**: DNSSEC is strongly recommended (though not strictly required) to ensure the integrity and authenticity of DNS responses. Without DNSSEC, DNS queries are vulnerable to spoofing, which could lead to invalidation of legitimate claims or injection of false positives. Enable DNSSEC on the domain to sign TXT records, preventing forgery or MITM attacks. Use a DNS provider supporting DNSSEC (e.g., Cloudflare, Route 53); generate DS records and delegate to registrar. During verification, require DNSSEC validation (e.g., via libraries like dnssec-python) to confirm record authenticity—reject if unsigned or invalid.
  - **Attack Scenarios Addressed by DNSSEC**:
    - **Response Forgery**: MITM attacker alters TXT records to invalidate a valid signature (e.g., by omitting or modifying the record, making a claim appear revoked).
    - **Injection of Fake Records**: Attacker provides spoofed TXT records with valid-looking signatures that don't exist in the original zone, potentially tricking verifiers into accepting unauthorized claims (though signature recovery would still fail unless the private key is compromised).
    - **Negative Response Spoofing**: Attacker fakes NXDOMAIN or "no records" responses for existing subdomains, falsely indicating revocation.
    - **Cache Poisoning**: Prevents attackers from injecting malicious data into DNS caches, ensuring resolvers get authentic records.
    - **Replay Attacks on DNS**: Ensures timestamps and records can't be manipulated in transit without detection.
- **Expiration Validation**: Strictly check current Unix time against "etime"(expiration time) during verification; invalidate if expired. Set conservative durations (e.g., 90-180 days)
{
  "forms_unique_id": "e6e655fc",
  "forms_claim_secret": "bab971b598bca505",
  "forms_txt_name": "aqua._wallet.inblock.io",
  "forms_wallet_address": "0x4b23da593596d94035c57adf6c2454216449b1b2",
  "forms_domain": "inblock.io",
  "forms_type": "dns_claim",
  "signature_type": "ethereum:eip-191",
  "itime": "1768164226",
  "etime": "1775940226",
  "sig": "0xadbd6ffd337a5126fb0318408ee67a40bb9141fc7176111eea4584b76546f86e07506c90943d39c05e39800f7c22bf7247f1b5f717c3aa71db7b0533bbd5bd811c"
}


