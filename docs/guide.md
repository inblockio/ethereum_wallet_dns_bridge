# Wallet-to-Domain Lookup System User Guide

## Overview
The Wallet-to-Domain Lookup System is a CLI tool that allows you to associate cryptocurrency wallet addresses with domain names using DNS TXT records. This creates a verifiable link between your wallet and domain that can be cryptographically validated.

## Prerequisites
- **Node.js** (v18 or higher)
- **DNS Admin Access**: You must have administrative access to your domain's DNS settings
- **Cryptocurrency Wallet**: A private key for the wallet you want to associate

## Installation

### Option 1: Use Pre-built Binary
1. Download `wallet-tool.js` from the GitHub releases
2. Run commands using: `node wallet-tool.js <command>`

### Option 2: Build from Source
1. Clone the repository
2. Install dependencies: `npm install`
3. Build the tool: `node build.js`
4. Use the built file: `node dist/wallet-tool.js <command>`
   
   **Note for Linux/Mac users:**
   You can also make the file executable and run it directly:
   ```bash
   chmod +x dist/wallet-tool.js
   ./dist/wallet-tool.js <command>
   ```

## Commands

### Generate Proof
Creates a cryptographic proof linking your wallet to a domain.

```bash
# Using node
node dist/wallet-tool.js generate <domain> [privateKey] [--public]

# Or directly (Linux/Mac)
./dist/wallet-tool.js generate <domain> [privateKey] [--public]
```

**Parameters:**
- `<domain>`: Your domain name (e.g., `example.com`)
- `[privateKey]`: (Optional) Your wallet's private key for headless generation. If omitted, opens browser for MetaMask.
- `--public`: (Optional) Make the association public by including the wallet address directly in the DNS record. This allows verification without the claim file.

**Example:**
```bash
# Private claim (default) - requires claim file to verify
node wallet-tool.js generate example.com 0x123456...

# Public claim - verifiable by anyone via DNS
node wallet-tool.js generate example.com 0x123456... --public
```

**Output:**
The tool will generate a TXT record content and the specific Host/Name to use:
```txt
Host:  _aw.example.com
Value: id=440a2718&time=...&sig=0x...
```

**Note:** The value `440a2718` (after `id=`) is your **Claim ID**. You may need this for verification.

### Verify Association
Verifies that a wallet-to-domain association exists and is valid.

**Option A: Verify from DNS (Public)**
Checks public DNS records directly.

```bash
./dist/wallet-tool.js verify-dns <domain> [claimId]
# or
node dist/wallet-tool.js verify-dns <domain> [claimId]
```

**Parameters:**
- `<domain>`: The domain name to check
- `[claimId]`: (Optional) The specific **Claim ID** (e.g., `440a2718`) from the generation output. Useful if you have multiple claims on one domain.

**Example:**
```bash
node wallet-tool.js verify-dns example.com
```

**Option B: Verify from Claim File (Private)**
Verifies a locally stored claim file.

```bash
./dist/wallet-tool.js verify <claimFile>
# or
node dist/wallet-tool.js verify <claimFile>
```

## DNS Configuration

### Step-by-Step DNS Setup

1. **Generate the Proof**
   ```bash
   ./dist/wallet-tool.js generate yourdomain.com [privateKey]
   ```

2. **Copy the Record Details**
   The tool will output the exact Host and Value you need.
   ```
   Host:  _aw.yourdomain.com
   Value: id=440a2718&wallet=0x...
   ```

3. **Access Your DNS Provider**
   - Log into your domain registrar
   - Navigate to DNS management

4. **Create TXT Record**
   - **Type**: TXT
   - **Host/Name**: Use the `Host` value from the tool output (usually `_aw` or `_aw.yourdomain.com` depending on your provider)
   - **Value**: Copy the full `Value` string

5. **Save and Wait**
   - Save the record
   - Wait for DNS propagation

6. **Verify**
   ```bash
   ./dist/wallet-tool.js verify-dns yourdomain.com
   ```

### DNS Record Format

The tool automatically manages record names to handle multiple claims via integer suffixes if necessary.

**Standard Record:**
```
_aw.<domain>
```

**Overflow Records:**
If you have many claims, the tool may direct you to use:
- `_aw2.<domain>`
- `_aw3.<domain>`
etc.

## Security Considerations

### Private Key Safety
- **Never share your private key** with anyone
- The tool only uses your private key to generate the cryptographic signature
- **Private keys are not stored** anywhere by this tool
- Consider using a dedicated wallet for domain associations

### DNS Security
- Use **DNSSEC** if your domain provider supports it
- Regularly monitor your DNS records for unauthorized changes
- Use strong passwords for your DNS provider account

### Proof Validity
- Each proof includes a timestamp and random nonce to prevent replay attacks
- The cryptographic signature ensures data integrity
- You can generate new proofs to update or revoke associations

## Troubleshooting

### "Invalid or no association found"
**Possible causes:**
1. **DNS Record Missing**: Check that the TXT record exists at the correct location
2. **DNS Propagation**: Wait longer for DNS changes to propagate globally
3. **Wrong Format**: Ensure the TXT record content exactly matches the generated proof

**Solutions:**
- Use online DNS lookup tools to verify your TXT record exists
- Try the verify command from different networks/locations
- Double-check the exact spelling of domain

### "Error generating proof"
**Possible causes:**
1. **Invalid Private Key**: Ensure the private key is in correct format (0x...)
2. **Invalid Domain**: Check domain name format and spelling

### DNS Propagation Check
You can manually check if your DNS record exists using:
```bash
# Linux/Mac
dig TXT _aw.yourdomain.com

# Windows
nslookup -type=TXT _aw.yourdomain.com
```

## Advanced Usage

### Multiple Associations
You can associate multiple wallets. The tool will automatically handle this by assigning them to the same `_aw` record (if space permits) or creating overflow records like `_aw2`.

```bash
# Associate main wallet
node wallet-tool.js generate yourdomain.com 0xMainWalletKey
# Output will direct you to: _aw.yourdomain.com

# Associate trading wallet
node wallet-tool.js generate yourdomain.com 0xTradingWalletKey
# Output will direct you to either append to _aw or create _aw2
```

### Updating Associations
To update or revoke an association:
1. Generate a new proof with the updated wallet
2. Replace the existing DNS TXT record
3. Or delete the DNS record to remove the association

## Technical Details

### Cryptographic Process
1. **Message Construction**: `timestamp + nonce + domain`
2. **Hashing**: SHA-256 hash of the message
3. **Signing**: EIP-191 signature using wallet private key
4. **Verification**: Recover address from signature and compare

### DNS Query Process
### DNS Query Process
1. Query `_aw.<domain>` for TXT records

2. Parse the record content into components
3. Reconstruct the original message
4. Verify the cryptographic signature
5. Compare recovered address with claimed wallet address

## Support

For issues, questions, or contributions:
- Check existing GitHub issues
- Create new issues with detailed error messages
- Include your OS, Node.js version, and exact commands used

---

**⚠️ Important**: Always keep your private keys secure and never share them. This tool is designed for users who understand cryptocurrency wallet security basics. 