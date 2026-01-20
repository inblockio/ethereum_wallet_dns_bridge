#!/usr/bin/env node

import { program } from 'commander';
import { exec } from 'child_process';
import { verifyClaim, verifyFromDNS } from './verify';

program
  .name('wallet-tool')
  .description('Ethereum Wallet to Domain DNS Bridge')
  .version('1.0.0');

import { generateClaimWithOverflow } from './proof';

program
  .command('generate')
  .description('Generate a claim using MetaMask browser signing or private key')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .argument('[privateKey]', 'Optional private key for headless generation')
  .option('-p, --public', 'Make association public (wallet visible in DNS record)')
  .action(async (domain: string, privateKey: string | undefined, options: { public?: boolean }) => {
    // Check if the second argument is actually the options object (commander behavior when optional arg is missing)
    // In Commander, if an optional argument is not provided, the argument value might be the options object if not handled carefully,
    // but usually with .argument(), it passes undefined. However, let's be safe.
    // If privateKey is an object (the options), then it wasn't passed as a string string.
    if (typeof privateKey === 'object') {
      options = privateKey as any;
      privateKey = undefined;
    }

    if (privateKey) {
      // Headless mode
      try {
        console.log(`Generating proof for ${domain}...`);
        const { claim, continuationsUpdate } = await generateClaimWithOverflow(
          domain,
          privateKey,
          90, // default expiration
          options.public
        );

        console.log('\n✅ Proof Generated!');
        console.log('\nCreate the following TXT record in your DNS provider:');
        console.log('---------------------------------------------------------');
        console.log(`Host:  ${claim.forms_txt_name}`);
        console.log(`Value: ${claim.forms_txt_record}`);
        console.log('---------------------------------------------------------');

        if (continuationsUpdate) {
          console.log('\n⚠️  UPDATE REQUIRED: Checks passed limits.');
          console.log(`Please ensure the parent record includes: ${continuationsUpdate}`);
        }
      } catch (error) {
        console.error('❌ Error generating proof:', error instanceof Error ? error.message : error);
        process.exit(1);
      }
      return;
    }

    // Browser mode
    const net = require('net');
    const path = require('path');
    const { spawn } = require('child_process');

    const params = new URLSearchParams({ domain });
    if (options.public) params.set('public', 'true');
    const url = `http://localhost:3000/browser-signer.html?${params.toString()}`;

    const client = net.createConnection({ port: 3000, host: 'localhost' }, () => {
      client.end();
      openBrowser(url);
    });

    client.on('error', () => {
      console.log('Starting server...');
      const server = spawn('node', [path.join(__dirname, 'server.js')], { stdio: 'pipe' });
      server.stdout.on('data', (data: Buffer) => {
        if (data.toString().includes('Server running')) {
          openBrowser(url);
        }
      });
      server.on('error', (err: Error) => {
        console.error('Server error:', err.message);
        process.exit(1);
      });
    });

    function openBrowser(url: string) {
      console.log(`Opening: ${url}`);
      if (options.public) {
        console.log('Mode: PUBLIC (wallet will be visible in DNS)');
      }
      exec(`xdg-open "${url}"`, () => { });
      console.log('\n1. Connect MetaMask\n2. Click "Generate Claim"\n3. Add TXT record to DNS');
    }
  });

program
  .command('server')
  .description('Start the signing server on port 3000')
  .action(() => {
    require('./server.js');
  });

program
  .command('verify')
  .description('Verify a claim from JSON file')
  .argument('<claimFile>', 'Path to claim JSON file')
  .action(async (claimFile: string) => {
    try {
      const fs = require('fs');
      const claim = JSON.parse(fs.readFileSync(claimFile, 'utf8'));
      const valid = await verifyClaim(claim);
      process.exit(valid ? 0 : 1);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('verify-dns')
  .description('Verify public claims directly from DNS (no claim file needed)')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .argument('[claimId]', 'Optional: specific claim ID to verify')
  .action(async (domain: string, claimId?: string) => {
    try {
      const result = await verifyFromDNS(domain, claimId);
      process.exit(result.valid ? 0 : 1);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program.parse();
