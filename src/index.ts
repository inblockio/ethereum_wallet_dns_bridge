#!/usr/bin/env node

import { program } from 'commander';
import { exec } from 'child_process';
import { verifyClaim, verifyFromDNS } from './verify';

program
  .name('wallet-tool')
  .description('Ethereum Wallet to Domain DNS Bridge')
  .version('1.0.0');

program
  .command('generate')
  .description('Generate a claim using MetaMask browser signing')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .option('-p, --public', 'Make association public (wallet visible in DNS record)')
  .action(async (domain: string, options: { public?: boolean }) => {
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
      exec(`xdg-open "${url}"`, () => {});
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
