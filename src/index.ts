#!/usr/bin/env node

import { program } from 'commander';
import { generateProof, generateProofFromSignature, formatTxtRecord, createMessageToSign, generateClaim, formatClaimTxtRecord } from './proof';
const { exec } = require('child_process');
import { verifyClaim } from './verify';
import { randomBytes } from 'crypto';

program
  .name('wallet-tool')
  .description('Wallet-to-Domain Lookup System CLI')
  .version('1.0.0');

program
  .command('generate')
  .description('Generate a claim using MetaMask browser signing')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .argument('[walletAddress]', 'Optional: Expected wallet address for verification')
  .action(async (domain, walletAddress) => {
    try {
      console.log('Starting MetaMask Browser Signer...');
      console.log(`\n📱 Generating proof for "${domain}"`);
      
      if (walletAddress) {
        console.log(`💡 Expected wallet address: ${walletAddress}`);
      }
      

      // Check if server is running
      const net = require('net');
      const client = net.createConnection({ port: 3000, host: 'localhost' }, () => {
        console.log('Server is running.');
        client.end();
        openBrowser();
      });
      client.on('error', (err) => {
        console.log('Server not running on port 3000. Starting server...');
        const { spawn } = require('child_process');
        const path = require('path');
        const serverProcess = spawn('node', [path.join(__dirname, 'server.js')], { stdio: 'pipe' });
        serverProcess.stdout.on('data', (data) => {
          if (data.toString().includes('Server running at http://localhost:3000')) {
            console.log('Server started successfully!');
            openBrowser();
          }
        });
        serverProcess.on('error', (error) => {
          console.error('Error starting server:', error.message);
          process.exit(1);
        });
      });

      function openBrowser() {
        console.log('\nOpening browser at: http://localhost:3000/browser-signer.html?domain=' + encodeURIComponent(domain));

        // Open browser
        exec('xdg-open http://localhost:3000/browser-signer.html?domain=' + encodeURIComponent(domain), (err) => {
          if (err) console.log('Could not open browser automatically. Please open http://localhost:3000/browser-signer.html?domain=' + encodeURIComponent(domain) + ' manually.');
        });
        console.log(`
Instructions:`);
        console.log('1. Connect your MetaMask wallet in the opened browser');
        console.log(`2. Domain should be pre-filled: ${domain}`);
        console.log('3. Click "Generate Claim"');
        console.log('4. Copy and run the generated CLI command (saves to claims/)');
        console.log('5. Publish the TXT record to DNS');
        console.log("\nNote: Close the browser tab when done. The server continues running.");
      }
    } catch (error) {
      console.error('Error starting server:', error instanceof Error ? error.message : error);
      console.log('\n🔧 Manual fallback:');
      console.log('Run: wallet-tool browser');
      process.exit(1);
    }
  });


program
  .command('server')
  .description('Start the Node.js server for browser signing on port 3000')
  .action(async () => {
    console.log('Starting Node.js server on port 3000...');
    // Run the server directly
    require('./server.js');
  });


program  .command('verify')  .description('Verify a claim from JSON file')  .argument('<claimFile>', 'Path to claim JSON file in claims/ folder (e.g., claims/abc123.json)')  .action(async (claimFile) => {
    try {
      console.log(`Verifying claim from: ${claimFile}`);

      // Load claim from JSON file
      const fs = require('fs');
      const claimData = JSON.parse(fs.readFileSync(claimFile, 'utf8'));
      console.log(`Claim ID: ${claimData.forms_unique_id}`);
      console.log(`Domain: ${claimData.forms_domain}`);
      console.log(`Wallet: ${claimData.forms_wallet_address}`);
      console.log(`DNS: ${claimData.forms_txt_name}`);
      const isValid = await verifyClaim(claimData);
      if (!isValid) {
        console.log("• Check DNS record format: id=...&itime=...&etime=...&sig=...");
        console.log("• Confirm claim JSON is correct and signature matches");
        console.log("• Test with: dig TXT " + claimData.forms_txt_name);
        process.exit(1);
      }
      
    } catch (error) {
      console.error('Verification error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program.parse(); 