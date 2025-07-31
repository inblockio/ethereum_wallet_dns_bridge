#!/usr/bin/env node

import { program } from 'commander';
import { generateProof, generateProofFromSignature, formatTxtRecord, createMessageToSign } from './proof';
import { verifyProof } from './verify';
import { randomBytes } from 'crypto';

program
  .name('wallet-tool')
  .description('Wallet-to-Domain Lookup System CLI')
  .version('1.0.0');

program
  .command('generate')
  .description('Generate a proof using MetaMask browser signing')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .argument('[walletAddress]', 'Optional: Expected wallet address for verification')
  .action(async (domain, walletAddress) => {
    try {
      console.log('🌐 Starting MetaMask Browser Signer...');
      console.log(`\n📱 Generating proof for "${domain}"`);
      
      if (walletAddress) {
        console.log(`💡 Expected wallet address: ${walletAddress}`);
      }
      
      console.log('\n🚀 Starting local HTTP server...');
      
      const { spawn } = require('child_process');
      
      // Start http-server
      const server = spawn('npx', ['http-server', 'src', '-p', '8080', '-o', 'browser-signer.html', '--cors'], {
        stdio: 'inherit',
        shell: true
      });
      
      console.log('✅ Server started successfully!');
      console.log('🌐 Opening browser at: http://localhost:8080/browser-signer.html');
      console.log(`\n📝 Instructions:`);
      console.log('1. Connect your MetaMask wallet');
      console.log(`2. Enter domain: ${domain}`);
      console.log('3. Click "Generate Signature"');
      console.log('4. Copy and run the generated CLI command');
      console.log('\n⚠️  Press Ctrl+C to stop the server');
      
      // Handle server shutdown
      process.on('SIGINT', () => {
        console.log('\n🛑 Shutting down server...');
        server.kill();
        process.exit(0);
      });
      
    } catch (error) {
      console.error('❌ Error starting server:', error instanceof Error ? error.message : error);
      console.log('\n🔧 Manual fallback:');
      console.log('Run: wallet-tool browser');
      process.exit(1);
    }
  });

program
  .command('generate-from-browser')
  .description('Generate proof from browser MetaMask signature')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .argument('<walletAddress>', 'Wallet address from MetaMask')
  .argument('<signature>', 'Signature from MetaMask')
  .action(async (domain, walletAddress, signature) => {
    try {
      console.log('🔐 Processing browser signature...');
      
      // Generate timestamp and expiration from local system time
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const expiration = Math.floor(Date.now() / 1000 + (90 * 24 * 60 * 60)).toString(); // 90 days default
      
      console.log(`\n🌐 Domain: ${domain}`);
      console.log(`🦊 Wallet Address: ${walletAddress}`);
      console.log(`⏰ System Timestamp: ${timestamp}`);
      console.log(`📅 Expiration: ${new Date(parseInt(expiration) * 1000).toISOString()}`);
      
      // Create proof object with expiration
      const proof = generateProofFromSignature(domain, walletAddress, timestamp, expiration, signature);
      const txtRecord = formatTxtRecord(proof);
      
      console.log('\n✅ Proof generated successfully from browser signature!');
      console.log('\n📋 TXT Record Content:');
      console.log(`${txtRecord}`);
      console.log('\n📍 DNS Configuration:');
      console.log(`Add the above content as a TXT record at: aqua._wallet.${domain}`);
      console.log('\n💡 Instructions:');
      console.log('1. Copy the TXT record content above');
      console.log('2. Log into your DNS provider');
      console.log('3. Create a new TXT record with the specified name');
      console.log('4. Paste the content as the value');
      console.log('5. Save the DNS record');
      console.log('6. Wait for DNS propagation (up to 24 hours)');
      console.log(`7. Verify with: wallet-tool verify ${domain}`);
      
    } catch (error) {
      console.error('❌ Error processing signature:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('generate-interactive')
  .description('Launch browser signer for MetaMask signatures')
  .action(async () => {
    try {
      console.log('🌐 Browser Signer Tool');
      console.log('\n📱 To generate signatures with MetaMask:');
      console.log('1. Open src/browser-signer.html in your web browser');
      console.log('2. Connect your MetaMask wallet');
      console.log('3. Enter your domain name');
      console.log('4. Click "Generate Signature"');
      console.log('5. Copy and run the generated CLI command');
      console.log('\n💡 The browser tool will generate the signature with proper timestamp formatting.');
      console.log('   The CLI command will use your local system time for the final DNS record.');
      
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('browser')
  .description('Start local server for MetaMask signing interface')
  .action(async () => {
    console.log('🌐 Starting MetaMask Browser Signer Server...');
    console.log('\n🚀 Starting local HTTP server...');
    
    try {
      console.log('📦 Installing http-server if needed...');
      const { spawn } = require('child_process');
      
      // Start http-server
      const server = spawn('npx', ['http-server', 'src', '-p', '8080', '-o', 'browser-signer.html', '--cors'], {
        stdio: 'inherit',
        shell: true
      });
      
      console.log('\n✅ Server starting...');
      console.log('🌐 Opening browser at: http://localhost:8080/browser-signer.html');
      console.log('\n💡 If browser doesn\'t open automatically:');
      console.log('   - Open your browser');
      console.log('   - Go to: http://localhost:8080/browser-signer.html');
      console.log('   - Make sure MetaMask extension is installed');
      console.log('\n⚠️  Press Ctrl+C to stop the server');
      
      // Handle server shutdown
      process.on('SIGINT', () => {
        console.log('\n🛑 Shutting down server...');
        server.kill();
        process.exit(0);
      });
      
    } catch (error) {
      console.error('❌ Error starting server:', error);
      console.log('\n🔧 Manual setup:');
      console.log('1. Install http-server: npm install -g http-server');
      console.log('2. Run: npx http-server src -p 8080 -o browser-signer.html');
      console.log('3. Open: http://localhost:8080/browser-signer.html');
    }
  });

program
  .command('verify')
  .description('Verify a wallet-to-domain association')
  .argument('<domain>', 'Domain name (e.g., example.com)')
  .argument('[expectedWallet]', 'Expected wallet address (optional)')
  .action(async (domain, expectedWallet?) => {
    try {
      console.log(`🔍 Verifying wallet association for: ${domain}`);
      console.log(`ℹ️  DNS record location: aqua._wallet.${domain}`);
      if(expectedWallet){
        console.log(`🟰  Wallet address expected: aqua._wallet.${expectedWallet}`);

      }
      
      const isValid = await verifyProof(domain, 'wallet', expectedWallet);
      
      if (!isValid) {
        console.log('\n📋 Troubleshooting checklist:');
        console.log('• Ensure DNS record exists at aqua._wallet.' + domain);
        console.log('• Check DNS record format: wallet=address&timestamp=time&sig=signature');
        console.log('• Verify DNS propagation (can take up to 24 hours)');
        console.log('• Confirm signature was generated for the correct domain');
        console.log('• Test with: dig TXT aqua._wallet.' + domain);
        process.exit(1);
      }
      
    } catch (error) {
      console.error('❌ Verification error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program.parse(); 