#!/usr/bin/env node
"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const { exec } = require('child_process');
const verify_1 = require("./verify");
commander_1.program
    .name('wallet-tool')
    .description('Wallet-to-Domain Lookup System CLI')
    .version('1.0.0');
commander_1.program
    .command('generate')
    .description('Generate a claim using MetaMask browser signing')
    .argument('<domain>', 'Domain name (e.g., example.com)')
    .argument('[walletAddress]', 'Optional: Expected wallet address for verification')
    .action((domain, walletAddress) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        console.log('Starting MetaMask Browser Signer...');
        console.log(`\n📱 Generating proof for "${domain}"`);
        if (walletAddress) {
            console.log(`💡 Expected wallet address: ${walletAddress}`);
        }
        console.log('\nStarting local HTTP server...');
        // Start simple HTTP server
        const http = require('http');
        const fs = require('fs');
        const path = require('path');
        const server = http.createServer((req, res) => {
            if (req.url === '/' || req.url === '/browser-signer.html') {
                const filePath = path.join(__dirname, '../src/browser-signer.html');
                fs.readFile(filePath, (err, data) => {
                    if (err) {
                        res.writeHead(404, { 'Content-Type': 'text/plain' });
                        res.end('File not found');
                        return;
                    }
                    // Inject the domain into the HTML
                    let html = data.toString();
                    html = html.replace('<input id="domain" placeholder="e.g., example.com">', ` <input id="domain" value="${domain}" placeholder="e.g., example.com">`);
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(html);
                });
            }
            else {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not found');
            }
        });
        server.listen(8080, () => {
            console.log('Server started successfully!');
            console.log('Opening browser at: http://localhost:8080/browser-signer.html');
            // Open browser immediately since server is ready
            exec('xdg-open http://localhost:8080/browser-signer.html', (err) => {
                if (err)
                    console.log('Could not open browser automatically. Please open http://localhost:8080/browser-signer.html manually.');
            });
        });
        console.log(`
Instructions:`);
        console.log('1. Connect your MetaMask wallet');
        console.log(`2. Enter domain: ${domain}`);
        console.log('3. Click "Generate Claim"');
        console.log('4. Copy and run the generated CLI command (saves to claims/)');
        console.log('5. Publish the TXT record to DNS');
        console.log("\nWARNING: Press Ctrl+C to stop the server");
        // Handle server shutdown
        // Handle server shutdown
        process.on('SIGINT', () => {
            console.log('\nShutting down server...');
            server.close(() => {
                process.exit(0);
            });
        });
    }
    catch (error) {
        console.error('Error starting server:', error instanceof Error ? error.message : error);
        console.log('\n🔧 Manual fallback:');
        console.log('Run: wallet-tool browser');
        process.exit(1);
    }
}));
commander_1.program.command('verify').description('Verify a claim from JSON file').argument('<claimFile>', 'Path to claim JSON file in claims/ folder (e.g., claims/abc123.json)').action((claimFile) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        console.log(`Verifying claim from: ${claimFile}`);
        // Load claim from JSON file
        const fs = require('fs');
        const claimData = JSON.parse(fs.readFileSync(claimFile, 'utf8'));
        console.log(`Claim ID: ${claimData.forms_unique_id}`);
        console.log(`Domain: ${claimData.forms_domain}`);
        console.log(`Wallet: ${claimData.forms_wallet_address}`);
        console.log(`DNS: ${claimData.forms_txt_name}`);
        const isValid = yield (0, verify_1.verifyClaim)(claimData);
        if (!isValid) {
            console.log("• Check DNS record format: id=...&itime=...&etime=...&sig=...");
            console.log("• Confirm claim JSON is correct and signature matches");
            console.log("• Test with: dig TXT " + claimData.forms_txt_name);
            process.exit(1);
        }
    }
    catch (error) {
        console.error('Verification error:', error instanceof Error ? error.message : error);
        process.exit(1);
    }
}));
commander_1.program.parse();
