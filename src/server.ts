#!/usr/bin/env node

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as url from 'url';

const PORT = process.env.PORT || 3000;
const CLAIMS_DIR = path.join(__dirname, '..', 'claims');

// Ensure claims directory exists
if (!fs.existsSync(CLAIMS_DIR)) {
    fs.mkdirSync(CLAIMS_DIR, { recursive: true });
}

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url!, true);
    const pathname = parsedUrl.pathname;

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    if (pathname === '/save-claim' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                const claimData = JSON.parse(body);
                const filename = `${claimData.forms_unique_id}.json`;
                const filepath = path.join(CLAIMS_DIR, filename);

                fs.writeFileSync(filepath, JSON.stringify(claimData, null, 2));
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: `Claim saved to ${filename}` }));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
    } else if (pathname === '/' || pathname === '/browser-signer.html') {
        const filePath = path.join(__dirname, '..', 'src', 'browser-signer.html');
        console.log(`Serving ${filePath}`);
        fs.readFile(filePath, (err, data) => {
            if (err) {
                console.error(`Error reading file ${filePath}:`, err);
                res.writeHead(404);
                res.end('File not found');
                return;
            }
            // Inject the domain from query parameter into the HTML
            let html = data.toString();
            const domain = parsedUrl.query.domain as string;
            if (domain) {
                html = html.replace('<input type="text" id="domain" placeholder="example.com">', `<input type="text" id="domain" value="${domain}" placeholder="example.com">`);
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
        });
    } else {
        res.writeHead(404);
        res.end('Not found');
    }
});

server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Claims will be saved to: ${CLAIMS_DIR}`);
});