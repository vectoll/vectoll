import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const BRAND_DIR = path.join(ROOT, 'brand');
const ORG_DIR = path.join(__dirname, 'org');
const COM_DIR = path.join(__dirname, 'com');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.md': 'text/markdown; charset=utf-8',
};

function buildDiscoveryManifest(siteName) {
  return {
    vectollVersion: '1.0',
    x402Version: 2,
    service: {
      name: siteName,
      description:
        siteName === 'vectoll.org'
          ? 'Vectoll Open Protocol Specification, WebCrypto Studio & RFC Hub'
          : 'Vectoll Cloud Managed Multi-Rail AI Agent Settlement Platform',
      mcpEndpoint: '/mcp',
    },
    settlement: {
      facilitatorUrl: 'https://pay.vectoll.com',
      jwksUrl: 'https://pay.vectoll.com/.well-known/jwks.json',
      facilitatorPublicKey: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      facilitatorKid: 'fac-ed25519-global-1',
      defaultCurrency: 'USD',
      defaultDecimals: 4,
      acceptedRails: [
        'stripe',
        'x402_usdc',
        'sepa_instant',
        'fednow_ach',
        'pix',
        'upi',
        'paynow',
        'mpesa',
        'momo',
      ],
    },
    routes: [
      {
        path: '/api/v1/signals',
        method: 'GET',
        pricingMode: 'fixed',
        amount: 50,
        currency: 'USD',
        decimals: 4,
        settlementMode: 'instant',
        humanPassthrough: true,
        mcpTool: {
          name: 'get_protocol_signals',
          description: 'Query live multi-rail settlement telemetry',
        },
      },
    ],
  };
}

function createSiteServer(siteDir, siteName) {
  let requestsTotal = 0;

  return http.createServer((req, res) => {
    requestsTotal++;
    const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = decodeURIComponent(reqUrl.pathname);

    if (pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: true, site: siteName, version: '1.0.0' }));
      return;
    }

    if (pathname === '/.well-known/vectoll.json') {
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
      });
      res.end(JSON.stringify(buildDiscoveryManifest(siteName), null, 2));
      return;
    }

    if (pathname === '/metrics') {
      res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
      res.end(
        `# HELP vectoll_web_requests_total Total HTTP requests served by ${siteName}\n` +
          `# TYPE vectoll_web_requests_total counter\n` +
          `vectoll_web_requests_total{site="${siteName}"} ${requestsTotal}\n`,
      );
      return;
    }

    let filePath;
    if (pathname.startsWith('/brand/')) {
      const rel = path.normalize(pathname.slice('/brand/'.length)).replace(/^(\.\.[/\\])+/, '');
      filePath = path.join(BRAND_DIR, rel);
    } else {
      const target = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const rel = path.normalize(target).replace(/^(\.\.[/\\])+/, '');
      filePath = path.join(siteDir, rel);
    }

    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    fs.createReadStream(filePath).pipe(res);
  });
}

const ORG_PORT = Number(process.env.VECTOLL_ORG_PORT || 4030);
const COM_PORT = Number(process.env.VECTOLL_COM_PORT || 4031);
const HOST = process.env.VECTOLL_WEB_HOST || '127.0.0.1';

const orgServer = createSiteServer(ORG_DIR, 'vectoll.org');
const comServer = createSiteServer(COM_DIR, 'vectoll.com');

orgServer.listen(ORG_PORT, HOST, () => {
  console.log(`[vectoll.org] Open Protocol & WebCrypto Studio -> http://${HOST}:${ORG_PORT}`);
});
comServer.listen(COM_PORT, HOST, () => {
  console.log(`[vectoll.com] Vectoll Cloud & Live Console     -> http://${HOST}:${COM_PORT}`);
});

function shutdown() {
  orgServer.close();
  comServer.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
