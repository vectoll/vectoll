import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const brandSrc = path.resolve(__dirname, '../../brand');

for (const site of ['org', 'com']) {
  const siteBrand = path.join(__dirname, site, 'brand');
  fs.mkdirSync(siteBrand, { recursive: true });
  for (const file of fs.readdirSync(brandSrc)) {
    fs.copyFileSync(path.join(brandSrc, file), path.join(siteBrand, file));
  }

  const wellKnownDir = path.join(__dirname, site, '.well-known');
  fs.mkdirSync(wellKnownDir, { recursive: true });
  const domain = site === 'org' ? 'vectoll.org' : 'vectoll.com';
  fs.writeFileSync(
    path.join(wellKnownDir, 'vectoll.json'),
    JSON.stringify(
      {
        vectollVersion: '1.0',
        x402Version: 2,
        service: {
          name: domain,
          description:
            site === 'org'
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
          },
        ],
      },
      null,
      2,
    ) + '\n',
  );
}

console.log('Synced /brand/* and /.well-known/vectoll.json into apps/web/org and apps/web/com');
