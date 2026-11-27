import http from 'node:http';
import { generateKeyPair } from '@vectoll/core';
import { VectollAgentClient } from '@vectoll/sdk';
import { vectollMiddleware } from '@vectoll/server';

// 1. Add Vectoll middleware to your existing Node / Express app (runs on ONE single port!)
const paywall = vectollMiddleware({
  name: 'my-weather-api',
  routes: {
    'GET /api/weather': '$0.005',
    'GET /blog/*': { price: '$0.001', browsers: 'free' },
  },
});

const app = http.createServer((req, res) => {
  paywall(req, res, () => {
    if (req.url?.startsWith('/api/weather')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ city: 'Tokyo', tempC: 21, paidByAgent: req.vectoll?.sub }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>Free for Human Browsers!</h1>');
  });
});

await new Promise((r) => app.listen(0, '127.0.0.1', r));
const port = app.address().port;
const appUrl = `http://127.0.0.1:${port}`;

// 2. Any AI agent pays your app automatically in 3 lines:
const agent = generateKeyPair();
const client = new VectollAgentClient({
  agentKeyPair: agent,
  facilitatorUrl: `${appUrl}/_vectoll`,
  preferredRail: 'stripe',
});

await client.topUp({ amount: '$1.00', rail: 'stripe' });
const res = await client.fetch(`${appUrl}/api/weather`);
console.log('Single-Port App Response:', await res.json());

app.close();
