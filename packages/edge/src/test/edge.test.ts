import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { parseVectollConfig } from '@vectoll/core';
import { createVectollEdgeHandler, RedisReplayStore, ReplayStore } from '../index.js';

describe('@vectoll/edge Fetch handler & ReplayStore', () => {
  it('enforces single-use JTI replay consumption and serves /.well-known/vectoll.json', async () => {
    const store = new ReplayStore();
    assert.equal(store.consume('vrt_test_1', 9999999999, 1795753800), true);
    assert.equal(store.consume('vrt_test_1', 9999999999, 1795753801), false);

    const cfg = parseVectollConfig(`
version: "1.0"
service:
  name: "edge-test-service"
  origin: "http://127.0.0.1:9999"
settlement:
  facilitator_url: "http://127.0.0.1:4021"
  facilitator_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  default_currency: "UGX"
  accepted_rails:
    - "momo"
routes:
  - path: "/paid"
    method: "GET"
    price: 50
`);
    const handler = createVectollEdgeHandler({ config: cfg });
    const discRes = await handler(new Request('https://example.com/.well-known/vectoll.json'));
    assert.equal(discRes.status, 200);
    const manifest = (await discRes.json()) as { vectollVersion: string };
    assert.equal(manifest.vectollVersion, '0.1');

    const chgRes = await handler(new Request('https://example.com/paid', { headers: { 'User-Agent': 'GPTBot/1.0' } }));
    assert.equal(chgRes.status, 402);
    assert.ok(chgRes.headers.get('payment-required'));
  });

  it('enforces distributed JTI replay rejection over TCP RESP2 RedisReplayStore', async () => {
    const keys = new Set<string>();
    const mockRedis = net.createServer((socket) => {
      socket.on('data', (buf) => {
        const text = buf.toString('utf8');
        if (text.includes('AUTH')) {
          socket.write('+OK\r\n');
        }
        // Extract key after vectoll:jti:
        const m = text.match(/vectoll:jti:[A-Za-z0-9_-]+/);
        if (m) {
          const key = m[0];
          if (keys.has(key)) {
            socket.write('$-1\r\n');
          } else {
            keys.add(key);
            socket.write('+OK\r\n');
          }
        }
      });
    });

    await new Promise<void>((r) => mockRedis.listen(0, '127.0.0.1', r));
    const port = (mockRedis.address() as net.AddressInfo).port;

    try {
      const store = new RedisReplayStore(`redis://:secretpass@127.0.0.1:${port}`);
      assert.equal(await store.consume('vrt_dist_001', 1795760900, 1795760000), true);
      assert.equal(await store.consume('vrt_dist_001', 1795760900, 1795760001), false);
      assert.equal(await store.consume('vrt_dist_002', 1795760900, 1795760001), true);
    } finally {
      mockRedis.close();
    }
  });
});
