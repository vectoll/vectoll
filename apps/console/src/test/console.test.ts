import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { renderConsoleHtml } from '../index.js';

describe('@vectoll/console Global Command Center renderer', () => {
  it('renders global simulator, FX calculator, Escrow table, HITL queue, and CSV/JSON exports', () => {
    const html = renderConsoleHtml({
      facilitatorUrl: 'http://127.0.0.1:4021',
      gateUrl: 'http://127.0.0.1:4020',
    });
    assert.match(html, /VECTOLL GLOBAL CONSOLE/);
    assert.match(html, /Interactive Global Agent & MCP Simulator/);
    assert.match(html, /Global Integer FX Quoting Engine/);
    assert.match(html, /Human-in-the-Loop \(HITL\) Approval Queue/);
    assert.match(html, /Double-Entry Immutable Audit Ledger/);
  });
});
