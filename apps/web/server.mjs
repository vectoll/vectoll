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

function createSiteServer(siteDir, siteName) {
  return http.createServer((req, res) => {
    const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = decodeURIComponent(reqUrl.pathname);

    if (pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, site: siteName }));
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
  console.log(`[vectoll.org] Open Protocol site  -> http://${HOST}:${ORG_PORT}`);
});
comServer.listen(COM_PORT, HOST, () => {
  console.log(`[vectoll.com] Vectoll Cloud site  -> http://${HOST}:${COM_PORT}`);
});

function shutdown() {
  orgServer.close();
  comServer.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
