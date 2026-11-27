import crypto from 'node:crypto';
import type { JsonWebKeyEd25519, VectollKeyPair } from './types.js';

// RFC 8410 ASN.1 DER prefixes for Ed25519
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const DID_KEY_ED25519_PREFIX = new Uint8Array([0xed, 0x01]);
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base64UrlEncode(data: Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return buf.toString('base64url');
}

export function base64UrlDecode(encoded: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(encoded)) {
    throw new Error('Invalid base64url characters');
  }
  return new Uint8Array(Buffer.from(encoded, 'base64url'));
}

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let zeroes = 0;
  while (zeroes < bytes.length && bytes[zeroes] === 0) {
    zeroes++;
  }
  let num = 0n;
  for (const b of bytes) {
    num = (num << 8n) + BigInt(b);
  }
  const chars: string[] = [];
  while (num > 0n) {
    const rem = Number(num % 58n);
    num = num / 58n;
    chars.push(BASE58_ALPHABET[rem]!);
  }
  for (let i = 0; i < zeroes; i++) {
    chars.push('1');
  }
  return chars.reverse().join('');
}

export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);
  let zeroes = 0;
  while (zeroes < str.length && str[zeroes] === '1') {
    zeroes++;
  }
  let num = 0n;
  for (let i = zeroes; i < str.length; i++) {
    const idx = BASE58_ALPHABET.indexOf(str[i]!);
    if (idx === -1) {
      throw new Error(`Invalid base58 character: ${str[i]}`);
    }
    num = num * 58n + BigInt(idx);
  }
  const byteList: number[] = [];
  while (num > 0n) {
    byteList.push(Number(num & 0xffn));
    num >>= 8n;
  }
  byteList.reverse();
  const out = new Uint8Array(zeroes + byteList.length);
  out.set(byteList, zeroes);
  return out;
}

export function publicKeyToDidKey(publicKeyBytes: Uint8Array): string {
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKeyBytes.length}`);
  }
  const prefixed = new Uint8Array(34);
  prefixed.set(DID_KEY_ED25519_PREFIX, 0);
  prefixed.set(publicKeyBytes, 2);
  return `did:key:z${base58Encode(prefixed)}`;
}

export function didKeyToPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Unsupported DID format: ${did}`);
  }
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error(`Invalid Ed25519 multicodec prefix in DID: ${did}`);
  }
  return decoded.slice(2);
}

export function keyPairFromSeed(seed: Uint8Array | string, kid?: string): VectollKeyPair {
  const seedBytes =
    typeof seed === 'string'
      ? /^[0-9a-fA-F]{64}$/.test(seed)
        ? new Uint8Array(Buffer.from(seed, 'hex'))
        : base64UrlDecode(seed)
      : new Uint8Array(seed);

  if (seedBytes.length !== 32) {
    throw new Error(`Ed25519 seed must be exactly 32 bytes, got ${seedBytes.length}`);
  }

  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seedBytes)]);
  const privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const spkiDer = pubKeyObj.export({ format: 'der', type: 'spki' }) as Buffer;
  const pubBytes = new Uint8Array(spkiDer.subarray(ED25519_SPKI_PREFIX.length));

  const did = publicKeyToDidKey(pubBytes);
  const resolvedKid = kid ?? `key-${Buffer.from(pubBytes.subarray(0, 6)).toString('hex')}`;

  return {
    kid: resolvedKid,
    did,
    seedHex: Buffer.from(seedBytes).toString('hex'),
    publicKeyBase64Url: base64UrlEncode(pubBytes),
    privateSeedBytes: seedBytes,
    publicKeyBytes: pubBytes,
  };
}

export function generateKeyPair(kid?: string): VectollKeyPair {
  const seed = new Uint8Array(crypto.randomBytes(32));
  return keyPairFromSeed(seed, kid);
}

export function ed25519Sign(privateSeedBytes: Uint8Array, message: Uint8Array | string): Uint8Array {
  if (privateSeedBytes.length !== 32) {
    throw new Error('Ed25519 private seed must be 32 bytes');
  }
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateSeedBytes)]);
  const privKeyObj = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const msgBuf = typeof message === 'string' ? Buffer.from(message, 'utf8') : Buffer.from(message);
  return new Uint8Array(crypto.sign(null, msgBuf, privKeyObj));
}

export function ed25519Verify(
  publicKey: Uint8Array | string,
  message: Uint8Array | string,
  signature: Uint8Array | string,
): boolean {
  try {
    const pubBytes =
      typeof publicKey === 'string'
        ? publicKey.startsWith('did:key:z')
          ? didKeyToPublicKey(publicKey)
          : base64UrlDecode(publicKey)
        : publicKey;
    if (pubBytes.length !== 32) return false;

    const sigBytes = typeof signature === 'string' ? base64UrlDecode(signature) : signature;
    if (sigBytes.length !== 64) return false;

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubBytes)]);
    const pubKeyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    const msgBuf = typeof message === 'string' ? Buffer.from(message, 'utf8') : Buffer.from(message);
    return crypto.verify(null, msgBuf, pubKeyObj, Buffer.from(sigBytes));
  } catch {
    return false;
  }
}

export function toPublicJwk(keyPair: Pick<VectollKeyPair, 'kid' | 'publicKeyBase64Url'>): JsonWebKeyEd25519 {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    kid: keyPair.kid,
    use: 'sig',
    alg: 'EdDSA',
    x: keyPair.publicKeyBase64Url,
  };
}

export function sha256Hex(data: Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function computeRequestHash(
  method: string,
  target: string,
  body: Uint8Array | string = new Uint8Array(0),
): string {
  const normalizedMethod = method.trim().toUpperCase();
  const normalizedTarget = target.startsWith('/') ? target : `/${target}`;
  const bodyHashHex = sha256Hex(body);
  const canonical = `${normalizedMethod}\n${normalizedTarget}\n${bodyHashHex}`;
  return `sha256:${sha256Hex(canonical)}`;
}

export function randomId(prefix: string, byteLen = 12): string {
  return `${prefix}_${crypto.randomBytes(byteLen).toString('hex')}`;
}
