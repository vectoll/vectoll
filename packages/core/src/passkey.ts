import crypto from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, randomId } from './crypto.js';
import { assertSafeMinorAmount, type SpendMandateClaims } from './types.js';

// W3C WebAuthn AuthenticatorData flag bit 0: User Present (UP)
const WEBAUTHN_FLAG_UP = 0x01;
// W3C WebAuthn AuthenticatorData flag bit 2: User Verified (UV — biometric/PIN)
const WEBAUTHN_FLAG_UV = 0x04;

export interface WebAuthnAssertionProof {
  /** Base64url SPKI DER P-256 public key of the hardware Passkey */
  publicKeySpkiB64Url: string;
  /** Credential ID (base64url) */
  credentialId: string;
  /** Raw WebAuthn authenticatorData bytes (base64url, >= 37 bytes) */
  authenticatorDataB64Url: string;
  /** Raw WebAuthn clientDataJSON UTF-8 bytes (base64url) */
  clientDataJsonB64Url: string;
  /** ECDSA P-256 SHA-256 DER signature over authenticatorData || SHA256(clientDataJSON) */
  signatureDerB64Url: string;
}

export interface PasskeyKeyPair {
  credentialId: string;
  principalDid: string;
  publicKeySpkiB64Url: string;
  privateKeyPem: string;
}

/**
 * Generates an ECDSA NIST P-256 (`prime256v1` / `ES256`) keypair matching W3C WebAuthn Passkeys.
 */
export function generatePasskeyKeyPair(credentialId = randomId('cred', 10)): PasskeyKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  const spkiDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const spkiB64 = base64UrlEncode(spkiDer);
  const fingerprint = crypto.createHash('sha256').update(spkiDer).digest('hex').slice(0, 32);
  return {
    credentialId,
    principalDid: `did:passkey:${fingerprint}`,
    publicKeySpkiB64Url: spkiB64,
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }) as string,
  };
}

/**
 * Computes the deterministic WebAuthn challenge bound to a Spend Mandate payload:
 *   base64url(SHA-256("vsm1-passkey." + payloadB64Url))
 */
export function computePasskeyMandateChallenge(payloadB64Url: string): string {
  const digest = crypto.createHash('sha256').update(`vsm1-passkey.${payloadB64Url}`, 'utf8').digest();
  return base64UrlEncode(digest);
}

/**
 * Issues a W3C WebAuthn / FIDO2 (`ES256` P-256) signed Spend Mandate (`vsm1p.<payload>.<proof>`).
 * Browser UIs construct the proof from `navigator.credentials.get()`; Node callers/tests can sign directly.
 */
export function createPasskeySpendMandate(input: {
  passkey: PasskeyKeyPair;
  agentId: string;
  origin?: string;
  mandateId?: string;
  currency: string;
  decimals: number;
  maxPerCall: number;
  maxDaily: number;
  allowedServices?: string[];
  allowedRails?: string[];
  hitlThreshold?: number | null;
  purpose?: string;
  issuedAt?: number;
  expiresAt?: number;
}): { token: string; claims: SpendMandateClaims } {
  assertSafeMinorAmount(input.maxPerCall, 'maxPerCall');
  assertSafeMinorAmount(input.maxDaily, 'maxDaily');
  if (input.maxPerCall <= 0 || input.maxDaily < input.maxPerCall) {
    throw new Error('Passkey spend mandate requires 0 < maxPerCall <= maxDaily');
  }

  const now = input.issuedAt ?? Math.floor(Date.now() / 1000);
  const claims: SpendMandateClaims = {
    v: 1,
    mandateId: input.mandateId ?? randomId('mnd', 10),
    principalId: input.passkey.principalDid,
    agentId: input.agentId,
    currency: input.currency.toUpperCase(),
    decimals: input.decimals,
    maxPerCall: input.maxPerCall,
    maxDaily: input.maxDaily,
    allowedServices: input.allowedServices ?? ['*'],
    allowedRails: input.allowedRails ?? ['*'],
    hitlThreshold: input.hitlThreshold ?? null,
    ...(input.purpose ? { purpose: input.purpose } : {}),
    issuedAt: now,
    expiresAt: input.expiresAt ?? now + 86400 * 30,
  };

  const payloadB64 = base64UrlEncode(JSON.stringify(claims));
  const challenge = computePasskeyMandateChallenge(payloadB64);
  const origin = input.origin ?? 'https://console.vectoll.org';
  const rpId = new URL(origin).hostname;

  // Build authentic 37-byte W3C authenticatorData: SHA256(rpId) (32B) || flags (1B: UP|UV) || signCount (4B)
  const rpIdHash = crypto.createHash('sha256').update(rpId, 'utf8').digest();
  const flags = Buffer.from([WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV]);
  const signCount = Buffer.alloc(4);
  signCount.writeUInt32BE(1, 0);
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCount]);

  const clientDataJSON = JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin,
    crossOrigin: false,
  });
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON, 'utf8').digest();
  const signedData = Buffer.concat([authenticatorData, clientDataHash]);

  const privKey = crypto.createPrivateKey(input.passkey.privateKeyPem);
  const sigDer = crypto.sign('sha256', signedData, privKey);

  const proof: WebAuthnAssertionProof = {
    publicKeySpkiB64Url: input.passkey.publicKeySpkiB64Url,
    credentialId: input.passkey.credentialId,
    authenticatorDataB64Url: base64UrlEncode(authenticatorData),
    clientDataJsonB64Url: base64UrlEncode(clientDataJSON),
    signatureDerB64Url: base64UrlEncode(sigDer),
  };

  const proofB64 = base64UrlEncode(JSON.stringify(proof));
  return {
    token: `vsm1p.${payloadB64}.${proofB64}`,
    claims,
  };
}

/**
 * Verifies a W3C WebAuthn / FIDO2 (`ES256` P-256) Spend Mandate assertion (`vsm1p.<payload>.<proof>`).
 */
export function verifyPasskeyAssertion(
  payloadB64Url: string,
  proofB64Url: string,
  expectedPrincipalDid: string,
): { valid: boolean; reason?: string } {
  try {
    const proof = JSON.parse(
      Buffer.from(base64UrlDecode(proofB64Url)).toString('utf8'),
    ) as WebAuthnAssertionProof;

    const spkiDer = Buffer.from(base64UrlDecode(proof.publicKeySpkiB64Url));
    const expectedDid = `did:passkey:${crypto.createHash('sha256').update(spkiDer).digest('hex').slice(0, 32)}`;
    if (expectedPrincipalDid !== expectedDid) {
      return { valid: false, reason: 'Passkey public key fingerprint does not match principalId' };
    }

    const authData = Buffer.from(base64UrlDecode(proof.authenticatorDataB64Url));
    if (authData.length < 37) {
      return { valid: false, reason: 'WebAuthn authenticatorData shorter than 37 bytes' };
    }
    const flags = authData[32]!;
    if ((flags & WEBAUTHN_FLAG_UP) === 0) {
      return { valid: false, reason: 'WebAuthn User Present (UP) flag not set' };
    }

    const clientDataBytes = Buffer.from(base64UrlDecode(proof.clientDataJsonB64Url));
    const clientData = JSON.parse(clientDataBytes.toString('utf8')) as {
      type?: string;
      challenge?: string;
    };
    if (clientData.type !== 'webauthn.get') {
      return { valid: false, reason: `Unexpected WebAuthn type: ${String(clientData.type)}` };
    }
    const expectedChallenge = computePasskeyMandateChallenge(payloadB64Url);
    if (clientData.challenge !== expectedChallenge) {
      return { valid: false, reason: 'WebAuthn clientDataJSON challenge mismatch' };
    }

    const clientDataHash = crypto.createHash('sha256').update(clientDataBytes).digest();
    const signedBytes = Buffer.concat([authData, clientDataHash]);
    const pubKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    const sigDer = Buffer.from(base64UrlDecode(proof.signatureDerB64Url));

    const ok = crypto.verify('sha256', signedBytes, pubKey, sigDer);
    return ok ? { valid: true } : { valid: false, reason: 'ECDSA P-256 Passkey signature invalid' };
  } catch (err) {
    return {
      valid: false,
      reason: `Malformed WebAuthn Passkey proof: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
