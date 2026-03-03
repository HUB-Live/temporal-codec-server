// @@@SNIPSTART typescript-encryption-codec
import { webcrypto as crypto, createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { METADATA_ENCODING_KEY, Payload, PayloadCodec, ValueError } from '@temporalio/common';
import { temporal } from '@temporalio/proto';
import { decode, encode } from '@temporalio/common/lib/encoding';
import { decrypt, encrypt } from './crypto';

const ENCODING = 'binary/encrypted';
const METADATA_ENCRYPTION_KEY_ID = 'encryption-key-id';
const DEFAULT_ENCRYPTION_KEY = 'sa-rocks!sa-rocks!sa-rocks!yeah!';
type EncryptionAlgorithm = 'aes-gcm' | 'fernet';

function isValidKeyLength(length: number, allowed: readonly number[]): boolean {
  return allowed.includes(length);
}

function formatAllowedLengths(allowed: readonly number[]): string {
  if (allowed.length === 1) {
    return `${allowed[0]}`;
  }
  if (allowed.length === 2) {
    return `${allowed[0]} or ${allowed[1]}`;
  }
  return `${allowed.slice(0, -1).join(', ')}, or ${allowed[allowed.length - 1]}`;
}

function tryDecodeBase64(value: string, allowedLengths: readonly number[]): Buffer | null {
  if (!/^[A-Za-z0-9+/=]+$/.test(value) || value.length % 4 !== 0) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  if (!isValidKeyLength(decoded.length, allowedLengths)) {
    return null;
  }
  const normalized = value.replace(/=+$/, '');
  const reencoded = decoded.toString('base64').replace(/=+$/, '');
  if (normalized !== reencoded) {
    return null;
  }
  return decoded;
}

function tryDecodeBase64Url(value: string, allowedLengths: readonly number[]): Buffer | null {
  const normalized = value.replace(/=+$/, '');
  if (!/^[A-Za-z0-9\-_]+$/.test(normalized)) {
    return null;
  }
  let padded = normalized.replace(/-/g, '+').replace(/_/g, '/');
  padded += '='.repeat((4 - (padded.length % 4)) % 4);
  const decoded = Buffer.from(padded, 'base64');
  if (!isValidKeyLength(decoded.length, allowedLengths)) {
    return null;
  }
  const reencoded = decoded
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (normalized !== reencoded) {
    return null;
  }
  return decoded;
}

function resolveEncryptionKey(allowedLengths: readonly number[], algorithmLabel: string): Buffer {
  const raw = process.env.ENCRYPTION_KEY?.trim();
  if (!raw) {
    return Buffer.from(DEFAULT_ENCRYPTION_KEY, 'utf8');
  }

  if (raw.startsWith('base64:')) {
    const decoded = Buffer.from(raw.slice('base64:'.length), 'base64');
    if (!isValidKeyLength(decoded.length, allowedLengths)) {
      throw new Error(
        `ENCRYPTION_KEY base64 payload must be ${formatAllowedLengths(allowedLengths)} bytes for ${algorithmLabel}; got ${decoded.length}.`
      );
    }
    return decoded;
  }

  const direct = Buffer.from(raw, 'utf8');
  if (isValidKeyLength(direct.length, allowedLengths)) {
    return direct;
  }

  const decoded = tryDecodeBase64(raw, allowedLengths);
  if (decoded) {
    return decoded;
  }

  const decodedUrl = tryDecodeBase64Url(raw, allowedLengths);
  if (decodedUrl) {
    return decodedUrl;
  }

  throw new Error(
    `ENCRYPTION_KEY must be ${formatAllowedLengths(allowedLengths)} bytes (raw) or a valid base64/base64url string for those lengths for ${algorithmLabel}. Got ${direct.length} bytes.`
  );
}

function isBase64UrlString(value: string): boolean {
  return /^[A-Za-z0-9\-_]+={0,2}$/.test(value);
}

function base64UrlDecode(value: string): Buffer {
  const trimmed = value.trim();
  if (!isBase64UrlString(trimmed)) {
    throw new Error('Invalid base64url string.');
  }
  const normalized = trimmed.replace(/=+$/, '');
  let padded = normalized.replace(/-/g, '+').replace(/_/g, '/');
  padded += '='.repeat((4 - (padded.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function base64UrlEncode(value: Uint8Array): string {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function getFernetKeys(key: Buffer): { signingKey: Buffer; encryptionKey: Buffer } {
  if (key.length !== 32) {
    throw new Error(`Fernet key must be 32 bytes; got ${key.length}.`);
  }
  return {
    signingKey: key.subarray(0, 16),
    encryptionKey: key.subarray(16, 32),
  };
}

function fernetEncrypt(plaintext: Uint8Array, key: Buffer): Uint8Array {
  const { signingKey, encryptionKey } = getFernetKeys(key);
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-128-cbc', encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);

  const version = Buffer.from([0x80]);
  const timestamp = Buffer.alloc(8);
  const seconds = Math.floor(Date.now() / 1000);
  timestamp.writeUInt32BE(0, 0);
  timestamp.writeUInt32BE(seconds >>> 0, 4);

  const body = Buffer.concat([version, timestamp, iv, ciphertext]);
  const hmac = createHmac('sha256', signingKey).update(body).digest();
  const token = base64UrlEncode(Buffer.concat([body, hmac]));
  return Buffer.from(token, 'utf8');
}

function fernetDecrypt(tokenData: Uint8Array, key: Buffer): Uint8Array {
  const { signingKey, encryptionKey } = getFernetKeys(key);
  const tokenString = Buffer.from(tokenData).toString('utf8').trim();
  let tokenBytes: Buffer;
  if (isBase64UrlString(tokenString)) {
    tokenBytes = base64UrlDecode(tokenString);
  } else {
    tokenBytes = Buffer.from(tokenData);
  }

  const minLength = 1 + 8 + 16 + 32;
  if (tokenBytes.length < minLength) {
    throw new ValueError(`Invalid Fernet token length: ${tokenBytes.length}.`);
  }

  const version = tokenBytes[0];
  if (version !== 0x80) {
    throw new ValueError(`Invalid Fernet token version: ${version}.`);
  }

  const hmacStart = tokenBytes.length - 32;
  const body = tokenBytes.subarray(0, hmacStart);
  const hmac = tokenBytes.subarray(hmacStart);
  const expectedHmac = createHmac('sha256', signingKey).update(body).digest();
  if (hmac.length !== expectedHmac.length || !timingSafeEqual(hmac, expectedHmac)) {
    throw new ValueError('Invalid Fernet token signature.');
  }

  const ivOffset = 1 + 8;
  const iv = body.subarray(ivOffset, ivOffset + 16);
  const ciphertext = body.subarray(ivOffset + 16);
  const decipher = createDecipheriv('aes-128-cbc', encryptionKey, iv);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return new Uint8Array(plaintext);
}

type KeyMaterial = crypto.CryptoKey | Buffer;

export class EncryptionCodec implements PayloadCodec {
  constructor(
    protected readonly keys: Map<string, KeyMaterial>,
    protected readonly defaultKeyId: string,
    protected readonly algorithm: EncryptionAlgorithm
  ) {}

  static async create(keyId: string, algorithm: EncryptionAlgorithm): Promise<EncryptionCodec> {
    const keys = new Map<string, KeyMaterial>();
    keys.set(keyId, await fetchKey(keyId, algorithm));
    return new this(keys, keyId, algorithm);
  }

  private async getKey(keyId: string): Promise<KeyMaterial> {
    let key = this.keys.get(keyId);
    if (!key) {
      key = await fetchKey(keyId, this.algorithm);
      this.keys.set(keyId, key);
    }
    return key;
  }

  private async getAesKey(keyId: string): Promise<crypto.CryptoKey> {
    const key = await this.getKey(keyId);
    if (Buffer.isBuffer(key)) {
      throw new Error('Expected AES-GCM key material, got Fernet key.');
    }
    return key;
  }

  private async getFernetKey(keyId: string): Promise<Buffer> {
    const key = await this.getKey(keyId);
    if (!Buffer.isBuffer(key)) {
      throw new Error('Expected Fernet key material, got AES-GCM key.');
    }
    return key;
  }

  async encode(payloads: Payload[]): Promise<Payload[]> {
    return Promise.all(
      payloads.map(async (payload) => ({
        metadata: {
          [METADATA_ENCODING_KEY]: encode(ENCODING),
          [METADATA_ENCRYPTION_KEY_ID]: encode(this.defaultKeyId),
        },
        // Encrypt entire payload, preserving metadata
        data: await (async () => {
          const bytes = temporal.api.common.v1.Payload.encode(payload).finish();
          if (this.algorithm === 'fernet') {
            const key = await this.getFernetKey(this.defaultKeyId);
            return fernetEncrypt(bytes, key);
          }
          const key = await this.getAesKey(this.defaultKeyId);
          return encrypt(bytes, key);
        })(),
      }))
    );
  }

  async decode(payloads: Payload[]): Promise<Payload[]> {
    return Promise.all(
      payloads.map(async (payload) => {
        if (!payload.metadata) {
          return payload;
        }

        const encodingBytes = payload.metadata[METADATA_ENCODING_KEY];
        if (!encodingBytes) {
          return payload;
        }

        let encoding: string;
        try {
          encoding = decode(encodingBytes);
        } catch (error) {
          console.warn('Invalid encoding metadata; skipping decode.', error);
          return payload;
        }

        if (encoding !== ENCODING) {
          return payload;
        }
        if (!payload.data) {
          throw new ValueError('Payload data is missing');
        }

        const keyIdBytes = payload.metadata[METADATA_ENCRYPTION_KEY_ID];
        if (!keyIdBytes) {
          console.warn('Missing encryption key id metadata; falling back to default key id.');
        }

        const keyId = keyIdBytes ? decode(keyIdBytes) : this.defaultKeyId;
        let decryptedPayloadBytes: Uint8Array;
        if (this.algorithm === 'fernet') {
          const key = await this.getFernetKey(keyId);
          decryptedPayloadBytes = fernetDecrypt(payload.data, key);
        } else {
          const key = await this.getAesKey(keyId);
          decryptedPayloadBytes = await decrypt(payload.data, key);
        }
        console.log('Decrypting payload.data:', payload.data);

        let decryptedPayload = temporal.api.common.v1.Payload.decode(decryptedPayloadBytes);
      
        // If Payload.data contains JSON data, redact any sensitive information
        if (decryptedPayload.data) {
          try {
            let payloadDataStr = new TextDecoder().decode(decryptedPayload.data);
            let payloadDataJson = JSON.parse(payloadDataStr);
            if (payloadDataJson.token === 'tok_visa') {
              console.log(`Found 'token' in payload. Redacting...`);
              payloadDataJson.token = '[REDACTED]';
              decryptedPayload.data = new TextEncoder().encode(JSON.stringify(payloadDataJson)); // Encode back to Uint8Array
            }
          } catch (error) {
            // If Payload.data can't be parsed as JSON, do nothing and proceed with the original decryptedPayload
          }
        }
  
        return decryptedPayload;

        // return temporal.api.common.v1.Payload.decode(decryptedPayloadBytes);
      })
    );
  }
}

async function fetchKey(_keyId: string, algorithm: EncryptionAlgorithm): Promise<KeyMaterial> {
  // In production, fetch key from a key management system (KMS). You may want to memoize requests if you'll be decoding
  // Payloads that were encrypted using keys other than defaultKeyId.
  if (algorithm === 'fernet') {
    return resolveEncryptionKey([32], 'fernet');
  }

  const key = resolveEncryptionKey([16, 24, 32], 'aes-gcm');
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'AES-GCM',
    },
    true,
    ['encrypt', 'decrypt']
  );

  return cryptoKey;
}
// @@@SNIPEND
