// @@@SNIPSTART typescript-encryption-codec
import { webcrypto as crypto } from 'node:crypto';
import { METADATA_ENCODING_KEY, Payload, PayloadCodec, ValueError } from '@temporalio/common';
import { temporal } from '@temporalio/proto';
import { decode, encode } from '@temporalio/common/lib/encoding';
import { decrypt, encrypt } from './crypto';

const ENCODING = 'binary/encrypted';
const METADATA_ENCRYPTION_KEY_ID = 'encryption-key-id';
const DEFAULT_ENCRYPTION_KEY = 'sa-rocks!sa-rocks!sa-rocks!yeah!';

function isValidAesKeyLength(length: number): boolean {
  return length === 16 || length === 24 || length === 32;
}

function tryDecodeBase64(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/=]+$/.test(value) || value.length % 4 !== 0) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  if (!isValidAesKeyLength(decoded.length)) {
    return null;
  }
  const normalized = value.replace(/=+$/, '');
  const reencoded = decoded.toString('base64').replace(/=+$/, '');
  if (normalized !== reencoded) {
    return null;
  }
  return decoded;
}

function resolveEncryptionKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY?.trim();
  if (!raw) {
    return Buffer.from(DEFAULT_ENCRYPTION_KEY, 'utf8');
  }

  if (raw.startsWith('base64:')) {
    const decoded = Buffer.from(raw.slice('base64:'.length), 'base64');
    if (!isValidAesKeyLength(decoded.length)) {
      throw new Error(`ENCRYPTION_KEY base64 payload must be 16, 24, or 32 bytes; got ${decoded.length}.`);
    }
    return decoded;
  }

  const direct = Buffer.from(raw, 'utf8');
  if (isValidAesKeyLength(direct.length)) {
    return direct;
  }

  const decoded = tryDecodeBase64(raw);
  if (decoded) {
    return decoded;
  }

  throw new Error(
    `ENCRYPTION_KEY must be 16, 24, or 32 bytes (raw) or a valid base64 string for those lengths. Got ${direct.length} bytes.`
  );
}

export class EncryptionCodec implements PayloadCodec {
  constructor(protected readonly keys: Map<string, crypto.CryptoKey>, protected readonly defaultKeyId: string) {}

  static async create(keyId: string): Promise<EncryptionCodec> {
    const keys = new Map<string, crypto.CryptoKey>();
    keys.set(keyId, await fetchKey(keyId));
    return new this(keys, keyId);
  }

  async encode(payloads: Payload[]): Promise<Payload[]> {
    return Promise.all(
      payloads.map(async (payload) => ({
        metadata: {
          [METADATA_ENCODING_KEY]: encode(ENCODING),
          [METADATA_ENCRYPTION_KEY_ID]: encode(this.defaultKeyId),
        },
        // Encrypt entire payload, preserving metadata
        data: await encrypt(
          temporal.api.common.v1.Payload.encode(payload).finish(),
          this.keys.get(this.defaultKeyId)! // eslint-disable-line @typescript-eslint/no-non-null-assertion
        ),
      }))
    );
  }

  async decode(payloads: Payload[]): Promise<Payload[]> {
    return Promise.all(
      payloads.map(async (payload) => {
        if (!payload.metadata || decode(payload.metadata[METADATA_ENCODING_KEY]) !== ENCODING) {
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
        let key = this.keys.get(keyId);
        if (!key) {
          key = await fetchKey(keyId);
          this.keys.set(keyId, key);
        }
        const decryptedPayloadBytes = await decrypt(payload.data, key);
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

async function fetchKey(_keyId: string): Promise<crypto.CryptoKey> {
  // In production, fetch key from a key management system (KMS). You may want to memoize requests if you'll be decoding
  // Payloads that were encrypted using keys other than defaultKeyId.
  const key = resolveEncryptionKey();
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
