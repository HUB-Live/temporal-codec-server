import { config } from 'dotenv';
import { resolve } from 'path';
import express from 'express';
import * as proto from '@temporalio/proto';
import { EncryptionCodec } from './encryption-codec';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { JwtHeader, VerifyOptions } from 'jsonwebtoken';
import jwksClient, { RsaSigningKey, SigningKey } from "jwks-rsa";

// most of this code is from the Temporal samples repo
// https://github.com/temporalio/samples-typescript/blob/main/encryption/src/codec-server.ts

type Payload = proto.temporal.api.common.v1.IPayload;

interface JSONPayload {
    metadata?: Record<string, string> | null;
    data?: string | null;
}

interface Body {
    payloads: JSONPayload[];
}

const path = process.env.NODE_ENV === 'production'
    ? resolve(__dirname, './.env.production')
    : resolve(__dirname, './.env.development');

config({ path });

console.log(process.env.NODE_ENV);

const DEFAULT_JWKS_URI = 'https://prod-tmprl.us.auth0.com/.well-known/jwks.json';
const DEFAULT_CORS_ORIGIN = 'https://cloud.temporal.io';
const DEFAULT_CORS_HEADERS = ['x-namespace', 'content-type', 'authorization'];
const DEFAULT_CORS_METHODS = ['POST', 'OPTIONS', 'GET'];
const DEFAULT_ENCRYPTION_KEY_ID = 'c2EtZGVtby1rZXk=';

function parseCsv(value?: string): string[] | undefined {
    if (!value) {
        return undefined;
    }
    const parts = value
        .split(',')
        .map((part) => part.trim())
        .filter(Boolean);
    return parts.length > 0 ? parts : undefined;
}

function wildcardToRegex(pattern: string): RegExp {
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    const regex = `^${escaped.replace(/\*/g, '.*')}$`;
    return new RegExp(regex, 'i');
}

function buildCorsOrigin(raw?: string): cors.CorsOptions['origin'] {
    if (!raw || raw.trim() === '') {
        return DEFAULT_CORS_ORIGIN;
    }

    const normalized = raw.trim();
    const lower = normalized.toLowerCase();
    if (lower === '*' || lower === 'true' || lower === 'all' || lower === 'any') {
        return true;
    }

    const origins = parseCsv(normalized) ?? [];
    if (origins.length === 0) {
        return DEFAULT_CORS_ORIGIN;
    }

    const hasWildcard = origins.some((origin) => origin.includes('*'));
    if (!hasWildcard) {
        return origins.length === 1 ? origins[0] : origins;
    }

    const patterns = origins.map((origin) => wildcardToRegex(origin));
    return (origin, callback) => {
        if (!origin) {
            return callback(null, true);
        }
        const allowed = patterns.some((pattern) => pattern.test(origin));
        return callback(null, allowed);
    };
}

const port = Number.parseInt(process.env.PORT ?? '', 10);
const listenPort = Number.isFinite(port) ? port : 3000;

const jwksUri = process.env.JWKS_URI || DEFAULT_JWKS_URI;
const corsOrigin = buildCorsOrigin(process.env.CORS_ALLOW_ORIGINS);
const corsAllowedHeaders = parseCsv(process.env.CORS_ALLOW_HEADERS) ?? DEFAULT_CORS_HEADERS;
const corsAllowedMethods = parseCsv(process.env.CORS_ALLOW_METHODS) ?? DEFAULT_CORS_METHODS;
const encryptionKeyId = process.env.ENCRYPTION_KEY_ID || DEFAULT_ENCRYPTION_KEY_ID;

const client = jwksClient({ jwksUri });

// get JWT signing key
function getKey(header: JwtHeader, callback: (err: Error | null, key?: string | Buffer) => void): void {
    client.getSigningKey(header.kid as string, (err: Error | null, key?: SigningKey) => {
        callback(err, key?.getPublicKey());
    });
}

/**
 * Helper function to convert a valid proto JSON to a payload object.
 *
 * This method will be part of the SDK when it supports proto JSON serialization.
 */
function fromJSON({ metadata, data }: JSONPayload): Payload {
    return {
        metadata:
            metadata &&
            Object.fromEntries(Object.entries(metadata).map(([k, v]): [string, Uint8Array] => [k, Buffer.from(v, 'base64')])),
        data: data ? Buffer.from(data, 'base64') : undefined,
    };
}

/**
 * Helper function to convert a payload object to a valid proto JSON.
 *
 * This method will be part of the SDK when it supports proto JSON serialization.
 */
function toJSON({ metadata, data }: proto.temporal.api.common.v1.IPayload): JSONPayload {
    return {
        metadata:
            metadata &&
            Object.fromEntries(
                Object.entries(metadata).map(([k, v]): [string, string] => [k, Buffer.from(v).toString('base64')])
            ),
        data: data ? Buffer.from(data).toString('base64') : undefined,
    };
}

async function main() {

    const codec = await EncryptionCodec.create(encryptionKeyId);

    const app = express();
    app.use(cors({
        origin: corsOrigin, // Or true to allow any origin
        allowedHeaders: corsAllowedHeaders, // Added 'authorization'
        methods: corsAllowedMethods,
        credentials: true // This is the important line
    }));
    app.use(express.json());

    app.post('/decode', async (req, res) => {
        console.log(`Received request to /decode`);
        console.log('Request headers:', req.headers);
        console.log('Request body:', req.body);
        
        const authHeader = req.headers.authorization;
        console.log(`Auth header: ${authHeader}`);

        const printToken = authHeader ? authHeader.split(' ')[1] : undefined;
        console.log(`Authorization token: ${printToken}`);

        // if auth header doesn't exist or doesn't start with 'Bearer ' then reject
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).end('Unauthorized');
        }

        // verify the signature on this access token (in your authorization header) against the JWKS endpoint
        const token = authHeader.split(' ')[1];
        jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
            if (err) {
                console.error('Failed to verify token:', err);
                return res.status(403).end('Invalid token');
            }

            console.log('Decoded JWT:', decoded);  // This will print the payload of the JWT

            // Here you can use the claims in `decoded` to identify the user and authorize their request.
        });

        try {
            const { payloads: raw } = req.body as Body;
            const encoded = raw.map(fromJSON);
            const decoded = await codec.decode(encoded);
            const payloads = decoded.map(toJSON);
            res.json({ payloads }).end();
        } catch (err) {
            console.error('Error in /decode', err);
            res.status(500).end('Internal server error');
        }
    });

    app.post('/encode', async (req, res) => {
        try {
            const { payloads: raw } = req.body as Body;
            const decoded = raw.map(fromJSON);
            const encoded = await codec.encode(decoded);
            const payloads = encoded.map(toJSON);
            res.json({ payloads }).end();
        } catch (err) {
            console.error('Error in /encode', err);
            res.status(500).end('Internal server error');
        }
    });

    app.get('/', (req, res) => {
        res.send(`Hi from the Temporal Codec Server`);
    });

    await new Promise<void>((resolve, reject) => {
        app.listen(listenPort, () => {
            console.log(`Codec Server listening at http://localhost:${listenPort}`);
        });
        app.on('error', reject);
    });

}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
