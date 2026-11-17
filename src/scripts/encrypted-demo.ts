/* eslint-disable no-console */
import { sealRequest } from '#src/common/utils/e2e-client.ts';

// Demonstrates the end-to-end encrypted protocol against a running server:
//   npm run demo:encrypted -- http://localhost:3000 demo@jstack.co Demo@123
// Prints what travels on the wire next to what the app sees after decrypting.

const [
  baseUrl = 'http://localhost:3000',
  email = 'demo@jstack.co',
  password = 'Demo@123',
] = process.argv.slice(2);

interface KeyInfo {
  body: { kid: string; publicKey: string };
}

const keyRes = await fetch(`${baseUrl}/api/v1/security/encryption-key`);
const { body: serverKey } = (await keyRes.json()) as KeyInfo;
console.log(`Server key: ${serverKey.kid}\n`);

async function call(
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
  token?: string,
): Promise<unknown> {
  const sealed = sealRequest({
    serverPublicKeyBase64: serverKey.publicKey,
    kid: serverKey.kid,
    method,
    originalUrl: path,
    body,
  });
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...sealed.headers,
      ...(sealed.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(sealed.body ? { body: JSON.stringify(sealed.body) } : {}),
  });
  const wire = await res.json();
  const data = sealed.openResponse(res.status, wire);
  console.log(`${method} ${path} -> ${res.status}`);
  if (sealed.body) {
    console.log(`  sent on wire:     ${sealed.body.payload.slice(0, 60)}...`);
  }
  console.log(
    `  received on wire: ${String((wire as { payload: string }).payload).slice(0, 60)}...`,
  );
  console.log(`  decrypted:        ${JSON.stringify(data).slice(0, 160)}\n`);
  return data;
}

const login = (await call('POST', '/api/v1/auth/login', {
  email,
  password,
})) as { body: { accessToken?: string } };

if (login.body.accessToken) {
  await call(
    'GET',
    '/api/v1/wallet/balance',
    undefined,
    login.body.accessToken,
  );
  await call(
    'GET',
    '/api/v1/transactions?limit=2',
    undefined,
    login.body.accessToken,
  );
}
