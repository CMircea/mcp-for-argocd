import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tlsOptionsFromEnv } from './tlsOptions.js';

// Helper: write each named file into a throwaway directory and return their
// paths. The directory is removed when `cleanup` is called. The loader only
// reads bytes, so the contents need not be real certificates.
const withTempFiles = (
  files: Record<string, string>
): { paths: Record<string, string>; cleanup: () => void } => {
  const dir = mkdtempSync(join(tmpdir(), 'tls-options-test-'));
  const paths: Record<string, string> = {};
  for (const [name, contents] of Object.entries(files)) {
    paths[name] = join(dir, name);
    writeFileSync(paths[name], contents);
  }
  return { paths, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
};

test('returns undefined when no TLS env vars are set', () => {
  assert.equal(tlsOptionsFromEnv({}), undefined);
});

test('loads a PEM certificate and key', () => {
  const { paths, cleanup } = withTempFiles({ 'client.crt': 'CERT', 'client.key': 'KEY' });
  try {
    const tls = tlsOptionsFromEnv({
      ARGOCD_CLIENT_CERT_PATH: paths['client.crt'],
      ARGOCD_CLIENT_KEY_PATH: paths['client.key']
    });
    assert.equal(tls?.cert?.toString(), 'CERT');
    assert.equal(tls?.key?.toString(), 'KEY');
    assert.equal(tls?.pfx, undefined);
  } finally {
    cleanup();
  }
});

test('loads a PFX bundle with its passphrase', () => {
  const { paths, cleanup } = withTempFiles({ 'client.pfx': 'PFX' });
  try {
    const tls = tlsOptionsFromEnv({
      ARGOCD_CLIENT_PFX_PATH: paths['client.pfx'],
      ARGOCD_CLIENT_KEY_PASSPHRASE: 'secret'
    });
    assert.equal(tls?.pfx?.toString(), 'PFX');
    assert.equal(tls?.passphrase, 'secret');
    assert.equal(tls?.cert, undefined);
  } finally {
    cleanup();
  }
});

test('loads a CA certificate on its own', () => {
  const { paths, cleanup } = withTempFiles({ 'ca.crt': 'CA' });
  try {
    const tls = tlsOptionsFromEnv({ ARGOCD_CA_CERT_PATH: paths['ca.crt'] });
    assert.equal(tls?.ca?.toString(), 'CA');
    assert.equal(tls?.cert, undefined);
  } finally {
    cleanup();
  }
});

test('rejects a certificate without its key, and a key without its certificate', () => {
  assert.throws(
    () => tlsOptionsFromEnv({ ARGOCD_CLIENT_CERT_PATH: '/x/client.crt' }),
    /must be set together/
  );
  assert.throws(
    () => tlsOptionsFromEnv({ ARGOCD_CLIENT_KEY_PATH: '/x/client.key' }),
    /must be set together/
  );
});

test('rejects configuring both a PEM pair and a PFX bundle', () => {
  assert.throws(
    () =>
      tlsOptionsFromEnv({
        ARGOCD_CLIENT_CERT_PATH: '/x/client.crt',
        ARGOCD_CLIENT_KEY_PATH: '/x/client.key',
        ARGOCD_CLIENT_PFX_PATH: '/x/client.pfx'
      }),
    /only one form of client identity/
  );
});

test('rejects a passphrase without a client certificate', () => {
  assert.throws(
    () => tlsOptionsFromEnv({ ARGOCD_CLIENT_KEY_PASSPHRASE: 'secret' }),
    /no client certificate/
  );
});

test('fails closed, naming the env var, when a configured file cannot be read', () => {
  assert.throws(
    () => tlsOptionsFromEnv({ ARGOCD_CA_CERT_PATH: '/nonexistent/ca.crt' }),
    /Failed to read ARGOCD_CA_CERT_PATH at "\/nonexistent\/ca.crt"/
  );
});
