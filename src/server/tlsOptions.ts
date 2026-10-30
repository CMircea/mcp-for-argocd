import { readFileSync } from 'node:fs';
import { logger } from '../logging/logging.js';
import { TlsOptions } from '../argocd/http.js';

type TlsEnv = Record<string, string | undefined>;

const readTlsFile = (envVar: string, path: string): Buffer => {
  try {
    return readFileSync(path);
  } catch (error) {
    throw new Error(
      `Failed to read ${envVar} at "${path}": ${error instanceof Error ? error.message : String(error)}`
    );
  }
};

// Build the outbound TLS options for the ArgoCD connection from env vars:
//
//   ARGOCD_CLIENT_CERT_PATH + ARGOCD_CLIENT_KEY_PATH  PEM client certificate and key
//   ARGOCD_CLIENT_PFX_PATH                           PKCS#12 bundle (alternative to PEM)
//   ARGOCD_CLIENT_KEY_PASSPHRASE                     decrypts the PEM key or the PFX
//   ARGOCD_CA_CERT_PATH                              extra CA to trust (PEM)
//
// Returns undefined when none are set, leaving fetch's default TLS behavior
// untouched. Fails closed on an incomplete or contradictory configuration, so
// the process crashes at startup rather than connecting without the client
// certificate the operator meant to present.
export const tlsOptionsFromEnv = (env: TlsEnv = process.env): TlsOptions | undefined => {
  const certPath = env.ARGOCD_CLIENT_CERT_PATH?.trim();
  const keyPath = env.ARGOCD_CLIENT_KEY_PATH?.trim();
  const pfxPath = env.ARGOCD_CLIENT_PFX_PATH?.trim();
  const passphrase = env.ARGOCD_CLIENT_KEY_PASSPHRASE;
  const caPath = env.ARGOCD_CA_CERT_PATH?.trim();

  const hasPem = Boolean(certPath || keyPath);
  const hasPfx = Boolean(pfxPath);

  if (hasPem && hasPfx) {
    throw new Error(
      'Both ARGOCD_CLIENT_CERT_PATH/ARGOCD_CLIENT_KEY_PATH and ARGOCD_CLIENT_PFX_PATH are set; configure only one form of client identity.'
    );
  }
  if (hasPem && (!certPath || !keyPath)) {
    throw new Error('ARGOCD_CLIENT_CERT_PATH and ARGOCD_CLIENT_KEY_PATH must be set together.');
  }
  if (passphrase && !hasPem && !hasPfx) {
    throw new Error(
      'ARGOCD_CLIENT_KEY_PASSPHRASE is set but no client certificate (PEM pair or PFX) was configured.'
    );
  }

  if (!hasPem && !hasPfx && !caPath) {
    return undefined;
  }

  const tls: TlsOptions = {};
  if (certPath && keyPath) {
    tls.cert = readTlsFile('ARGOCD_CLIENT_CERT_PATH', certPath);
    tls.key = readTlsFile('ARGOCD_CLIENT_KEY_PATH', keyPath);
  }
  if (pfxPath) tls.pfx = readTlsFile('ARGOCD_CLIENT_PFX_PATH', pfxPath);
  if (passphrase) tls.passphrase = passphrase;
  if (caPath) tls.ca = readTlsFile('ARGOCD_CA_CERT_PATH', caPath);

  logger.info(
    `Loaded ArgoCD TLS options: client certificate ${
      hasPem ? '(PEM)' : hasPfx ? '(PFX)' : 'none'
    }, extra CA ${caPath ? 'yes' : 'no'}`
  );
  return tls;
};
