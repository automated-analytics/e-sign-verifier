/**
 * The pinned TSA trust anchor (the cross-signed DigiCert Trusted Root G4), embedded at BUILD time
 * from the single source of truth the api verifier pins: `api/app/assets/digicert_trusted_root_g4.pem`
 * (see `ui/scripts/build-verifier.mjs` and `ui/vitest.config.ts`, which `define` this constant).
 * There is deliberately no second copy in the repo to drift, and no runtime fetch: a saved copy
 * of the page carries its trust anchor with it.
 */

import { b64decodePy } from "./bytes";

declare const __PINNED_TSA_ROOT_PEM__: string;

export const PINNED_TSA_ROOT_PEM: string = __PINNED_TSA_ROOT_PEM__;

/** The DER bytes of the first CERTIFICATE block in a PEM string. */
export function pemToDer(pem: string): Uint8Array {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  if (!m) throw new Error("no CERTIFICATE block in PEM");
  return b64decodePy(m[1]);
}
