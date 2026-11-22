/**
 * Browser port of `api/app/core/timestamp_verify.py`: does the anchor's timestamp token bind the
 * Merkle root to trusted time?
 *
 * - `prod`: parse the RFC 3161 TimeStampToken (CMS SignedData over a TSTInfo), require the imprint
 *   to be sha256 over exactly `root`, a single SignerInfo whose responder cert is embedded and
 *   carries the timeStamping EKU, a valid RSA/PKCS#1 v1.5 SHA-256 signature over the re-tagged
 *   signed attributes whose messageDigest matches the TSTInfo, and an issuer chain (each link's
 *   signature checked) that ends byte-for-byte at the pinned DigiCert root.
 * - `dev`: the api's local stand-in token (`anchoring._dev_timestamp`, base64 JSON). Not
 *   cryptographic; the page never treats it as trusted time (see `report.ts`).
 *
 * Like the Python, this is a pinned OFFLINE verifier: no validity-date, BasicConstraints, or
 * OCSP/CRL checks, because evidence must re-verify years later with no network - the token's own
 * signed time is the trusted instant. Never throws: anything malformed is simply `false`.
 */

import { arrayBufferView, b64decodePy, equalBytes, fromHexPy, sha256 } from "./bytes";
import { children, expect, integer, oid, parse, TAG, type Tlv } from "./der";
import { isObject, parseJson, type Json } from "./json";
import { PINNED_TSA_ROOT_PEM, pemToDer } from "./pinnedRoot";

export type TimestampMode = "dev" | "prod";

const OID = {
  signedData: "1.2.840.113549.1.7.2",
  sha256: "2.16.840.1.101.3.4.2.1",
  messageDigest: "1.2.840.113549.1.9.4",
  rsaEncryption: "1.2.840.113549.1.1.1",
  extKeyUsage: "2.5.29.37",
  subjectKeyId: "2.5.29.14",
  timeStamping: "1.3.6.1.5.5.7.3.8",
} as const;

/** sha*WithRSAEncryption -> WebCrypto hash. (sha224 has no WebCrypto support: rejected.) */
const RSA_SIG_HASH: Record<string, string> = {
  "1.2.840.113549.1.1.5": "SHA-1",
  "1.2.840.113549.1.1.11": "SHA-256",
  "1.2.840.113549.1.1.12": "SHA-384",
  "1.2.840.113549.1.1.13": "SHA-512",
};

export async function verifyTimestamp(
  token: Json,
  root: Json,
  mode: TimestampMode,
  pinnedRootPem: string = PINNED_TSA_ROOT_PEM,
): Promise<boolean> {
  try {
    if (typeof token !== "string") return false;
    return mode === "dev"
      ? verifyDevTimestamp(token, root)
      : await verifyRfc3161(b64decodePy(token), root, pemToDer(pinnedRootPem));
  } catch {
    return false;
  }
}

/** `_verify_dev_timestamp`. */
function verifyDevTimestamp(token: string, root: Json): boolean {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(b64decodePy(token));
  const t = parseJson(text);
  return (
    isObject(t) &&
    t.authority === "dev-local" &&
    t.algorithm === "sha256" &&
    t.message_imprint === root
  );
}

interface Cert {
  der: Uint8Array;
  tbs: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  serial: bigint;
  spki: Tlv;
  sigHash: string | undefined;
  signature: Uint8Array;
  extensions: Map<string, Uint8Array>;
}

function parseCert(t: Tlv): Cert {
  const [tbsT, sigAlgT, sigT] = children(expect(t, TAG.SEQUENCE));
  const tbs = children(expect(tbsT, TAG.SEQUENCE));
  let i = tbs[0].tag === TAG.ctx(0) ? 1 : 0; // optional [0] version
  const serial = integer(tbs[i++]);
  i++; // signature AlgorithmIdentifier
  const issuer = expect(tbs[i++], TAG.SEQUENCE).bytes;
  i++; // validity
  const subject = expect(tbs[i++], TAG.SEQUENCE).bytes;
  const spki = expect(tbs[i++], TAG.SEQUENCE);
  const extensions = new Map<string, Uint8Array>();
  for (const opt of tbs.slice(i)) {
    if (opt.tag !== TAG.ctx(3)) continue; // [1]/[2] unique ids
    for (const ext of children(expect(children(opt)[0], TAG.SEQUENCE))) {
      const parts = children(expect(ext, TAG.SEQUENCE));
      extensions.set(oid(parts[0]), expect(parts[parts.length - 1], TAG.OCTET_STRING).value);
    }
  }
  const bits = expect(sigT, TAG.BIT_STRING).value;
  if (bits[0] !== 0) throw new Error("unexpected unused bits in signature");
  return {
    der: t.bytes,
    tbs: tbsT.bytes,
    issuer,
    subject,
    serial,
    spki,
    sigHash: RSA_SIG_HASH[oid(children(expect(sigAlgT, TAG.SEQUENCE))[0])],
    signature: bits.subarray(1),
    extensions,
  };
}

/** `cert.key_identifier`: the SubjectKeyIdentifier value, if present. */
function keyIdentifier(c: Cert): Uint8Array | undefined {
  const ext = c.extensions.get(OID.subjectKeyId);
  return ext && expect(parse(ext), TAG.OCTET_STRING).value;
}

function hasTimestampingEku(c: Cert): boolean {
  const ext = c.extensions.get(OID.extKeyUsage);
  if (!ext) return false;
  return children(expect(parse(ext), TAG.SEQUENCE)).some((p) => oid(p) === OID.timeStamping);
}

async function rsaVerify(
  spki: Tlv,
  hash: string,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  const alg = children(expect(children(expect(spki, TAG.SEQUENCE))[0], TAG.SEQUENCE))[0];
  if (oid(alg) !== OID.rsaEncryption) return false; // Python: non-RSA key -> False
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      arrayBufferView(spki.bytes),
      { name: "RSASSA-PKCS1-v1_5", hash },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      arrayBufferView(signature),
      arrayBufferView(message),
    );
  } catch {
    return false;
  }
}

/** `_imprint_matches_root`. */
function imprintMatchesRoot(econtent: Uint8Array, root: Json): boolean {
  const tst = children(expect(parse(econtent), TAG.SEQUENCE));
  const [algT, hashedT] = children(expect(tst[2], TAG.SEQUENCE));
  if (oid(children(expect(algT, TAG.SEQUENCE))[0]) !== OID.sha256) return false;
  if (typeof root !== "string") return false; // Python: TypeError -> rejected
  let want: Uint8Array;
  try {
    want = fromHexPy(root);
  } catch {
    return false;
  }
  return equalBytes(expect(hashedT, TAG.OCTET_STRING).value, want);
}

/** `_find_signer_cert`: resolve SignerInfo.sid by issuer+serial or by SubjectKeyIdentifier. */
function findSignerCert(sid: Tlv, certs: Cert[]): Cert | undefined {
  if (sid.tag === TAG.SEQUENCE) {
    const [issuerT, serialT] = children(sid);
    const issuer = expect(issuerT, TAG.SEQUENCE).bytes;
    const serial = integer(serialT);
    return certs.find((c) => equalBytes(c.issuer, issuer) && c.serial === serial);
  }
  const keyId = expect(sid, TAG.ctxPrim(0)).value;
  return certs.find((c) => {
    const ski = keyIdentifier(c);
    return ski !== undefined && equalBytes(ski, keyId);
  });
}

/** `_cms_signature_valid`. */
async function cmsSignatureValid(
  econtent: Uint8Array,
  signedAttrs: Tlv | undefined,
  signature: Uint8Array,
  signer: Cert,
): Promise<boolean> {
  if (!signedAttrs) return false;
  const attrs = children(signedAttrs);
  if (attrs.length === 0) return false;
  let messageDigest: Uint8Array | undefined;
  for (const a of attrs) {
    const [typeT, valuesT] = children(expect(a, TAG.SEQUENCE));
    if (oid(typeT) === OID.messageDigest) {
      messageDigest = expect(children(expect(valuesT, TAG.SET))[0], TAG.OCTET_STRING).value;
    }
  }
  if (!messageDigest || !equalBytes(messageDigest, await sha256(econtent))) return false;
  // Signed attributes are signed as an explicit SET OF (0x31), not the [0] IMPLICIT they carry
  // inside the SignerInfo - re-tag before verifying (RFC 5652 5.4).
  const signedDer = new Uint8Array(signedAttrs.bytes);
  signedDer[0] = TAG.SET;
  return rsaVerify(signer.spki, "SHA-256", signature, signedDer);
}

/** `_chains_to_pinned_root`. */
async function chainsToPinnedRoot(signer: Cert, certs: Cert[], pinned: Cert): Promise<boolean> {
  const bySubject = new Map<string, Cert>();
  for (const c of certs) bySubject.set(key(c.subject), c);
  const seen = new Set<string>();
  let current = signer;
  for (;;) {
    if (equalBytes(current.subject, pinned.subject)) return equalBytes(current.der, pinned.der);
    const issuer = bySubject.get(key(current.issuer));
    if (!issuer) return false;
    if (!current.sigHash) return false;
    if (!(await rsaVerify(issuer.spki, current.sigHash, current.signature, current.tbs))) {
      return false;
    }
    const marker = key(issuer.der);
    if (seen.has(marker)) return false; // a cert cycle in the embedded set
    seen.add(marker);
    current = issuer;
  }
}

function key(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** `_verify_rfc3161_inner`. */
async function verifyRfc3161(der: Uint8Array, root: Json, pinnedDer: Uint8Array): Promise<boolean> {
  const ci = children(expect(parse(der), TAG.SEQUENCE));
  if (oid(ci[0]) !== OID.signedData) return false;
  const sd = children(expect(children(expect(ci[1], TAG.ctx(0)))[0], TAG.SEQUENCE));

  const eci = children(expect(sd[2], TAG.SEQUENCE));
  const econtent = expect(children(expect(eci[1], TAG.ctx(0)))[0], TAG.OCTET_STRING).value;
  if (!imprintMatchesRoot(econtent, root)) return false;

  const signerInfos = children(expect(sd[sd.length - 1], TAG.SET));
  if (signerInfos.length !== 1) return false;
  const si = children(expect(signerInfos[0], TAG.SEQUENCE));

  const certSet = sd.slice(3, -1).find((t) => t.tag === TAG.ctx(0));
  if (!certSet) return false; // Python: iterating a missing CertificateSet -> rejected
  const certs = children(certSet).map(parseCert); // non-certificate choices fail to parse

  const signer = findSignerCert(si[1], certs);
  if (!signer) return false;
  if (!hasTimestampingEku(signer)) return false;

  const signedAttrs = si.find((t) => t.tag === TAG.ctx(0));
  const signature = expect(si.find((t) => t.tag === TAG.OCTET_STRING), TAG.OCTET_STRING).value;
  if (!(await cmsSignatureValid(econtent, signedAttrs, signature, signer))) return false;

  return chainsToPinnedRoot(signer, certs, parseCert(parse(pinnedDer)));
}

/** The TSA-signed time (TSTInfo.genTime) of an RFC 3161 token, as ISO-8601 UTC, or null if the
 * token can't be read. Display only: call it for a token `verifyTimestamp` already accepted -
 * this is the one trustworthy instant in a bundle (event `occurred_at` and `anchored_at` are not
 * covered by any hash or signature). */
export function timestampGenTime(token: Json): string | null {
  try {
    if (typeof token !== "string") return null;
    const ci = children(parse(b64decodePy(token)));
    const sd = children(children(ci[1])[0]);
    const econtent = children(children(sd[2])[1])[0].value;
    const genTime = children(parse(econtent))[4];
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(
      new TextDecoder().decode(expect(genTime, 0x18).value),
    );
    if (!m) return null;
    return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`;
  } catch {
    return null;
  }
}

/** Internals exposed for unit tests only (hand-built DER edge cases the vectors can't reach). */
export const _internal = { parseCert, rsaVerify };
