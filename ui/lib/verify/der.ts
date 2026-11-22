/**
 * A minimal, strict DER reader: just enough ASN.1 to walk an RFC 3161 TimeStampToken (CMS
 * SignedData + TSTInfo + X.509 certificates). Small on purpose - an auditor can read it in one
 * sitting, and the page ships no third-party crypto. Anything outside DER (indefinite lengths,
 * multi-byte tags, truncation) throws; the timestamp verifier turns any throw into "invalid".
 */

export interface Tlv {
  /** The identifier octet (class + constructed bit + tag number). */
  tag: number;
  /** The whole element: identifier + length + contents. */
  bytes: Uint8Array;
  /** Just the contents octets. */
  value: Uint8Array;
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OID: 0x06,
  SEQUENCE: 0x30,
  SET: 0x31,
  /** [n] constructed (EXPLICIT, or IMPLICIT over a constructed type). */
  ctx: (n: number) => 0xa0 | n,
  /** [n] primitive (IMPLICIT over a primitive type). */
  ctxPrim: (n: number) => 0x80 | n,
} as const;

/** Read one TLV starting at `offset` of `buf`. */
export function readTlv(buf: Uint8Array, offset = 0): Tlv {
  if (offset + 2 > buf.length) throw new Error("DER: truncated header");
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error("DER: multi-byte tags unsupported");
  let len = buf[offset + 1];
  let header = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("DER: unsupported length form");
    if (offset + 2 + n > buf.length) throw new Error("DER: truncated length");
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[offset + 2 + k];
    header += n;
  }
  const end = offset + header + len;
  if (end > buf.length) throw new Error("DER: truncated contents");
  return {
    tag,
    bytes: buf.subarray(offset, end),
    value: buf.subarray(offset + header, end),
  };
}

/** Read `buf` as exactly one TLV, ignoring trailing bytes (asn1crypto's lenient `load`). */
export function parse(buf: Uint8Array): Tlv {
  return readTlv(buf, 0);
}

/** The child elements of a constructed TLV. */
export function children(t: Tlv): Tlv[] {
  if (!(t.tag & 0x20)) throw new Error("DER: not a constructed element");
  const out: Tlv[] = [];
  let off = 0;
  while (off < t.value.length) {
    const c = readTlv(t.value, off);
    out.push(c);
    off += c.bytes.length;
  }
  return out;
}

/** Assert a tag and return the element (fluent guard). */
export function expect(t: Tlv | undefined, tag: number): Tlv {
  if (!t || t.tag !== tag) throw new Error(`DER: expected tag 0x${tag.toString(16)}`);
  return t;
}

/** Dotted-decimal text of an OBJECT IDENTIFIER element. */
export function oid(t: Tlv): string {
  const v = expect(t, TAG.OID).value;
  if (v.length === 0) throw new Error("DER: empty OID");
  const parts: number[] = [];
  let acc = 0;
  for (const b of v) {
    acc = acc * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(acc);
      acc = 0;
    }
  }
  const first = parts[0];
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  return [...head, ...parts.slice(1)].join(".");
}

/** Signed big-endian INTEGER contents as a BigInt. */
export function integer(t: Tlv): bigint {
  const v = expect(t, TAG.INTEGER).value;
  let n = 0n;
  for (const b of v) n = (n << 8n) | BigInt(b);
  if (v.length && v[0] & 0x80) n -= 1n << BigInt(v.length * 8);
  return n;
}
