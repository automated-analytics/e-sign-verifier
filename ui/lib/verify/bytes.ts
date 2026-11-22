/** Byte helpers that mirror the Python builtins the reference verifier relies on. */

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

const HEX_WS = new Set([" ", "\t", "\n", "\r", "\v", "\f"]);

/** Python's `bytes.fromhex`: case-insensitive pairs, ASCII whitespace allowed between pairs.
 * Throws on anything else (Python raises ValueError). */
export function fromHexPy(s: string): Uint8Array {
  const out: number[] = [];
  let i = 0;
  while (i < s.length) {
    if (HEX_WS.has(s[i])) {
      i++;
      continue;
    }
    const pair = s.slice(i, i + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) throw new Error("non-hexadecimal number");
    out.push(parseInt(pair, 16));
    i += 2;
  }
  return Uint8Array.from(out);
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Python's non-strict `base64.b64decode` (binascii.a2b_base64, strict_mode=False): characters
 * outside the alphabet are skipped (non-ASCII input is an error), decoding stops once a quad is completed by padding, and a
 * dangling partial quad is an error. */
export function b64decodePy(s: string): Uint8Array {
  const out: number[] = [];
  let quadPos = 0;
  let leftChar = 0;
  let pads = 0;
  // A str argument must be ASCII (Python raises ValueError before decoding).
  if (/[^\x00-\x7f]/.test(s)) throw new Error("string argument should contain only ASCII");
  for (const ch of s) {
    if (ch === "=") {
      if (quadPos >= 2 && quadPos + ++pads >= 4) return Uint8Array.from(out);
      continue;
    }
    const v = B64.indexOf(ch);
    if (v < 0) continue;
    pads = 0;
    switch (quadPos) {
      case 0:
        quadPos = 1;
        leftChar = v;
        break;
      case 1:
        quadPos = 2;
        out.push((leftChar << 2) | (v >> 4));
        leftChar = v & 0x0f;
        break;
      case 2:
        quadPos = 3;
        out.push((leftChar << 4) | (v >> 2));
        leftChar = v & 0x03;
        break;
      default:
        quadPos = 0;
        out.push((leftChar << 6) | v);
        leftChar = 0;
    }
  }
  if (quadPos !== 0) throw new Error("Incorrect padding");
  return Uint8Array.from(out);
}

/** Copy into a fresh ArrayBuffer-backed view (WebCrypto rejects SharedArrayBuffer views). */
function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await sha256(bytes));
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export { buf as arrayBufferView };
