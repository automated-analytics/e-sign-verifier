/**
 * A JSON parser and canonical serializer that reproduce Python's `json` module exactly, so the
 * browser recomputes the same audit-chain hashes the api wrote (`audit_chain._canonical`:
 * `json.dumps(sort_keys=True, separators=(",", ":"))`, default `ensure_ascii=True`).
 *
 * `JSON.parse` + `JSON.stringify` are not enough: JS loses integers above 2^53, prints floats
 * differently (`10000000000000000` vs Python's `1e+16`, `100` vs `100.0`), doesn't escape
 * non-ASCII or DEL, and orders keys by UTF-16 unit rather than code point. So numbers keep their
 * Python type (int vs float), ints stay exact as decimal strings, and the serializer follows
 * CPython's `float_repr` + `ensure_ascii` rules. Golden vectors shared with the api suite
 * (`testdata/evidence_vectors.json`) pin both halves.
 */

/** A Python `int`: kept as its exact decimal text (arbitrary precision). */
export class PyInt {
  constructor(readonly digits: string) {}
}

/** A Python `float` (incl. NaN/Infinity, which Python's json reads and writes). */
export class PyFloat {
  constructor(readonly value: number) {}
}

export type Json = null | boolean | string | PyInt | PyFloat | Json[] | JsonObject;
export interface JsonObject {
  [key: string]: Json;
}

export class JsonSyntaxError extends Error {
  constructor(message: string, readonly position: number) {
    super(`${message} at position ${position}`);
    this.name = "JsonSyntaxError";
  }
}

const WS = new Set([" ", "\t", "\n", "\r"]);
const NUMBER = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/y;

export function isObject(v: Json | undefined): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof PyInt) &&
    !(v instanceof PyFloat);
}

/** Parse JSON text the way Python's `json.loads` does (keeps int/float distinction, exact ints,
 * accepts `NaN`/`Infinity`/`-Infinity`, last duplicate key wins). */
export function parseJson(text: string): Json {
  let i = 0;
  const skip = () => {
    while (i < text.length && WS.has(text[i])) i++;
  };
  const fail = (msg: string): never => {
    throw new JsonSyntaxError(msg, i);
  };
  const literal = (word: string, value: Json): Json => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail("unexpected token");
  };
  const str = (): string => {
    const start = i;
    i++; // opening quote
    while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    if (i >= text.length) fail("unterminated string");
    i++;
    try {
      return JSON.parse(text.slice(start, i)) as string;
    } catch {
      return fail("invalid string");
    }
  };
  const value = (): Json => {
    skip();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: JsonObject = Object.create(null) as JsonObject;
      skip();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        skip();
        if (text[i] !== '"') fail("expected string key");
        const key = str();
        skip();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        obj[key] = value();
        skip();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr: Json[] = [];
      skip();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value());
        skip();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    if (c === "t") return literal("true", true);
    if (c === "f") return literal("false", false);
    if (c === "n") return literal("null", null);
    if (c === "N") return literal("NaN", new PyFloat(NaN));
    if (c === "I") return literal("Infinity", new PyFloat(Infinity));
    if (text.startsWith("-Infinity", i)) return literal("-Infinity", new PyFloat(-Infinity));
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) return fail("unexpected token");
    i += m[0].length;
    if (m[1] === undefined && m[2] === undefined) {
      return new PyInt(m[0] === "-0" ? "0" : m[0]);
    }
    return new PyFloat(Number(m[0]));
  };
  const out = value();
  skip();
  if (i !== text.length) fail("extra data");
  return out;
}

/** CPython's `repr(float)`: shortest round-trip digits, exponent form iff exp < -4 or >= 16,
 * always a `.0` on integral values, two-digit minimum exponent. */
export function pyFloatRepr(x: number): string {
  if (Number.isNaN(x)) return "NaN";
  if (x === Infinity) return "Infinity";
  if (x === -Infinity) return "-Infinity";
  if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
  const sign = x < 0 ? "-" : "";
  const [mant, expText] = Math.abs(x).toExponential().split("e");
  const digits = mant.replace(".", "");
  const exp = Number(expText);
  if (exp < -4 || exp >= 16) {
    const frac = digits.length > 1 ? `.${digits.slice(1)}` : "";
    const e = Math.abs(exp).toString().padStart(2, "0");
    return `${sign}${digits[0]}${frac}e${exp < 0 ? "-" : "+"}${e}`;
  }
  const point = exp + 1;
  if (point <= 0) return `${sign}0.${"0".repeat(-point)}${digits}`;
  if (point >= digits.length) return `${sign}${digits}${"0".repeat(point - digits.length)}.0`;
  return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
}

/** Python's `json` string encoding with `ensure_ascii=True`. */
export function pyString(s: string): string {
  return JSON.stringify(s).replace(
    /[^\x20-\x7e]/g,
    (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/** Order strings by Unicode code point, as Python's `sorted` does (JS sorts by UTF-16 unit). */
export function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done === y.done ? 0 : x.done ? -1 : 1;
    const d = (x.value.codePointAt(0) as number) - (y.value.codePointAt(0) as number);
    if (d !== 0) return d;
  }
}

/** `json.dumps(v, sort_keys=True, separators=(",", ":"))`. */
export function canonicalJson(v: Json): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return pyString(v);
  if (v instanceof PyInt) return v.digits;
  if (v instanceof PyFloat) return pyFloatRepr(v.value);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(v).sort(compareCodePoints);
  return `{${keys.map((k) => `${pyString(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}

/** Python truthiness of a JSON value (`if x:`). */
export function pyTruthy(v: Json | undefined): boolean {
  if (v === undefined || v === null || v === false) return false;
  if (v === true) return true;
  if (typeof v === "string") return v.length > 0;
  if (v instanceof PyInt) return v.digits !== "0";
  if (v instanceof PyFloat) return v.value !== 0;
  if (Array.isArray(v)) return v.length > 0;
  return Object.keys(v).length > 0;
}
