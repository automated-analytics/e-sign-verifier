/**
 * Edge cases of the browser verifier's building blocks that the shared golden vectors don't
 * reach: Python-builtin parity (fromhex, b64decode, json), strict DER failure modes, hand-built
 * certificates, and the report's plain-language derivations.
 */
import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { b64decodePy, fromHexPy, sha256Hex, toHex, utf8 } from "@/lib/verify/bytes";
import { children, integer, oid, parse, readTlv, TAG } from "@/lib/verify/der";
import {
  computeEventHash,
  MalformedBundle,
  normalizeUuid,
  verifyBundle,
  verifyInclusion,
  ZERO_HASH,
} from "@/lib/verify/evidence";
import {
  canonicalJson,
  compareCodePoints,
  JsonSyntaxError,
  parseJson,
  pyFloatRepr,
  PyFloat,
  PyInt,
  pyTruthy,
  type Json,
  type JsonObject,
} from "@/lib/verify/json";
import { pemToDer, PINNED_TSA_ROOT_PEM } from "@/lib/verify/pinnedRoot";
import { buildReport, envelopeStatus, matchPdf, NO_WEBCRYPTO } from "@/lib/verify/report";
import { _internal, timestampGenTime, verifyTimestamp } from "@/lib/verify/timestamp";

const vectors = parseJson(
  readFileSync(resolve(__dirname, "../../../../testdata/evidence_vectors.json"), "utf8"),
) as JsonObject;
const bundleVec = (name: string): Json =>
  (vectors.bundles as JsonObject[]).find((v) => v.name === name)!.bundle;

/** Minimal DER encoder for hand-built structures. */
function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const lenBytes =
    len < 128 ? [len] : len < 256 ? [0x81, len] : [0x82, len >> 8, len & 0xff];
  const out = new Uint8Array(1 + lenBytes.length + len);
  out.set([tag, ...lenBytes]);
  let off = 1 + lenBytes.length;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
const b = (...xs: number[]) => Uint8Array.from(xs);
const OID_SHA256_RSA = b(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b);
const OID_RSA = b(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01);

describe("bytes", () => {
  it("fromHexPy follows bytes.fromhex", () => {
    expect(toHex(fromHexPy(" AB\tcd\n01 "))).toBe("abcd01");
    expect(() => fromHexPy("a b")).toThrow();
    expect(() => fromHexPy("abc")).toThrow();
    expect(() => fromHexPy("zz")).toThrow();
  });

  // Expected values are CPython 3.11's (the api's runtime, api/Dockerfile): junk is skipped and
  // decoding stops once padding completes a quad. (3.14 tightened the latter; tokens that rely on
  // either are invalid DER anyway.)
  it("b64decodePy follows non-strict base64.b64decode", () => {
    expect(toHex(b64decodePy("aGk="))).toBe(toHex(utf8("hi")));
    expect(toHex(b64decodePy("a G!k=trailing"))).toBe(toHex(utf8("hi")));
    expect(toHex(b64decodePy("aGk=aGk="))).toBe(toHex(utf8("hi")));
    expect(toHex(b64decodePy("aG=k="))).toBe(toHex(utf8("hi")));
    expect(toHex(b64decodePy("YQ==="))).toBe(toHex(utf8("a")));
    expect(toHex(b64decodePy("aGVsbG8h"))).toBe(toHex(utf8("hello!")));
  });

  it("b64decodePy rejects dangling quads and non-ASCII", () => {
    expect(() => b64decodePy("aGk")).toThrow("Incorrect padding");
    expect(() => b64decodePy("aGVsbG8")).toThrow("Incorrect padding");
    expect(() => b64decodePy("aGk=é")).toThrow("ASCII");
    expect(toHex(b64decodePy("=a=Gk=="))).toBe(toHex(utf8("hi"))); // '=' before 2 chars is skipped
  });
});

describe("json (Python json parity)", () => {
  it("parses every value kind, keeping int/float apart", () => {
    const v = parseJson(' {"a": [1, -0, 2.0, 1e2, true, false, null, NaN, Infinity, -Infinity]} ');
    const a = (v as JsonObject).a as Json[];
    expect(a[0]).toEqual(new PyInt("1"));
    expect(a[1]).toEqual(new PyInt("0"));
    expect(a[2]).toEqual(new PyFloat(2));
    expect(a[3]).toEqual(new PyFloat(100));
    expect(a.slice(4, 7)).toEqual([true, false, null]);
    expect(canonicalJson(a.slice(7))).toBe("[NaN,Infinity,-Infinity]");
    expect(parseJson("{}")).toEqual({});
    expect(parseJson("[]")).toEqual([]);
    expect(parseJson('"\\u00e9\\n"')).toBe("é\n");
  });

  it("keeps __proto__ as an ordinary key and the last duplicate", () => {
    const v = parseJson('{"__proto__": 1, "k": 1, "k": 2}') as JsonObject;
    expect(Object.keys(v)).toEqual(["__proto__", "k"]);
    expect(canonicalJson(v)).toBe('{"__proto__":1,"k":2}');
  });

  it.each([
    ["", "unexpected token"],
    ["tru", "unexpected token"],
    ['"abc', "unterminated string"],
    ['"\\x"', "invalid string"],
    ["{1:2}", "expected string key"],
    ['{"a" 1}', "expected ':'"],
    ['{"a":1 "b":2}', "expected ',' or '}'"],
    ["[1 2]", "expected ',' or ']'"],
    ["[1,]", "unexpected token"],
    ["01", "extra data"],
    ["- 1", "unexpected token"],
  ])("rejects %j", (text, msg) => {
    expect(() => parseJson(text)).toThrow(JsonSyntaxError);
    expect(() => parseJson(text)).toThrow(msg);
  });

  it.each([
    [NaN, "NaN"],
    [Infinity, "Infinity"],
    [-Infinity, "-Infinity"],
    [0, "0.0"],
    [-0, "-0.0"],
    [1, "1.0"],
    [-2.5, "-2.5"],
    [123.456, "123.456"],
    [1e15, "1000000000000000.0"],
    [1e16, "1e+16"],
    [1.5e-5, "1.5e-05"],
    [1e-4, "0.0001"],
    [0.00012, "0.00012"],
    [1e100, "1e+100"],
    [-1.25e-7, "-1.25e-07"],
  ])("pyFloatRepr(%d) === %s", (x, want) => {
    expect(pyFloatRepr(x)).toBe(want);
  });

  it("orders keys by code point, not UTF-16 unit", () => {
    expect(compareCodePoints("￿", "\u{1f600}")).toBeLessThan(0);
    expect(compareCodePoints("a", "ab")).toBeLessThan(0);
    expect(compareCodePoints("ab", "a")).toBeGreaterThan(0);
    expect(compareCodePoints("ab", "ab")).toBe(0);
  });

  it.each([
    [undefined, false],
    [null, false],
    [false, false],
    [true, true],
    ["", false],
    ["x", true],
    [new PyInt("0"), false],
    [new PyInt("2"), true],
    [new PyFloat(0), false],
    [new PyFloat(NaN), true],
    [[], false],
    [[null], true],
    [{}, false],
    [{ a: null }, true],
  ] as [Json | undefined, boolean][])("pyTruthy(%j) === %s", (v, want) => {
    expect(pyTruthy(v)).toBe(want);
  });
});

describe("der", () => {
  it("rejects non-DER encodings", () => {
    expect(() => readTlv(b(0x30))).toThrow("truncated header");
    expect(() => readTlv(b(0x1f, 0x01, 0x00))).toThrow("multi-byte tags");
    expect(() => readTlv(b(0x30, 0x80))).toThrow("unsupported length form");
    expect(() => readTlv(b(0x30, 0x85, 1, 2, 3, 4, 5))).toThrow("unsupported length form");
    expect(() => readTlv(b(0x30, 0x82, 0x01))).toThrow("truncated length");
    expect(() => readTlv(b(0x30, 0x03, 0x01))).toThrow("truncated contents");
    expect(() => children(parse(b(0x02, 0x01, 0x00)))).toThrow("not a constructed");
    expect(() => oid(parse(b(0x06, 0x00)))).toThrow("empty OID");
    expect(() => oid(parse(b(0x02, 0x01, 0x00)))).toThrow("expected tag 0x6");
  });

  it("decodes long-form lengths, OIDs and signed integers", () => {
    const long = tlv(0x04, new Uint8Array(300));
    expect(readTlv(long).value.length).toBe(300);
    expect(oid(parse(b(0x06, 0x03, 0x55, 0x1d, 0x25)))).toBe("2.5.29.37");
    expect(oid(parse(b(0x06, 0x01, 0x2a)))).toBe("1.2");
    expect(integer(parse(b(0x02, 0x01, 0x7f)))).toBe(127n);
    expect(integer(parse(b(0x02, 0x02, 0x00, 0x80)))).toBe(128n);
    expect(integer(parse(b(0x02, 0x01, 0xff)))).toBe(-1n);
    expect(integer(parse(b(0x02, 0x00)))).toBe(0n);
  });
});

describe("timestamp internals", () => {
  const algId = (o: Uint8Array) => tlv(0x30, tlv(0x06, o), b(0x05, 0x00));
  const name = (cn: string) =>
    tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b(0x55, 0x04, 0x03)), tlv(0x0c, utf8(cn)))));
  const spki = (keyBits: Uint8Array, alg = OID_RSA) =>
    tlv(0x30, algId(alg), tlv(0x03, b(0x00), keyBits));
  const cert = (tbsParts: Uint8Array[], sigBits = b(0x00, 0x01)) =>
    tlv(0x30, tlv(0x30, ...tbsParts), algId(OID_SHA256_RSA), tlv(0x03, sigBits));

  it("parses a v1 certificate (no version, no extensions) and skips unique ids", () => {
    const der = cert([
      tlv(0x02, b(0x05)),
      algId(OID_SHA256_RSA),
      name("Issuer"),
      tlv(0x30),
      name("Subject"),
      spki(b(0x30, 0x00)),
      tlv(0x81, b(0x00, 0x01)), // [1] issuerUniqueID
    ]);
    const c = _internal.parseCert(parse(der));
    expect(c.serial).toBe(5n);
    expect(c.sigHash).toBe("SHA-256");
    expect(c.extensions.size).toBe(0);
  });

  it("rejects a signature BIT STRING with unused bits", () => {
    const der = cert(
      [tlv(0x02, b(0x01)), algId(OID_SHA256_RSA), name("I"), tlv(0x30), name("S"), spki(b())],
      b(0x01, 0xff),
    );
    expect(() => _internal.parseCert(parse(der))).toThrow("unused bits");
  });

  it("treats an RSA key WebCrypto cannot import as a failed signature", async () => {
    const bad = parse(spki(b(0x00, 0x00, 0x00)));
    expect(await _internal.rsaVerify(bad, "SHA-256", b(1), b(2))).toBe(false);
  });

  it("never throws: non-string tokens and missing pins are simply invalid", async () => {
    expect(await verifyTimestamp(null, "11".repeat(32), "prod")).toBe(false);
    expect(await verifyTimestamp(new PyInt("1"), "11".repeat(32), "dev")).toBe(false);
    const tok = (vectors.timestamps as JsonObject[])[0];
    expect(await verifyTimestamp(tok.token, tok.root, "prod", "not a pem")).toBe(false);
    expect(await verifyTimestamp(tok.token, new PyInt("1"), "prod")).toBe(false);
  });

  it("reads the TSA-signed genTime of a real token, and null for anything else", () => {
    const tok = (vectors.timestamps as JsonObject[]).find((v) => v.name === "real_token_11")!;
    expect(timestampGenTime(tok.token)).toBe("2026-07-11T21:06:17Z");
    expect(timestampGenTime(null)).toBeNull();
    expect(timestampGenTime("not-a-token")).toBeNull();
    // A GeneralizedTime with fractional seconds, and one that is not a UTC time.
    const withTime = (t: string) => {
      const tst = tlv(0x30, tlv(0x02, b(1)), tlv(0x06, b(0x2a)), tlv(0x30), tlv(0x02, b(1)),
        tlv(0x18, utf8(t)));
      const sd = tlv(0x30, tlv(0x02, b(3)), tlv(0x31), tlv(0x30, tlv(0x06, b(0x2a)),
        tlv(0xa0, tlv(0x04, tst))));
      const ci = tlv(0x30, tlv(0x06, b(0x2a)), tlv(0xa0, sd));
      return btoa(String.fromCharCode(...ci));
    };
    expect(timestampGenTime(withTime("20260711210617.25Z"))).toBe("2026-07-11T21:06:17.25Z");
    expect(timestampGenTime(withTime("20260711210617+0100"))).toBeNull();
  });

  it("pemToDer reads the first certificate block", () => {
    expect(pemToDer(PINNED_TSA_ROOT_PEM)[0]).toBe(0x30);
    expect(() => pemToDer("nothing here")).toThrow("no CERTIFICATE block");
  });
});

describe("evidence", () => {
  it("normalizes ledger ids like Python's str(UUID(...))", () => {
    const want = "6f1c2b9e-8d4a-4c3e-9f21-0a7b5c3d2e10";
    expect(normalizeUuid("{6F1C2B9E8D4A4C3E9F210A7B5C3D2E10}")).toBe(want);
    expect(normalizeUuid(`urn:uuid:${want}`)).toBe(want);
    expect(() => normalizeUuid("not-a-uuid")).toThrow(MalformedBundle);
    expect(() => normalizeUuid(new PyInt("1"))).toThrow("must be a string");
  });

  it("computes the same event hash as the writer", async () => {
    const valid = bundleVec("valid_full") as JsonObject;
    const e = (valid.events as JsonObject[])[0];
    expect(
      await computeEventHash({
        ledger_id: e.ledger_id as string,
        type: e.type,
        actor: e.actor,
        payload: e.payload,
        prev_hash: ZERO_HASH,
      }),
    ).toBe(e.this_hash);
  });

  it("verifyInclusion: empty proof is leaf === root; bad shapes are malformed", async () => {
    expect(await verifyInclusion("ab", [], "ab")).toBe(true);
    await expect(verifyInclusion("ab", {}, "ab")).rejects.toThrow("must be a list");
    await expect(verifyInclusion("ab", [{ hash: new PyInt("1"), right: true }], "ab")).rejects
      .toThrow("must be a string");
    await expect(verifyInclusion("ab", [{ hash: "cd" }], "ab")).rejects.toThrow('missing "right"');
    await expect(verifyInclusion("ab", [null], "ab")).rejects.toThrow("expected an object");
  });

  const anchored = bundleVec("valid_full") as JsonObject;
  const with_ = (patch: (b: JsonObject) => void): JsonObject => {
    const copy = parseJson(canonicalJson(anchored)) as JsonObject;
    patch(copy);
    return copy;
  };

  it.each([
    ["events is not a list", with_((x) => (x.events = {}))],
    ["events is null", with_((x) => (x.events = null))],
    ["an event is not an object", with_((x) => ((x.events as Json[])[0] = "e"))],
    ["a redacted hash is not a string", with_((x) => {
      (x.events as Json[])[0] = { redacted: true, prev_hash: ZERO_HASH, this_hash: null };
    })],
    ["a proof hash is not hex", with_((x) => {
      ((x.anchor as JsonObject).inclusion_proof as JsonObject[])[0].hash = "zz";
    })],
    ["anchor is not an object", with_((x) => (x.anchor = []))],
    ["anchor lacks a token", with_((x) => delete (x.anchor as JsonObject).tsa_token)],
  ])("malformed when %s", async (_why, bundle) => {
    await expect(verifyBundle(bundle, "dev")).rejects.toBeInstanceOf(MalformedBundle);
  });

  it("a missing events key is an empty chain", async () => {
    const r = await verifyBundle({ head: ZERO_HASH }, "dev");
    expect(r).toMatchObject({ chain_valid: true, anchored: false, head: ZERO_HASH });
  });
});

describe("report", () => {
  const text = (name: string) => canonicalJson(bundleVec(name));

  const prodPin = (vectors.bundles as JsonObject[]).find(
    (v) => v.name === "valid_full_prod_test_ca",
  )!.pinned_root_pem as string;

  it("verified: fully verified under the production timestamp rules", async () => {
    const r = await buildReport(text("valid_full_prod_test_ca"), undefined, prodPin);
    expect(r.verdict).toBe("verified");
    expect(r.result?.timestamp_valid).toBe(true);
    expect(r.trustedTime).toBe("2026-07-11T21:06:17Z"); // the TSTInfo genTime the test TSA kept
  });

  it("the same bundle under the real pin is not trusted (and is not 'development')", async () => {
    const r = await buildReport(text("valid_full_prod_test_ca"));
    expect(r.verdict).toBe("failed");
    expect(r.result?.timestamp_valid).toBe(false);
  });

  it("development: passes only with the dev stand-in token", async () => {
    const r = await buildReport(text("valid_full"));
    expect(r.verdict).toBe("development");
    expect(r.result?.fully_verified).toBe(true);
    expect(r.status).toBe("completed");
    expect(r.anchoredAt).toBe("2026-11-17T10:30:00+00:00");
    expect(r.timeline[0]).toEqual({
      type: "envelope.created",
      actor: "caller:fathers-platform",
      occurredAt: "2026-11-17T10:00:00Z",
      unproven: false,
    });
  });

  it("not anchored / failed / invalid", async () => {
    expect((await buildReport(text("valid_unanchored"))).verdict).toBe("not_anchored");
    expect((await buildReport(text("tampered_event_payload"))).verdict).toBe("failed");
    const unanchoredTampered = parseJson(text("tampered_event_payload")) as JsonObject;
    unanchoredTampered.anchor = null;
    expect((await buildReport(canonicalJson(unanchoredTampered))).verdict).toBe("failed");
    const bad = await buildReport("{not json");
    expect(bad).toMatchObject({ verdict: "invalid", error: "This file is not valid JSON." });
    const notBundle = await buildReport("[1]");
    expect(notBundle.verdict).toBe("invalid");
    expect(notBundle.error).toMatch(/evidence bundle/);
  });

  it("explains a browser without Web Crypto (an insecure origin) instead of blaming the file", async () => {
    vi.stubGlobal("crypto", {});
    try {
      expect((await buildReport(text("valid_full"))).error).toBe(NO_WEBCRYPTO);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("reports an unexpected failure verbatim", async () => {
    const spy = vi.spyOn(crypto.subtle, "digest").mockRejectedValue(new Error("boom"));
    try {
      const r = await buildReport(text("valid_full"));
      expect(r).toMatchObject({ verdict: "invalid", error: "The bundle could not be checked: Error: boom" });
    } finally {
      spy.mockRestore();
    }
  });

  it("revoked: surfaces when and why", async () => {
    const r = await buildReport(text("revoked"));
    expect(r.status).toBe("revoked");
    expect(r.revoked).toEqual({ occurredAt: "2026-11-17T10:06:00Z", reason: "issued in error" });
  });

  it("redacted receipt: counts hidden events, status unknown", async () => {
    const r = await buildReport(text("redacted_valid"));
    expect(r.verdict).toBe("development");
    expect(r.redactedCount).toBeGreaterThan(0);
    expect(r.status).toBe("unknown");
    expect(r.eventCount).toBe(8);
    const pdf = await buildReport(text("redacted_valid"), utf8("%PDF"));
    expect(pdf.pdf.kind).toBe("unavailable");
  });

  it("an event without a string type or actor is still listed safely", async () => {
    expect(envelopeStatus([{ type: "envelope.declined" }])).toBe("declined");
    const events: JsonObject[] = [
      { type: "signature_applied", payload: { input_pdf_sha256: await sha256Hex(utf8("in")) } },
      { type: "envelope.completed", payload: { pdf_sha256: await sha256Hex(utf8("v1")) } },
      { type: "envelope.completed", payload: "not an object" },
      { type: "envelope.completed", payload: { pdf_sha256: await sha256Hex(utf8("v2")) } },
    ];
    expect((await matchPdf(events, utf8("v2"))).kind).toBe("match");
    expect((await matchPdf(events, utf8("v1"))).kind).toBe("earlier");
    expect((await matchPdf(events, utf8("in"))).kind).toBe("unsigned_input");
    expect((await matchPdf(events, utf8("other"))).kind).toBe("mismatch");
  });

  it("tolerates a bundle without anchor metadata or actor strings", async () => {
    const bundle = parseJson(text("valid_unanchored")) as JsonObject;
    bundle.ledger_id = new PyInt("7");
    ((bundle.events as JsonObject[])[0]).actor = null;
    const r = await buildReport(canonicalJson(bundle));
    expect(r.ledgerId).toBeNull();
    expect(r.anchoredAt).toBeNull();
    expect(r.timeline[0].actor).toBe("");
    const empty = await buildReport(`{"head": "${ZERO_HASH}"}`);
    expect(empty).toMatchObject({ verdict: "not_anchored", eventCount: 0, status: "unknown" });
  });
});
