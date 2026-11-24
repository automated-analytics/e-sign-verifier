/**
 * The shared golden vectors (testdata/evidence_vectors.json), also run by
 * api/tests/test_evidence_vectors.py against the Python reference verifier. If the TypeScript
 * port drifts from Python on any vector, this fails.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { b64decodePy, sha256Hex, utf8 } from "@/lib/verify/bytes";
import { MalformedBundle, verifyBundle } from "@/lib/verify/evidence";
import {
  canonicalJson,
  isObject,
  parseJson,
  PyInt,
  type Json,
  type JsonObject,
} from "@/lib/verify/json";
import { PINNED_TSA_ROOT_PEM } from "@/lib/verify/pinnedRoot";
import { buildReport } from "@/lib/verify/report";
import { verifyTimestamp, type TimestampMode } from "@/lib/verify/timestamp";

const REPO = resolve(__dirname, "../../../..");
const raw = readFileSync(resolve(REPO, "testdata/evidence_vectors.json"), "utf8");
const doc = parseJson(raw) as JsonObject;

interface BundleVec {
  name: string;
  mode: TimestampMode;
  bundle: Json;
  expect: JsonObject;
  status: string;
  pdfs?: { b64: string; match: boolean }[];
  pin?: string;
}

const bundles = (doc.bundles as JsonObject[]).map((v) => ({
  name: v.name as string,
  mode: v.mode as TimestampMode,
  bundle: v.bundle,
  // The vectors are read with the Python-exact parser, so an int (a count) is a PyInt;
  // the verifier result is a plain JS object, so compare it as a number.
  expect: Object.fromEntries(
    Object.entries(v.expect as JsonObject).map(([k, x]) => [
      k,
      x instanceof PyInt ? Number(x.digits) : x,
    ]),
  ) as JsonObject,
  status: v.status as string,
  pin: typeof v.pinned_root_pem === "string" ? v.pinned_root_pem : undefined,
  pdfs: (v.pdfs as JsonObject[] | undefined)?.map((p) => ({
    b64: p.b64 as string,
    match: p.match as boolean,
  })),
})) satisfies BundleVec[];

describe("golden vectors: canonical JSON", () => {
  it.each((doc.canonical as JsonObject[]).map((v, i) => [i, v] as const))(
    "canonical #%i matches Python json.dumps",
    async (_i, v) => {
      expect(canonicalJson(v.value)).toBe(v.canonical);
      expect(await sha256Hex(utf8(v.canonical as string))).toBe(v.sha256);
    },
  );
});

describe("golden vectors: bundles", () => {
  it.each(bundles.map((v) => [v.name, v] as const))("%s", async (_name, v) => {
    if (isObject(v.expect) && v.expect.error === "malformed") {
      await expect(verifyBundle(v.bundle, v.mode, v.pin)).rejects.toBeInstanceOf(MalformedBundle);
      return;
    }
    expect(await verifyBundle(v.bundle, v.mode, v.pin)).toEqual(v.expect);
  });

  it.each(bundles.filter((v) => !v.name.startsWith("malformed")).map((v) => [v.name, v] as const))(
    "%s: status as recorded by the bundle",
    async (_name, v) => {
      // Vectors are pre-parsed Json; re-serialize to text the way a dropped file would arrive.
      const report = await buildReport(canonicalJson(v.bundle), undefined, v.pin);
      expect(report.status).toBe(v.status);
    },
  );

  it.each(bundles.filter((v) => v.pdfs).map((v) => [v.name, v] as const))(
    "%s: PDF match against envelope.completed",
    async (_name, v) => {
      for (const pdf of v.pdfs ?? []) {
        const report = await buildReport(canonicalJson(v.bundle), b64decodePy(pdf.b64), v.pin);
        expect(report.pdf.kind === "match").toBe(pdf.match);
      }
    },
  );
});

describe("golden vectors: timestamps", () => {
  it.each((doc.timestamps as JsonObject[]).map((v) => [v.name as string, v] as const))(
    "%s",
    async (_name, v) => {
      const pin = typeof v.pinned_root_pem === "string" ? v.pinned_root_pem : undefined;
      expect(await verifyTimestamp(v.token, v.root, v.mode as TimestampMode, pin)).toBe(v.expect);
    },
  );
});

it("embeds the same pinned TSA root the api pins", async () => {
  expect(await sha256Hex(utf8(PINNED_TSA_ROOT_PEM))).toBe(doc.pinned_tsa_root_pem_sha256);
});
