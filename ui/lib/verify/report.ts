/**
 * Turn the reference-verifier result into what a non-technical reader needs: one verdict, the
 * envelope's status as the bundle records it (incl. revocation), and whether a dropped PDF is the
 * sealed record. Everything here is derived from the bundle; nothing is fetched.
 *
 * Trust rule: only a bundle that is fully verified under the PRODUCTION timestamp rules (a real
 * RFC 3161 token chaining to the pinned TSA root) is "verified". A bundle that only passes with
 * the api's dev-mode stand-in token is reported as a development bundle - never green - because
 * anyone can mint that token.
 */

import { sha256Hex } from "./bytes";
import { MalformedBundle, verifyBundle, type VerifyBundleResult } from "./evidence";
import { timestampGenTime } from "./timestamp";
import { isObject, JsonSyntaxError, parseJson, pyTruthy, type Json, type JsonObject } from "./json";

export type Verdict =
  | "verified" // chain + inclusion + trusted timestamp all pass
  | "development" // passes only with the dev-mode stand-in timestamp (local test bundle)
  | "not_anchored" // chain intact, but no timestamp yet: cannot be trusted yet
  | "failed" // something does not verify: altered or forged
  | "invalid"; // not an evidence bundle at all

export type EnvelopeStatus = "completed" | "declined" | "revoked" | "unknown";

export type PdfMatch =
  | { kind: "none" } // no PDF supplied
  | { kind: "match"; sha256: string } // the final sealed record
  | { kind: "earlier"; sha256: string } // an intermediate seal (a later signer sealed again)
  | { kind: "unsigned_input"; sha256: string } // the document a signer signed onto
  | { kind: "mismatch"; sha256: string }
  | { kind: "unavailable"; sha256: string }; // bundle carries no visible sealed-PDF hash

export interface TimelineEntry {
  type: string;
  actor: string;
  occurredAt: string | null;
}

export interface Report {
  verdict: Verdict;
  result: VerifyBundleResult | null;
  /** The anchor carries the api's dev-mode stand-in token (genuine for a local stack, but never
   * trusted time); `result` then reflects the dev-mode checks so a reader sees the real failure. */
  devTimestamp: boolean;
  /** The TSA-signed time from a timestamp that verified under the production rules: the only
   * date in a bundle that is cryptographically bound (event and anchor dates are server claims). */
  trustedTime: string | null;
  error: string | null;
  ledgerId: string | null;
  status: EnvelopeStatus;
  revoked: { occurredAt: string | null; reason: string | null } | null;
  redactedCount: number;
  eventCount: number;
  anchoredAt: string | null;
  timeline: TimelineEntry[];
  pdf: PdfMatch;
}

const STATUS_EVENTS: Record<string, EnvelopeStatus> = {
  "envelope.completed": "completed",
  "envelope.declined": "declined",
  "envelope.revoked": "revoked",
};

function str(v: Json | undefined): string | null {
  return typeof v === "string" ? v : null;
}

/** The events whose content the bundle shows (redacted co-recipient events carry none). */
function visibleEvents(events: JsonObject[]): JsonObject[] {
  return events.filter((e) => !pyTruthy(e.redacted) && typeof e.type === "string");
}

/** Status per the latest status-bearing event (envelope.revoked follows completed). */
export function envelopeStatus(events: JsonObject[]): EnvelopeStatus {
  let status: EnvelopeStatus = "unknown";
  for (const e of events) status = STATUS_EVENTS[e.type as string] ?? status;
  return status;
}

function payloadField(e: JsonObject, field: string): string | null {
  return isObject(e.payload) ? str(e.payload[field]) : null;
}

export async function matchPdf(events: JsonObject[], pdf: Uint8Array): Promise<PdfMatch> {
  const sha = await sha256Hex(pdf);
  const sealed = events
    .filter((e) => e.type === "envelope.completed")
    .map((e) => payloadField(e, "pdf_sha256"))
    .filter((h): h is string => h !== null);
  if (sealed.length === 0) return { kind: "unavailable", sha256: sha };
  if (sealed[sealed.length - 1] === sha) return { kind: "match", sha256: sha };
  if (sealed.includes(sha)) return { kind: "earlier", sha256: sha };
  const inputs = events
    .filter((e) => e.type === "signature_applied")
    .map((e) => payloadField(e, "input_pdf_sha256"));
  if (inputs.includes(sha)) return { kind: "unsigned_input", sha256: sha };
  return { kind: "mismatch", sha256: sha };
}

function verdictOf(prod: VerifyBundleResult, dev: VerifyBundleResult): Verdict {
  if (prod.fully_verified) return "verified";
  if (!prod.anchored) return prod.chain_valid ? "not_anchored" : "failed";
  if (dev.fully_verified) return "development";
  return "failed";
}

const EMPTY = {
  devTimestamp: false,
  trustedTime: null,
  ledgerId: null,
  status: "unknown" as const,
  revoked: null,
  redactedCount: 0,
  eventCount: 0,
  anchoredAt: null,
  timeline: [],
};

export const NO_WEBCRYPTO =
  "This browser cannot run the checks here: Web Crypto is only available on secure pages. " +
  "Open the page over https, or save it and open the saved file.";

function describeError(err: unknown): string {
  if (err instanceof MalformedBundle) return `This is not a complete evidence bundle (${err.message}).`;
  if (err instanceof JsonSyntaxError) return "This file is not valid JSON.";
  if (typeof crypto === "undefined" || !crypto.subtle) return NO_WEBCRYPTO;
  return `The bundle could not be checked: ${String(err)}`;
}

/** Verify an evidence bundle (its JSON text) and, optionally, a PDF against it.
 * `pinnedRootPem` is for tests only; the page always uses the embedded pin. */
export async function buildReport(
  bundleText: string,
  pdf?: Uint8Array,
  pinnedRootPem?: string,
): Promise<Report> {
  let bundle: Json;
  let prod: VerifyBundleResult;
  let dev: VerifyBundleResult;
  try {
    bundle = parseJson(bundleText);
    prod = await verifyBundle(bundle, "prod", pinnedRootPem);
    dev = await verifyBundle(bundle, "dev");
  } catch (err) {
    return {
      ...EMPTY,
      verdict: "invalid",
      result: null,
      error: describeError(err),
      pdf: { kind: "none" },
    };
  }
  // verifyBundle accepted it, so it is an object whose events (if any) are a list of objects.
  const b = bundle as JsonObject;
  const allEvents = (b.events ?? []) as JsonObject[];
  const events = visibleEvents(allEvents);
  const revokedEvent = [...events].reverse().find((e) => e.type === "envelope.revoked");
  const verdict = verdictOf(prod, dev);
  const devTimestamp = prod.timestamp_valid === false && dev.timestamp_valid === true;
  return {
    verdict,
    result: devTimestamp ? dev : prod,
    devTimestamp,
    trustedTime: prod.timestamp_valid ? timestampGenTime((b.anchor as JsonObject).tsa_token) : null,
    error: null,
    ledgerId: str(b.ledger_id),
    status: envelopeStatus(events),
    revoked: revokedEvent
      ? { occurredAt: str(revokedEvent.occurred_at), reason: payloadField(revokedEvent, "reason") }
      : null,
    redactedCount: allEvents.filter((e) => pyTruthy(e.redacted)).length,
    eventCount: allEvents.length,
    anchoredAt: isObject(b.anchor) ? str(b.anchor.anchored_at) : null,
    timeline: events.map((e) => ({
      type: e.type as string,
      actor: str(e.actor) ?? "",
      occurredAt: str(e.occurred_at),
    })),
    pdf: pdf ? await matchPdf(events, pdf) : { kind: "none" },
  };
}
