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
  | "partial" // proven up to a timestamped event; later events unproven (ADR-0027)
  | "receipt" // anchor checks pass, but redacted events make it unprovable (ADR-0028)
  | "failed" // something does not verify: altered or forged
  | "invalid"; // not an evidence bundle at all

export type EnvelopeStatus = "completed" | "declined" | "revoked" | "unknown";

export type PdfMatch =
  | { kind: "none" } // no PDF supplied
  | { kind: "match"; sha256: string } // the final sealed record
  | { kind: "earlier"; sha256: string } // an intermediate seal (a later signer sealed again)
  | { kind: "unsigned_input"; sha256: string } // the document a signer signed onto
  | { kind: "mismatch"; sha256: string }
  | { kind: "unavailable"; sha256: string } // bundle carries no visible sealed-PDF hash
  | { kind: "unprovable"; sha256: string } // hidden events: the visible hashes prove nothing
  | { kind: "after_anchor"; sha256: string }; // recorded only AFTER the timestamp: unproven

export interface TimelineEntry {
  type: string;
  actor: string;
  occurredAt: string | null;
  /** Recorded after the last timestamp (ADR-0027): only self-consistent, so not proven. */
  unproven: boolean;
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

/** Chain intact and the anchor (over the head, or an earlier event) proven and timestamped - but
 * not, by itself, trustworthy when the bundle has redacted stubs (ADR-0028: a stub can re-root a
 * forged record onto a real anchor). */
function anchorChecksPass(r: VerifyBundleResult): boolean {
  return Boolean(r.chain_valid && r.inclusion_valid && r.timestamp_valid);
}

function verdictOf(prod: VerifyBundleResult, dev: VerifyBundleResult): Verdict {
  if (prod.fully_verified) return "verified";
  if (!prod.anchored) return prod.chain_valid ? "not_anchored" : "failed";
  if (anchorChecksPass(prod) && prod.redacted_events > 0) return "receipt";
  if (anchorChecksPass(prod)) return "partial";
  if (anchorChecksPass(dev)) return "development";
  return "failed";
}

/** Match against the anchored events; a hash that only a later (unproven) event records is
 * reported as such, never as a match. */
async function matchProven(
  proven: JsonObject[],
  later: JsonObject[],
  pdf: Uint8Array,
): Promise<PdfMatch> {
  const m = await matchPdf(proven, pdf);
  if (later.length === 0 || m.kind === "match" || m.kind === "earlier") return m;
  const after = await matchPdf([...proven, ...later], pdf);
  if (after.kind === "match" || after.kind === "earlier" || after.kind === "unsigned_input") {
    return { kind: "after_anchor", sha256: after.sha256 };
  }
  return m;
}

/** With redacted stubs in the bundle, a visible sealed-PDF hash may belong to a forged record
 * re-rooted onto a genuine anchor (ADR-0028), so no PDF result can be vouched for. */
function provable(m: PdfMatch, redacted: number): PdfMatch {
  if (redacted === 0 || m.kind === "none" || m.kind === "unavailable") return m;
  return { kind: "unprovable", sha256: m.sha256 };
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
  const verdict = verdictOf(prod, dev);
  const devTimestamp = prod.timestamp_valid === false && dev.timestamp_valid === true;
  const result = devTimestamp ? dev : prod;
  // ADR-0027: an anchor over an earlier event proves only the events up to it. Anyone can append
  // self-consistent events after it, so status, revocation and the PDF match come from the
  // anchored prefix; the rest is shown as unproven.
  const cut = result.anchored_events ?? allEvents.length;
  const events = visibleEvents(allEvents.slice(0, cut));
  const later = visibleEvents(allEvents.slice(cut));
  const revokedEvent = [...events].reverse().find((e) => e.type === "envelope.revoked");
  return {
    verdict,
    result,
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
    timeline: [...events, ...later].map((e, i) => ({
      type: e.type as string,
      actor: str(e.actor) ?? "",
      occurredAt: str(e.occurred_at),
      unproven: i >= events.length,
    })),
    pdf: pdf
      ? provable(await matchProven(events, later, pdf), prod.redacted_events)
      : { kind: "none" },
  };
}
