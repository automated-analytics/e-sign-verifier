/**
 * Browser port of the reference evidence verifier: `api/app/core/evidence.py:verify_bundle`,
 * `audit_chain.compute_event_hash`, and `merkle.verify_inclusion`. Same inputs, same result
 * fields, same short-circuit order, so the shared golden vectors (`testdata/evidence_vectors.json`)
 * pass on both sides. Runs entirely on WebCrypto - no network.
 *
 * Where Python would raise on a structurally broken bundle (a missing key, a non-object event),
 * this throws `MalformedBundle`. It is deliberately a little STRICTER than Python about shapes
 * Python never produces (e.g. a non-string `this_hash` on a redacted event, a non-list `events`):
 * those are reported as malformed instead of "chain invalid". Either way nothing verifies.
 */

import { concat, fromHexPy, sha256Hex, utf8 } from "./bytes";
import { canonicalJson, isObject, pyTruthy, type Json, type JsonObject } from "./json";
import { verifyTimestamp, type TimestampMode } from "./timestamp";

export const ZERO_HASH = "0".repeat(64);

export class MalformedBundle extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MalformedBundle";
  }
}

/** Mirrors `app.models.schemas.VerifyBundleResult`. */
export interface VerifyBundleResult {
  chain_valid: boolean;
  anchored: boolean;
  inclusion_valid: boolean | null;
  timestamp_valid: boolean | null;
  fully_verified: boolean;
  head: string;
}

/** `obj[key]` with Python's KeyError/TypeError semantics. */
function req(obj: Json | undefined, key: string): Json {
  if (!isObject(obj)) throw new MalformedBundle(`expected an object holding "${key}"`);
  if (!Object.prototype.hasOwnProperty.call(obj, key)) {
    throw new MalformedBundle(`missing "${key}"`);
  }
  return obj[key];
}

function reqString(obj: Json | undefined, key: string): string {
  const v = req(obj, key);
  if (typeof v !== "string") throw new MalformedBundle(`"${key}" must be a string`);
  return v;
}

/** `str(UUID(s))`: accepts `urn:uuid:`, braces, any case, with or without hyphens. */
export function normalizeUuid(v: Json): string {
  if (typeof v !== "string") throw new MalformedBundle("ledger_id must be a string");
  const hex = v.replace(/urn:/g, "").replace(/uuid:/g, "").replace(/^[{}]+|[{}]+$/g, "")
    .replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new MalformedBundle("badly formed ledger_id");
  const h = hex.toLowerCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** `audit_chain.compute_event_hash`. */
export async function computeEventHash(e: {
  ledger_id: string;
  type: Json;
  actor: Json;
  payload: Json;
  prev_hash: string;
}): Promise<string> {
  const body: JsonObject = {
    ledger_id: e.ledger_id,
    type: e.type,
    actor: e.actor,
    payload: e.payload,
    prev_hash: e.prev_hash,
  };
  return sha256Hex(utf8(canonicalJson(body)));
}

async function pair(a: string, b: string): Promise<string> {
  return sha256Hex(concat(fromHexPy(a), fromHexPy(b)));
}

/** `merkle.verify_inclusion`. */
export async function verifyInclusion(leaf: string, proof: Json, root: Json): Promise<boolean> {
  if (!Array.isArray(proof)) throw new MalformedBundle("inclusion_proof must be a list");
  let acc = leaf;
  for (const step of proof) {
    const sib = reqString(step, "hash");
    acc = pyTruthy(req(step, "right")) ? await pair(acc, sib) : await pair(sib, acc);
  }
  return acc === root;
}

/** `evidence.verify_bundle`. `mode` selects the timestamp verifier, like the api's dev_mode;
 * `pinnedRootPem` overrides the pinned TSA root (tests only - the page always uses the pin). */
export async function verifyBundle(
  bundle: Json,
  mode: TimestampMode,
  pinnedRootPem?: string,
): Promise<VerifyBundleResult> {
  if (!isObject(bundle)) throw new MalformedBundle("an evidence bundle is a JSON object");
  const events = Object.prototype.hasOwnProperty.call(bundle, "events") ? bundle.events : [];
  if (!Array.isArray(events)) throw new MalformedBundle("events must be a list");

  let prev = ZERO_HASH;
  let chainValid = true;
  for (const e of events) {
    if (!isObject(e)) throw new MalformedBundle("each event must be an object");
    if (pyTruthy(e.redacted)) {
      if (req(e, "prev_hash") !== prev) {
        chainValid = false;
        break;
      }
      prev = reqString(e, "this_hash");
      continue;
    }
    const expected = await computeEventHash({
      ledger_id: normalizeUuid(req(e, "ledger_id")),
      type: req(e, "type"),
      actor: req(e, "actor"),
      payload: req(e, "payload"),
      prev_hash: prev,
    });
    if (req(e, "prev_hash") !== prev || expected !== req(e, "this_hash")) {
      chainValid = false;
      break;
    }
    prev = expected;
  }
  const head = prev;
  chainValid = chainValid && head === bundle.head;

  const anchor = bundle.anchor ?? null;
  let inclusionValid: boolean | null = null;
  let timestampValid: boolean | null = null;
  if (anchor !== null) {
    try {
      inclusionValid =
        req(anchor, "leaf_hash") === head &&
        (await verifyInclusion(head, req(anchor, "inclusion_proof"), req(anchor, "merkle_root")));
    } catch (err) {
      if (err instanceof MalformedBundle) throw err;
      throw new MalformedBundle(String(err)); // e.g. a non-hex proof hash (Python: ValueError)
    }
    timestampValid = await verifyTimestamp(
      req(anchor, "tsa_token"),
      req(anchor, "merkle_root"),
      mode,
      pinnedRootPem,
    );
  }
  return {
    chain_valid: chainValid,
    anchored: anchor !== null,
    inclusion_valid: inclusionValid,
    timestamp_valid: timestampValid,
    fully_verified: Boolean(chainValid && anchor !== null && inclusionValid && timestampValid),
    head,
  };
}
