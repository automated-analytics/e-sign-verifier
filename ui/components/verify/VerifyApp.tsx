"use client";

import { useCallback, useEffect, useRef, useState, type DragEvent, type ReactNode } from "react";
import { buildReport, type PdfMatch, type Report } from "@/lib/verify/report";

/**
 * The public, browser-only verifier (docs/specs/public-verify-page.md). A visitor drops an
 * evidence bundle (and optionally the sealed PDF); every check runs here, on WebCrypto. The page
 * makes no network requests - its Content-Security-Policy forbids them (`connect-src 'none'`).
 */

type Tone = "good" | "warn" | "bad";

interface Loaded {
  name: string;
  bytes: Uint8Array;
}

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46, 0x2d]; // "%PDF-"

export function isPdf(bytes: Uint8Array): boolean {
  return PDF_MAGIC.every((b, i) => bytes[i] === b);
}

async function readFile(file: File): Promise<Loaded> {
  return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
}

export function headline(r: Report): { tone: Tone; title: string; body: string } {
  const pdfBad = r.pdf.kind !== "none" && r.pdf.kind !== "match";
  switch (r.verdict) {
    case "verified":
      if (r.status === "revoked") {
        return {
          tone: "bad",
          title: "Genuine record - but it has been revoked",
          body: "The audit trail is authentic and unaltered, and it records that the issuer later revoked this envelope. Do not rely on it.",
        };
      }
      if (pdfBad) {
        return {
          tone: "bad",
          title: "The record is genuine, but this PDF is not the sealed document",
          body: "The evidence verifies, but the PDF you supplied is not the one e-sign sealed for it.",
        };
      }
      return {
        tone: "good",
        title: "Verified",
        body: "This audit trail is complete and unaltered, and a trusted timestamp authority (DigiCert) proves it existed in this form at the anchor time.",
      };
    case "development":
      if (pdfBad) {
        return {
          tone: "bad",
          title: "Valid test record, but this PDF is not its sealed document",
          body: "The evidence checks out (with a development timestamp, which is not trusted time), but the PDF you supplied is not the one sealed for it.",
        };
      }
      return {
        tone: "warn",
        title: "Valid test record - not evidence",
        body: "Everything checks out, but the timestamp is the local stand-in a development server uses, which anyone can create. Records from a real deployment carry a DigiCert timestamp.",
      };
    case "not_anchored":
      return {
        tone: "warn",
        title: "Intact, but not timestamped yet",
        body: "The audit trail is internally consistent, but it has not been anchored to a trusted timestamp yet, so it cannot prove when it existed. Download the bundle again later.",
      };
    case "failed":
      return {
        tone: "bad",
        title: "Does not verify",
        body: "This record has been altered, is incomplete, or was not produced by e-sign. Do not rely on it.",
      };
    default:
      return {
        tone: "bad",
        title: "This is not an evidence bundle",
        body: r.error ?? "The file could not be read.",
      };
  }
}

const TONE = {
  good: "border-emerald-300 bg-emerald-50 text-emerald-900",
  warn: "border-amber-300 bg-amber-50 text-amber-900",
  bad: "border-rose-300 bg-rose-50 text-rose-900",
} as const;

function Mark({ ok }: { ok: boolean | null }) {
  if (ok === null) {
    return (
      <span aria-label="not applicable" className="mt-0.5 h-5 w-5 shrink-0 rounded-full border-2 border-slate-300" />
    );
  }
  return ok ? (
    <svg aria-label="pass" className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.7-9.3a1 1 0 0 0-1.4-1.4L9 10.6 7.7 9.3a1 1 0 0 0-1.4 1.4l2 2a1 1 0 0 0 1.4 0l4-4Z" clipRule="evenodd" />
    </svg>
  ) : (
    <svg aria-label="fail" className="mt-0.5 h-5 w-5 shrink-0 text-rose-600" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16ZM8.7 7.3a1 1 0 0 0-1.4 1.4L8.6 10l-1.3 1.3a1 1 0 1 0 1.4 1.4l1.3-1.3 1.3 1.3a1 1 0 0 0 1.4-1.4L11.4 10l1.3-1.3a1 1 0 0 0-1.4-1.4L10 8.6 8.7 7.3Z" clipRule="evenodd" />
    </svg>
  );
}

function Check({ ok, title, children }: { ok: boolean | null; title: string; children: ReactNode }) {
  return (
    <li className="flex gap-3 py-3">
      <Mark ok={ok} />
      <div>
        <p className="font-medium text-slate-900">{title}</p>
        <p className="text-sm text-slate-600">{children}</p>
      </div>
    </li>
  );
}

export function pdfCheck(pdf: PdfMatch): { ok: boolean | null; text: string } | null {
  switch (pdf.kind) {
    case "none":
      return null;
    case "match":
      return { ok: true, text: "Its SHA-256 equals the sealed record's hash in the audit trail." };
    case "earlier":
      return {
        ok: false,
        text: "This is an earlier, intermediate seal: another signer signed after it. Ask for the final sealed PDF.",
      };
    case "unsigned_input":
      return {
        ok: false,
        text: "This is a document as it was BEFORE a signer signed it, not the sealed record.",
      };
    case "unavailable":
      return {
        ok: null,
        text: "This bundle does not show the sealed record's hash (it is a signer's receipt with shared events hidden). Ask the issuing organization for the full bundle to check the PDF.",
      };
    default:
      return { ok: false, text: "Its SHA-256 does not match any document recorded in this audit trail." };
  }
}

function Results({ report, pdfName }: { report: Report; pdfName: string }) {
  const h = headline(report);
  const r = report.result;
  const pdf = pdfCheck(report.pdf);
  const dev = report.devTimestamp;
  return (
    <section aria-live="polite" className="mt-8 space-y-6">
      <div role="status" className={`rounded-xl border p-5 ${TONE[h.tone]}`}>
        <h2 className="text-lg font-semibold">{h.title}</h2>
        <p className="mt-1 text-sm">{h.body}</p>
      </div>

      {report.revoked && (report.verdict === "verified" || report.verdict === "development") && (
        <div className="rounded-xl border border-rose-300 bg-white p-4 text-sm text-rose-800">
          <p className="font-semibold">Revoked{report.revoked.occurredAt ? ` on ${report.revoked.occurredAt}` : ""}</p>
          {report.revoked.reason && <p>Reason given: {report.revoked.reason}</p>}
        </div>
      )}

      {r && (
        <ul className="divide-y divide-slate-200 rounded-xl border border-slate-200 bg-white px-5">
          <Check
            ok={r.chain_valid}
            title={r.chain_valid ? "Audit trail is complete and unaltered" : "Audit trail has been altered or is incomplete"}
          >
            {r.chain_valid
              ? "Every event's fingerprint (SHA-256 hash chain) was recomputed in your browser and links to the one before it, ending at the recorded head."
              : "Recomputing the events' fingerprints (SHA-256 hash chain) in your browser does not reproduce the recorded ones: an event was edited, removed, reordered, or the head is wrong."}
          </Check>
          <Check
            ok={r.inclusion_valid}
            title={r.inclusion_valid === false ? "Not proven to be in the timestamped anchor" : "Included in a timestamped anchor"}
          >
            {!r.anchored
              ? "Not anchored yet - the daily anchor has not covered this record."
              : r.inclusion_valid
                ? "A Merkle inclusion proof shows this audit trail's head is part of the anchored batch."
                : "The Merkle inclusion proof does not connect this audit trail's head to the anchored batch."}
          </Check>
          <Check ok={dev ? false : r.timestamp_valid} title="Trusted timestamp (RFC 3161)">
            {!r.anchored
              ? "No timestamp yet."
              : dev
                ? "Development stand-in token: not trusted time."
                : r.timestamp_valid
                  ? `Signed by DigiCert's timestamp authority${report.trustedTime ? ` at ${report.trustedTime}` : ""}, checked against the pinned DigiCert Trusted Root G4 embedded in this page.`
                  : "The timestamp token is missing, forged, or covers a different anchor."}
          </Check>
          {pdf && (
            <Check
              ok={pdf.ok}
              title={`${pdf.ok === null ? "PDF cannot be checked against" : pdf.ok ? "PDF matches" : "PDF does not match"} the sealed record (${pdfName})`}
            >
              {pdf.text}
            </Check>
          )}
        </ul>
      )}

      {report.redactedCount > 0 && (
        <p className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          This is a signer&apos;s receipt: {report.redactedCount} of {report.eventCount} events
          belong to other parties and are shown only as hashes. Their integrity is still proven
          by the anchor, but their contents (including whether the envelope was later revoked)
          are not visible here.
        </p>
      )}

      {r && (
        <details className="rounded-xl border border-slate-200 bg-white p-4 text-sm">
          <summary className="cursor-pointer font-medium text-slate-900">Technical details</summary>
          <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 break-all text-slate-700">
            <dt className="font-medium">Ledger</dt>
            <dd>{report.ledgerId ?? "-"}</dd>
            <dt className="font-medium">Chain head</dt>
            <dd className="font-mono text-xs">{r.head}</dd>
            <dt className="font-medium">Trusted time</dt>
            <dd>{report.trustedTime ?? "-"}</dd>
            <dt className="font-medium">Anchored at</dt>
            <dd>{report.anchoredAt ?? "-"} (as recorded by e-sign)</dd>
            {report.pdf.kind !== "none" && (
              <>
                <dt className="font-medium">PDF SHA-256</dt>
                <dd className="font-mono text-xs">{report.pdf.sha256}</dd>
              </>
            )}
          </dl>
          {report.timeline.length > 0 && (
            <p className="mt-3 text-xs text-slate-500">
              Visible events. Their content is covered by the hash chain; the times shown are as
              recorded by e-sign and are not. Only the trusted time above is signed by the TSA.
            </p>
          )}
          {report.timeline.length > 0 && (
            <ol className="mt-1 space-y-1 text-slate-700">
              {report.timeline.map((e, i) => (
                <li key={i}>
                  <span className="font-mono text-xs">{e.occurredAt ?? ""}</span>{" "}
                  <span className="font-medium">{e.type}</span>{" "}
                  <span className="text-slate-500">{e.actor}</span>
                </li>
              ))}
            </ol>
          )}
        </details>
      )}
    </section>
  );
}

/** `pinnedRootPem` exists for tests only; the page always uses the pin embedded at build time. */
export function VerifyApp({ pinnedRootPem }: { pinnedRootPem?: string } = {}) {
  const [bundle, setBundle] = useState<Loaded | null>(null);
  const [pdf, setPdf] = useState<Loaded | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [dragging, setDragging] = useState(false);
  const bundleInput = useRef<HTMLInputElement>(null);
  const pdfInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let live = true;
    if (!bundle) return;
    const text = new TextDecoder().decode(bundle.bytes);
    void buildReport(text, pdf?.bytes, pinnedRootPem).then((r) => {
      if (live) setReport(r);
    });
    return () => {
      live = false;
    };
  }, [bundle, pdf, pinnedRootPem]);

  const accept = useCallback(async (files: FileList | null) => {
    for (const file of Array.from(files ?? [])) {
      const loaded = await readFile(file);
      if (isPdf(loaded.bytes)) setPdf(loaded);
      else setBundle(loaded);
    }
  }, []);

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    void accept(e.dataTransfer.files);
  };

  return (
    <main className="mx-auto max-w-2xl px-4 py-10 text-slate-800">
      <header>
        <p className="text-sm font-semibold uppercase tracking-wide text-brand-700">e-sign</p>
        <h1 className="mt-1 text-2xl font-bold text-slate-900">Verify a signed record</h1>
        <p className="mt-2 text-sm text-slate-600">
          Check an e-sign evidence bundle yourself, without trusting e-sign. Everything runs in
          your browser: nothing is uploaded, and this page cannot make network requests. You can
          save it (File &rarr; Save Page As) and use it offline.
        </p>
      </header>

      <div
        data-testid="dropzone"
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`mt-6 rounded-xl border-2 border-dashed p-6 text-center ${
          dragging ? "border-brand-500 bg-brand-50" : "border-slate-300 bg-white"
        }`}
      >
        <p className="font-medium text-slate-900">Drop the evidence bundle (.json) here</p>
        <p className="text-sm text-slate-600">and, optionally, the sealed PDF to check it too</p>
        <div className="mt-4 flex flex-wrap justify-center gap-3">
          <button
            type="button"
            onClick={() => bundleInput.current?.click()}
            className="rounded-md bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-600 focus-visible:ring-offset-2"
          >
            Choose evidence bundle
          </button>
          <button
            type="button"
            onClick={() => pdfInput.current?.click()}
            className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-800 hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-600 focus-visible:ring-offset-2"
          >
            Choose sealed PDF
          </button>
        </div>
        <input
          ref={bundleInput}
          type="file"
          accept=".json,application/json"
          aria-label="Evidence bundle"
          className="hidden"
          onChange={(e) => void accept(e.target.files)}
        />
        <input
          ref={pdfInput}
          type="file"
          accept=".pdf,application/pdf"
          aria-label="Sealed PDF"
          className="hidden"
          onChange={(e) => void accept(e.target.files)}
        />
        {(bundle || pdf) && (
          <p className="mt-4 text-sm text-slate-600">
            {bundle && <>Bundle: <span className="font-medium">{bundle.name}</span></>}
            {bundle && pdf && " · "}
            {pdf && <>PDF: <span className="font-medium">{pdf.name}</span></>}
          </p>
        )}
      </div>

      {report && <Results report={report} pdfName={pdf?.name ?? ""} />}
      {!bundle && pdf && (
        <p className="mt-6 text-sm text-slate-600">Now add the evidence bundle the PDF belongs to.</p>
      )}

      <section className="mt-10 border-t border-slate-200 pt-6 text-sm text-slate-600">
        <h2 className="font-semibold text-slate-900">What is checked</h2>
        <ol className="mt-2 list-decimal space-y-1 pl-5">
          <li>Each audit event is re-hashed; any edit, deletion or reordering breaks the chain.</li>
          <li>The chain&apos;s final hash is proven to be inside a batch (Merkle tree) of anchored records.</li>
          <li>That batch is timestamped by DigiCert (RFC 3161), verified against the root certificate built into this page.</li>
          <li>If you add the PDF, its SHA-256 must equal the sealed record&apos;s hash in the audit trail.</li>
        </ol>
        <p className="mt-3">
          The evidence bundle comes from the organization that sent the document for signature
          (or, for a signer, from their own receipt). This page never contacts e-sign.
        </p>
      </section>
    </main>
  );
}
