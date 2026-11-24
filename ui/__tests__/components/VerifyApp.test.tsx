import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { headline, isPdf, pdfCheck, VerifyApp } from "@/components/verify/VerifyApp";
import { b64decodePy } from "@/lib/verify/bytes";
import { canonicalJson, parseJson, type JsonObject } from "@/lib/verify/json";
import type { Report } from "@/lib/verify/report";

const vectors = parseJson(
  readFileSync(resolve(__dirname, "../../../testdata/evidence_vectors.json"), "utf8"),
) as JsonObject;
const vec = (name: string) => (vectors.bundles as JsonObject[]).find((v) => v.name === name)!;
const bundleFile = (name: string, json?: string) =>
  new File([json ?? canonicalJson(vec(name).bundle)], `${name}.json`, { type: "application/json" });
const pdfs = (vec("valid_full").pdfs as JsonObject[]).map((p) => b64decodePy(p.b64 as string));
const sealedPdf = new File([new Uint8Array(pdfs[0])], "sealed.pdf", { type: "application/pdf" });
const otherPdf = new File([new Uint8Array(pdfs[1])], "other.pdf", { type: "application/pdf" });

async function upload(...files: File[]) {
  const user = userEvent.setup({ applyAccept: false });
  for (const f of files) {
    await user.upload(screen.getByLabelText(isPdfName(f) ? "Sealed PDF" : "Evidence bundle"), f);
  }
}
const isPdfName = (f: File) => f.name.endsWith(".pdf");

describe("VerifyApp", () => {
  it("starts empty with both pickers and the explanation", () => {
    render(<VerifyApp />);
    expect(screen.getByRole("heading", { name: "Verify a signed record" })).toBeInTheDocument();
    expect(screen.getByText(/this page cannot make network requests/)).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("the buttons open the hidden file pickers", async () => {
    render(<VerifyApp />);
    const bundleClick = vi.spyOn(screen.getByLabelText("Evidence bundle"), "click");
    const pdfClick = vi.spyOn(screen.getByLabelText("Sealed PDF"), "click");
    await userEvent.click(screen.getByRole("button", { name: "Choose evidence bundle" }));
    await userEvent.click(screen.getByRole("button", { name: "Choose sealed PDF" }));
    expect(bundleClick).toHaveBeenCalled();
    expect(pdfClick).toHaveBeenCalled();
  });

  it("verifies a development bundle and a matching PDF", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("valid_full"), sealedPdf);
    expect(await screen.findByText("Valid test record - not evidence")).toBeInTheDocument();
    expect(screen.getByText("Audit trail is complete and unaltered")).toBeInTheDocument();
    expect(screen.getByText("Included in a timestamped anchor")).toBeInTheDocument();
    expect(screen.getByText("Development stand-in token: not trusted time.")).toBeInTheDocument();
    expect(await screen.findByText("PDF matches the sealed record (sealed.pdf)")).toBeInTheDocument();
    expect(screen.getByText(/Bundle:/)).toHaveTextContent("Bundle: valid_full.json · PDF: sealed.pdf");
    expect(screen.getByText("Technical details")).toBeInTheDocument();
    expect(screen.getAllByText("envelope.completed").length).toBeGreaterThan(0);
  });

  it("does not vouch for a PDF when the record itself fails", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("tampered_event_payload"), sealedPdf);
    expect(await screen.findByText("Does not verify")).toBeInTheDocument();
    expect(
      await screen.findByText("PDF cannot be checked against the sealed record (sealed.pdf)"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/^PDF matches/)).not.toBeInTheDocument();
    expect(screen.getByText(/record itself does not verify/)).toBeInTheDocument();
  });

  it("an old redacted receipt says the PDF can't be checked, not that it is wrong", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("redacted_valid"), sealedPdf);
    expect(
      await screen.findByText("PDF cannot be checked against the sealed record (sealed.pdf)"),
    ).toBeInTheDocument();
    expect(screen.getByRole("status")).not.toHaveTextContent(/not its sealed document/);
    expect(screen.getByRole("status")).toHaveTextContent(/PDF could not be checked/);
  });

  it("flags a PDF that is not the sealed record", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("valid_full"), otherPdf);
    expect(
      await screen.findByText("Valid test record, but this PDF is not its sealed document"),
    ).toBeInTheDocument();
    expect(screen.getByText("PDF does not match the sealed record (other.pdf)")).toBeInTheDocument();
  });

  it("rejects a tampered bundle with failure-worded checks", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("tampered_event_payload"));
    expect(await screen.findByText("Does not verify")).toBeInTheDocument();
    expect(screen.getByText("Audit trail has been altered or is incomplete")).toBeInTheDocument();
    expect(screen.getByText("Not proven to be in the timestamped anchor")).toBeInTheDocument();
    expect(screen.getAllByLabelText("fail").length).toBeGreaterThan(0);
  });

  it("explains an unanchored bundle", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("valid_unanchored"));
    expect(await screen.findByText("Intact, but not timestamped yet")).toBeInTheDocument();
    expect(screen.getByText(/the daily anchor has not covered/)).toBeInTheDocument();
    expect(screen.getByText("No timestamp yet.")).toBeInTheDocument();
    expect(screen.getAllByLabelText("not applicable").length).toBeGreaterThan(0);
  });

  it("explains a production bundle whose timestamp is not from the pinned TSA", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("valid_full_prod_test_ca"));
    expect(await screen.findByText("Does not verify")).toBeInTheDocument();
    expect(
      screen.getByText("The timestamp token is missing, forged, or covers a different anchor."),
    ).toBeInTheDocument();
  });

  it("shows revocation", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("revoked"));
    expect(await screen.findByText("Revoked on 2026-11-17T10:06:00Z")).toBeInTheDocument();
    expect(screen.getByText("Reason given: issued in error")).toBeInTheDocument();
  });

  it("explains a redacted receipt and that its PDF cannot be checked", async () => {
    render(<VerifyApp />);
    await upload(bundleFile("redacted_valid"), sealedPdf);
    expect(await screen.findByText(/This is a signer's receipt: 5 of 8 events/)).toBeInTheDocument();
    expect(
      await screen.findByText("PDF cannot be checked against the sealed record (sealed.pdf)"),
    ).toBeInTheDocument();
  });

  it("says what is wrong with a file that is not a bundle", async () => {
    render(<VerifyApp />);
    await upload(new File(["not json"], "x.json"));
    expect(await screen.findByText("This is not an evidence bundle")).toBeInTheDocument();
    expect(screen.getByText("This file is not valid JSON.")).toBeInTheDocument();
    expect(screen.queryByText("Technical details")).not.toBeInTheDocument();
  });

  it("asks for the bundle when only a PDF was given", async () => {
    render(<VerifyApp />);
    await upload(sealedPdf);
    expect(
      await screen.findByText("Now add the evidence bundle the PDF belongs to."),
    ).toBeInTheDocument();
  });

  it("accepts both files dropped at once, sorting them by content", async () => {
    render(<VerifyApp />);
    const zone = screen.getByTestId("dropzone");
    fireEvent.dragOver(zone);
    expect(zone.className).toContain("border-brand-500");
    fireEvent.dragLeave(zone);
    expect(zone.className).not.toContain("border-brand-500");
    await act(async () => {
      fireEvent.drop(zone, { dataTransfer: { files: [sealedPdf, bundleFile("valid_full")] } });
    });
    expect(await screen.findByText("PDF matches the sealed record (sealed.pdf)")).toBeInTheDocument();
  });

  it("shows a production-verified bundle as Verified (test CA pinned)", async () => {
    render(<VerifyApp pinnedRootPem={vec("valid_full_prod_test_ca").pinned_root_pem as string} />);
    await upload(bundleFile("valid_full_prod_test_ca"), sealedPdf);
    expect(await screen.findByText("Verified")).toBeInTheDocument();
    expect(
      screen.getByText(/Signed by DigiCert's timestamp authority at 2026-07-11T21:06:17Z/),
    ).toBeInTheDocument();
  });

  it("shows a record timestamped up to an earlier event as verified up to that point", async () => {
    const v = vec("anchor_covers_earlier_event_prod_test_ca");
    render(<VerifyApp pinnedRootPem={v.pinned_root_pem as string} />);
    await upload(bundleFile("anchor_covers_earlier_event_prod_test_ca"), sealedPdf);
    expect(await screen.findByText("Verified up to its last timestamp")).toBeInTheDocument();
    expect(screen.getByText(/2 later events were recorded after that timestamp/)).toBeInTheDocument();
    expect(screen.getByText(/The 2 events after it are not timestamped yet/)).toBeInTheDocument();
    // envelope.completed sits AFTER the anchored event: unproven, so it is never a match, and the
    // status comes from the anchored part only (review B1).
    expect(
      await screen.findByText("PDF cannot be checked against the sealed record (sealed.pdf)"),
    ).toBeInTheDocument();
    expect(screen.getByText(/appears only in an entry recorded after the last timestamp/))
      .toBeInTheDocument();
    expect(screen.queryByText(/PDF matches/)).not.toBeInTheDocument();
    expect(screen.getAllByText("(after the last timestamp - unproven)")).toHaveLength(2);
    expect(screen.queryByText(/Revoked/)).not.toBeInTheDocument();
  });

  it("names a single event after the timestamp in the singular", async () => {
    const v = vec("anchor_covers_earlier_event_prod_test_ca");
    const b = parseJson(canonicalJson(v.bundle)) as JsonObject;
    const events = b.events as JsonObject[];
    events.pop();
    b.head = events[events.length - 1].this_hash;
    render(<VerifyApp pinnedRootPem={v.pinned_root_pem as string} />);
    await upload(bundleFile("anchor_covers_earlier_event_prod_test_ca", canonicalJson(b)));
    expect(await screen.findByText(/The 1 event after it is not timestamped yet/)).toBeInTheDocument();
  });

  it("matches the PDF when the sealed hash is inside the anchored part", async () => {
    const v = vec("anchor_covers_completion_then_webhook_prod_test_ca");
    render(<VerifyApp pinnedRootPem={v.pinned_root_pem as string} />);
    await upload(bundleFile("anchor_covers_completion_then_webhook_prod_test_ca"), sealedPdf);
    expect(await screen.findByText("Verified up to its last timestamp")).toBeInTheDocument();
    expect(await screen.findByText("PDF matches the sealed record (sealed.pdf)")).toBeInTheDocument();
  });

  it("never vouches for a forged completion appended after the anchored part", async () => {
    const v = vec("forged_completion_after_anchor_prod_test_ca");
    const attackerPdf = new File(
      [new Uint8Array(b64decodePy((v.pdfs as JsonObject[])[0].b64 as string))],
      "attacker.pdf",
      { type: "application/pdf" },
    );
    render(<VerifyApp pinnedRootPem={v.pinned_root_pem as string} />);
    await upload(bundleFile("forged_completion_after_anchor_prod_test_ca"), attackerPdf);
    expect(await screen.findByText("Verified up to its last timestamp")).toBeInTheDocument();
    expect(
      await screen.findByText("PDF cannot be checked against the sealed record (attacker.pdf)"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/PDF matches/)).not.toBeInTheDocument();
  });

  it("flags the wrong PDF against a record verified up to an earlier event", async () => {
    const v = vec("anchor_covers_completion_then_webhook_prod_test_ca");
    render(<VerifyApp pinnedRootPem={v.pinned_root_pem as string} />);
    await upload(bundleFile("anchor_covers_completion_then_webhook_prod_test_ca"), otherPdf);
    expect(
      await screen.findByText(
        "Proven up to its last timestamp, but this PDF is not the sealed document",
      ),
    ).toBeInTheDocument();
  });

  it("never shows a forged record re-rooted by a redacted stub as Verified (ADR-0028)", async () => {
    const v = vec("forged_record_redacted_stub_reroots");
    const attackerPdf = new File(
      [new Uint8Array(b64decodePy((v.pdfs as JsonObject[])[0].b64 as string))],
      "attacker.pdf",
      { type: "application/pdf" },
    );
    render(<VerifyApp pinnedRootPem={v.pinned_root_pem as string} />);
    await upload(bundleFile("forged_record_redacted_stub_reroots"), attackerPdf);
    expect(
      await screen.findByText("Receipt checks out, but cannot prove the record on its own"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Verified")).not.toBeInTheDocument();
    expect(
      await screen.findByText("PDF cannot be checked against the sealed record (attacker.pdf)"),
    ).toBeInTheDocument();
    expect(screen.getByText(/the document hashes it shows cannot be trusted/)).toBeInTheDocument();
    expect(screen.queryByText(/PDF matches/)).not.toBeInTheDocument();
  });

  it("copes with missing optional metadata (dates, ledger id), which is not hashed", async () => {
    const b = parseJson(canonicalJson(vec("revoked").bundle)) as JsonObject;
    delete b.ledger_id;
    for (const e of b.events as JsonObject[]) delete e.occurred_at;
    render(<VerifyApp />);
    await upload(bundleFile("revoked", canonicalJson(b)));
    expect(await screen.findByText("Revoked")).toBeInTheDocument();
    expect(screen.getByText("Ledger").nextSibling).toHaveTextContent("-");
  });

  it("tolerates a picker change with no files", async () => {
    render(<VerifyApp />);
    fireEvent.change(screen.getByLabelText("Evidence bundle"), { target: { files: null } });
    await waitFor(() => expect(screen.queryByRole("status")).not.toBeInTheDocument());
  });
});

describe("helpers", () => {
  const base: Report = {
    verdict: "verified",
    result: null,
    devTimestamp: false,
    trustedTime: null,
    error: null,
    ledgerId: null,
    status: "completed",
    revoked: null,
    redactedCount: 0,
    eventCount: 0,
    anchoredAt: null,
    timeline: [],
    pdf: { kind: "none" },
  };

  it("headline: verified, verified+revoked, verified+wrong PDF, invalid fallback", () => {
    expect(headline(base)).toMatchObject({ tone: "good", title: "Verified" });
    expect(headline({ ...base, status: "revoked" }).title).toMatch(/revoked/);
    expect(headline({ ...base, pdf: { kind: "mismatch", sha256: "x" } }).title).toMatch(
      /not the sealed document/,
    );
    expect(headline({ ...base, verdict: "invalid" }).body).toBe("The file could not be read.");
  });

  it("headline: a PDF the bundle cannot check is not called a mismatch", () => {
    const unavailable = { kind: "unavailable", sha256: "x" } as const;
    for (const verdict of ["verified", "development"] as const) {
      const h = headline({ ...base, verdict, pdf: unavailable });
      expect(h.title).not.toMatch(/not (the|its) sealed document/);
      expect(h.title).toMatch(/PDF could not be checked/);
      expect(h.tone).toBe("warn");
    }
  });

  it("pdfCheck never passes a PDF against a record that does not verify", () => {
    expect(pdfCheck({ kind: "match", sha256: "x" }, false)).toMatchObject({ ok: null });
    expect(pdfCheck({ kind: "mismatch", sha256: "x" }, false)).toMatchObject({ ok: null });
    expect(pdfCheck({ kind: "match", sha256: "x" })).toMatchObject({ ok: true });
  });

  it("headline: a dev record with later events says so", () => {
    const dev = (n: number) =>
      headline({
        ...base,
        verdict: "development",
        result: {
          chain_valid: true,
          anchored: true,
          inclusion_valid: true,
          timestamp_valid: true,
          fully_verified: false,
          redacted_events: 0,
          anchored_events: 3,
          events_after_anchor: n,
          head: "h",
        },
      }).body;
    expect(dev(1)).toMatch(/1 later event is unproven/);
    expect(dev(2)).toMatch(/2 later events are unproven/);
    expect(dev(0)).toMatch(/^Everything checks out/);
  });

  it("headline: partial, with one later event and no trusted time", () => {
    const partial = {
      ...base,
      verdict: "partial" as const,
      result: {
        chain_valid: true,
        anchored: true,
        inclusion_valid: true,
        timestamp_valid: true,
        fully_verified: false,
        redacted_events: 0,
        anchored_events: 3,
        events_after_anchor: 1,
        head: "h",
      },
    };
    expect(headline(partial).body).toMatch(/1 later event was recorded/);
    expect(headline(partial).body).toMatch(/timestamped by DigiCert\. /);
    expect(headline({ ...partial, result: null }).body).toMatch(/0 later events were recorded/);
  });

  it("pdfCheck explains intermediate seals and pre-signing inputs", () => {
    expect(pdfCheck({ kind: "earlier", sha256: "x" })).toMatchObject({ ok: false });
    expect(pdfCheck({ kind: "unsigned_input", sha256: "x" })?.text).toMatch(/BEFORE a signer/);
  });

  it("isPdf checks the %PDF- magic", () => {
    expect(isPdf(new TextEncoder().encode("%PDF-1.7"))).toBe(true);
    expect(isPdf(new TextEncoder().encode("{}"))).toBe(false);
  });
});
