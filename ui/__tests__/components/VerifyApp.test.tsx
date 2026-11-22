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

  it("pdfCheck explains intermediate seals and pre-signing inputs", () => {
    expect(pdfCheck({ kind: "earlier", sha256: "x" })).toMatchObject({ ok: false });
    expect(pdfCheck({ kind: "unsigned_input", sha256: "x" })?.text).toMatch(/BEFORE a signer/);
  });

  it("isPdf checks the %PDF- magic", () => {
    expect(isPdf(new TextEncoder().encode("%PDF-1.7"))).toBe(true);
    expect(isPdf(new TextEncoder().encode("{}"))).toBe(false);
  });
});
