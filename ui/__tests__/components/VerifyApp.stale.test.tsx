import { expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import type { Report } from "@/lib/verify/report";

// Control when each verification resolves, to prove an out-of-date result never replaces the
// current one (the first file finishes verifying AFTER the second was dropped).
const pending: ((r: Report) => void)[] = [];
vi.mock("@/lib/verify/report", () => ({
  buildReport: () => new Promise<Report>((resolve) => pending.push(resolve)),
}));

const { VerifyApp } = await import("@/components/verify/VerifyApp");

const report = (verdict: Report["verdict"]): Report => ({
  verdict,
  result: null,
  devTimestamp: false,
  trustedTime: null,
  error: "x",
  ledgerId: null,
  status: "unknown",
  revoked: null,
  redactedCount: 0,
  eventCount: 0,
  anchoredAt: null,
  timeline: [],
  pdf: { kind: "none" },
});

it("a verified timestamp without a readable genTime omits the time", async () => {
  pending.length = 0;
  render(<VerifyApp />);
  await act(async () => {
    fireEvent.change(screen.getByLabelText("Evidence bundle"), {
      target: { files: [new File(["{}"], "b.json")] },
    });
  });
  const result = { chain_valid: true, anchored: true, inclusion_valid: true, timestamp_valid: true,
    fully_verified: true, redacted_events: 0, anchored_events: 1, events_after_anchor: 0,
    head: "h" };
  await act(async () => pending[0]({ ...report("verified"), result }));
  expect(
    screen.getByText(/^Signed by DigiCert's timestamp authority, checked against/),
  ).toBeInTheDocument();
});

it("ignores a verification that finishes after its input was replaced", async () => {
  pending.length = 0;
  render(<VerifyApp />);
  const input = screen.getByLabelText("Evidence bundle");
  await act(async () => {
    fireEvent.change(input, { target: { files: [new File(["{}"], "first.json")] } });
  });
  await act(async () => {
    fireEvent.change(input, { target: { files: [new File(["{}"], "second.json")] } });
  });
  expect(pending).toHaveLength(2);
  await act(async () => pending[1](report("failed")));
  await act(async () => pending[0](report("not_anchored"))); // stale: must be ignored
  expect(screen.getByText("Does not verify")).toBeInTheDocument();
  expect(screen.queryByText("Intact, but not timestamped yet")).not.toBeInTheDocument();
});
