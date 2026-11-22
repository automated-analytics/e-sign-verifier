// Entry point of the standalone verifier page (public/verify.html, built by
// scripts/build-verifier.mjs). Not a Next.js route: it ships as ONE self-contained HTML file so a
// saved copy works fully offline, with no framework runtime fetching chunks.
import { createRoot } from "react-dom/client";
import { VerifyApp } from "@/components/verify/VerifyApp";

const root = document.getElementById("root");
if (root) createRoot(root).render(<VerifyApp />);
