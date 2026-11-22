# e-sign evidence verifier

This is the source of e-sign's public evidence verifier: the `/verify` page that checks an e-sign
evidence bundle, and optionally the sealed PDF, entirely in your browser. You can audit it here and
rebuild the page byte for byte.

The page is one self-contained HTML file. Its Content-Security-Policy allows only its own inline
script and style (pinned by sha256) and forbids all network access. A saved copy works offline,
and nothing you drop on it leaves your machine.

This repository is an **export**. Each tag here is copied, on release, from the e-sign release with
the same tag. It is not developed here, so changes land upstream first. `EXPORT.json` records the
source tag and commit, the sha256 of every file in the export, and the sha256 of the `verify.html`
that e-sign built from that commit.

## What's here

| Path | What it is |
|---|---|
| `ui/lib/verify/` | The verifier: canonical JSON, the audit hash chain, Merkle inclusion, RFC 3161 timestamp and certificate-chain checks (DER parsing + WebCrypto), and the report |
| `ui/components/verify/VerifyApp.tsx` | The page UI (React) |
| `ui/verifier/` | The page entry point and its HTML template (with the CSP placeholder) |
| `ui/scripts/build-verifier.mjs` | The build: bundles the JS (Vite), compiles the CSS (Tailwind), inlines the pinned TSA root, and writes `verify.html` with a hash-pinned CSP |
| `ui/app/globals.css`, `ui/tailwind.config.js` | The stylesheet input |
| `api/app/assets/digicert_trusted_root_g4.pem` | The pinned timestamp-authority trust anchor (the public DigiCert Trusted Root G4), inlined at build time |
| `testdata/evidence_vectors.json` | Golden vectors. The same file is run against e-sign's Python reference verifier, so the two cannot drift apart |
| `ui/__tests__/` | The vitest suites: the golden vectors, unit tests, and page tests |
| `ui/package.json`, `ui/package-lock.json` | The only generated files: e-sign's manifest and lockfile narrowed to the verifier's dependencies, with the same locked versions and integrity hashes |

Every other file is byte-identical to the same path in the e-sign source at the tagged commit.

## Rebuild and check the hash

You need Node.js 20 (the version e-sign's CI builds with) and npm.

```bash
git clone https://github.com/automated-analytics/e-sign-verifier.git
cd e-sign-verifier
git checkout <tag>                         # e.g. v2.1.0
cd ui
npm ci                                     # exact versions from package-lock.json
npm test                                   # golden vectors + unit + page tests
npm run build:verifier -- --out ../verify.html
cd ..
shasum -a 256 verify.html                  # or: sha256sum verify.html
```

The build also prints the sha256 of the file it wrote. Compare it with:

1. **This repo's release for `<tag>`.** Its `verify.html.sha256` asset holds the hash that this
   repo's CI got by building the tagged source in public. Its `verify.html` asset is that build.
2. **e-sign's own release for `<tag>`.** e-sign attaches the `verify.html` it deployed, with its
   sha256. Before tagging here, the export job checks that building this tree gives exactly those
   bytes.
3. **The live page.** Save the deployed `/verify` page as raw bytes (for example
   `curl -s https://<e-sign host>/verify -o live.html`, without `--compressed` rewriting), then
   hash it.

The three hashes should all match. Each build is deterministic: the same source and the same
locked dependencies give the same bytes. If you get a different hash, check your Node major
version first. Then confirm that `npm ci`, rather than `npm install`, built your `node_modules`.

## Verifying the page itself

Open the built `verify.html` straight from disk. The `<meta http-equiv="Content-Security-Policy">`
in its `<head>` lists `script-src 'sha256-…'` and `style-src 'sha256-…'`. You can recompute both
from the inline `<script>` and `<style>` contents. `connect-src 'none'` and `default-src 'none'`
mean the browser itself blocks any network request the code might attempt.

## License

Apache License 2.0. See [LICENSE](LICENSE).
