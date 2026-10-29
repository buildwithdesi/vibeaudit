# OSV-Scanner and Cosign cost check

Checked: 2026-08-30

## Verdict

OSV-Scanner and Sigstore Cosign are free, open-source tools. Neither requires a paid software license for Vibe Audit.

## Evidence

- **OSV-Scanner:** The official repository uses the Apache License 2.0. That license grants a no-charge, royalty-free copyright and patent license. The hosted OSV API also currently documents no API limits. Sources: [OSV-Scanner license](https://github.com/google/osv-scanner/blob/main/LICENSE), [OSV API](https://google.github.io/osv.dev/api/).
- **Cosign:** The official repository also uses the Apache License 2.0. Sigstore states that its project is 100% open source, free to use, and operates a public-good nonprofit service. Sources: [Cosign license](https://github.com/sigstore/cosign/blob/main/LICENSE), [Sigstore overview](https://docs.sigstore.dev/).
- **Possible outside costs:** CI minutes, artifact registry storage, network use, or infrastructure for a private Sigstore deployment may cost money. Those are operational costs from the chosen hosting providers, not OSV-Scanner or Cosign license fees.

## Roadmap order

The next item in the supplied Vibe Audit roadmap is **Semgrep, fourth**. It follows OSV-Scanner and Cosign. OpenSSF Scorecard follows Semgrep.

Semgrep should remain an optional deep adapter so normal local scans stay fast.
