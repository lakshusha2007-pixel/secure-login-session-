# Release Security & Provenance Documentation

## 1. Artifact Verification & Provenance

Every official release of the **Secure Login & Session Management Module** is packaged with SHA-256 integrity checksums and CycloneDX Software Bill of Materials (`sbom.json`).

### SHA-256 Checksum Generation
To generate and verify checksums locally:
```bash
# Generate SHA-256 hash for release bundle
sha256sum release-v2.0.0.zip > release-v2.0.0.zip.sha256

# Verify SHA-256 integrity hash
sha256sum -c release-v2.0.0.zip.sha256
```

---

## 2. Release Signing with Sigstore / Cosign

For production CI/CD releases, artifacts are signed using **Sigstore / Cosign**:

```bash
# Sign a release container or artifact keyless via OIDC
cosign sign-blob --key cosign.key release-v2.0.0.zip

# Verify release signature
cosign verify-blob --key cosign.pub --signature release-v2.0.0.zip.sig release-v2.0.0.zip
```

---

## 3. Bill of Materials (SBOM)

Audit PHP dependencies, runtime extensions, and vendor modules via:
```bash
php scripts/generate_sbom.php
```
The output file `sbom.json` complies with **CycloneDX v1.4** specifications for automated supply-chain vulnerability matching.
