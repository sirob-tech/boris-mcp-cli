# macOS code signing and notarization

Customer-facing macOS binaries are signed and notarized in CI via GoReleaser. Linux builds use sha256 checksums only.

## Prerequisites

1. Enroll in the [Apple Developer Program](https://developer.apple.com/programs/) (~$99/year).
2. Create a **Developer ID Application** certificate in Xcode or the Apple Developer portal.
3. Export the certificate as a `.p12` file (with a strong password).
4. In App Store Connect, create a **notarytool** API key and download the `.p8` file.

## GitHub Actions secrets

Add these repository secrets before the first signed release:

| Secret | Value |
|--------|-------|
| `MACOS_SIGN_P12` | Base64-encoded `.p12` (`base64 -i cert.p12 \| pbcopy`) |
| `MACOS_SIGN_PASSWORD` | Password used when exporting the `.p12` |
| `MACOS_NOTARY_ISSUER_ID` | Issuer ID from App Store Connect → Keys |
| `MACOS_NOTARY_KEY_ID` | Key ID for the notarytool API key |
| `MACOS_NOTARY_KEY` | Contents of the `.p8` file |

Notarization runs on the `macos-latest` runner in `.github/workflows/release.yml`.

## Local development

When signing secrets are not set, GoReleaser skips notarization automatically:

```bash
goreleaser release --snapshot --clean
```

Unsigned snapshot builds are fine for local smoke tests. Production releases require the secrets above.

## Account ownership

Whether the certificate is issued to a personal or organization Apple Developer account affects the identity shown in Gatekeeper prompts. Decide before enrolling; migrating later requires re-signing and updating secrets.
