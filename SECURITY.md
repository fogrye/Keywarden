# Security policy

Keywarden handles vault keys and passwords, so please report vulnerabilities privately rather than in a public issue.

## Reporting

Use [Report a vulnerability](https://github.com/fogrye/keywarden/security/advisories/new) (GitHub's private vulnerability reporting). Include the Keywarden version and build from **Settings › App**, the macOS version, and steps to reproduce. Never include real passwords, keys, tokens or vault contents.

This is a personal project maintained in spare time, so there is no bounty and no guaranteed response time.

## Supported versions

Only the latest release gets fixes.

## Scope

- In scope: the app, its native-messaging helper, the browser checks and Touch ID gating, and how keys, tokens and the vault cache are stored. [Security notes](docs/security.md) describes the design.
- Out of scope: Bitwarden's servers, SDK, browser extension and official apps. Report those to [Bitwarden](https://github.com/bitwarden/clients/security/policy), which does not support Keywarden.
