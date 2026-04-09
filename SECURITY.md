# Security Policy

## Supported Scope

This repository focuses on the public `ccp-core` kernel:

- governed execution
- approvals
- traceability
- secret-safe connection handling
- MCP trust and runtime posture

## Reporting A Vulnerability

Please do not open a public issue for sensitive security reports.

Instead, report privately through one of these paths:

- GitHub private vulnerability reporting for this repository, if it is enabled
- email: `vishnunarayanvenugopal@gmail.com`

Please include:

- a clear description of the issue
- affected commands or resource kinds
- impact and likely attack path
- reproduction steps if available

If you are testing a bug, avoid including real secrets, real tokens, or private tenant details in the report.

## Security Principles

The project tries to follow a few boring but useful rules:

- secrets should not be revealed to AI by default
- policy should be enforced on the execution path, not just described
- approval receipts should only be trusted when backed by an explicitly configured signer
- trace output should be sanitized
- integrations should be treated as untrusted until proven otherwise

Boring security usually ages better than exciting security.
