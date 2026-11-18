# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting: on the repository's **Security** tab,
choose **Report a vulnerability**. This opens a private advisory visible only to the
maintainers.

Include, as far as you can:

- the version or commit affected,
- how to reproduce the issue,
- the impact you think it has.

You can expect an acknowledgement within a few days. Please give a reasonable amount
of time for a fix before any public disclosure.

## Supported versions

This project is pre-1.0. Only the latest released version receives security fixes.

## Scope

nis2check is self-hosted. It is meant to run on a server you control, behind HTTPS,
with access limited to your own users. The threat model assumes authenticated,
semi-trusted internal users rather than the public internet. Findings that require
an already-compromised host or administrator account are out of scope.

nis2check produces an indicative self-assessment, not legal advice or certification;
scoping or scoring inaccuracies are product issues, not security vulnerabilities.
