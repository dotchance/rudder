<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Security Policy

## Reporting Vulnerabilities

Please report vulnerabilities privately through GitHub Security Advisories:

https://github.com/dotchance/rudder/security/advisories/new

If private advisories are unavailable, open a minimal public issue asking for a private reporting channel. Do not include exploit details, packet captures with sensitive data, private topology information, credentials, or production IP addresses in a public issue.

## Scope

Security reports are in scope when they affect rudder's repository, CLI, rule parsing, eBPF programs, container manifests, GitHub Actions workflows, or documented deployment model.

Rudder is a privileged networking tool. Loading policies requires root-equivalent privileges because TC and eBPF attachment need elevated Linux capabilities. Treat rule files, container images, Kubernetes manifests, and host access as privileged operational inputs.

## Supported Versions

Rudder currently tracks the `main` branch. Security fixes are applied there first unless release branches are introduced later.

## Operational Guidance

- Review rule files before loading them on a host.
- Run rudder only on hosts where root or equivalent eBPF/TC capabilities are acceptable.
- Keep dependencies, base images, and GitHub Actions updated through Dependabot.
- Prefer private vulnerability reports over public issues for anything that could affect packet handling, host privilege boundaries, CI secrets, or deployment safety.
