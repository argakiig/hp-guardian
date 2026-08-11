# Security Policy

## Supported scope

Security fixes are considered for the source in the current default branch and
the v0.1 source release. Hardpoint Guardian does not currently publish Python
or Rust packages, operate a hosted service, or make support-time commitments.

## Report a vulnerability privately

Do not report suspected vulnerabilities in public issues, discussions, or pull
requests. Use GitHub's private vulnerability-reporting flow for this repository
(`Security` -> `Report a vulnerability`). If that control is unavailable,
contact a repository maintainer through an established private channel before
disclosing technical details.

Include:

- the affected commit or release;
- a minimal reproduction and impact assessment;
- affected runtime(s) and operating system, when relevant; and
- any suggested mitigation or patch.

Please avoid including production credentials, raw tool arguments, private
policy content, or other sensitive data in a report.

## Security boundaries

Hardpoint Guardian is not a sandbox or proxy. The host application remains
responsible for tool execution, process isolation, filesystem access controls,
secret handling, and enforcing the returned decision at every execution path.
The inline adapter audits before returning an `allow` effect and fails closed
when its required audit write fails, but it does not execute or contain the
effect. See the [README](README.md) for the supported scope and limitations.
