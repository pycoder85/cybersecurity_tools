# Security and Scope

Driftwatch is a defensive, local-first host auditing tool for inspecting systems you own or are explicitly authorized to assess.

## Intended use

Supported use cases:

- local host inspection and learning labs
- defensive triage of suspicious persistence, process, network, and filesystem changes
- baseline drift review on managed or lab machines
- offline or localhost-only analysis workflows

## Out of scope

This repository does not support offensive workflows. In particular, Driftwatch is not intended to provide:

- exploitation or post-exploitation features
- privilege escalation techniques
- credential harvesting or credential replay
- malware deployment or persistence installation
- remote control, lateral movement, or command-and-control features
- automatic destructive remediation by default

## Deployment guidance

Operational expectations for this MVP:

- bind the dashboard to `127.0.0.1` unless you intentionally need LAN exposure
- treat `0.0.0.0` binding as less safe and appropriate only for controlled environments
- keep response actions disabled unless you have reviewed the code path and intentionally opted in
- use OS-native schedulers for durable automation instead of relying on the in-process dashboard scheduler
- review stored SQLite data before sharing it, because findings and evidence may contain host-specific paths, usernames, and process metadata
- treat external enrichment as data egress, because enabling it sends extracted observables such as IPs, domains, URLs, hashes, and software names or versions to third-party services

## Vulnerability reporting

If you find a security issue in Driftwatch itself, do not use the issue tracker for sensitive disclosures.

Preferred reporting approach:

1. Provide a concise reproduction and impact summary.
2. Include the affected version or commit if known.
3. Describe whether the issue requires local access, authenticated access, or unusual environment assumptions.

This repository currently does not publish a dedicated private disclosure address, so handle sensitive details carefully and avoid posting exploit-ready material in public issues.

## Project stance

Driftwatch is intentionally conservative:

- deterministic detections come first
- evidence stays local by default
- LLM features are optional and secondary
- destructive or high-risk actions are not a product goal for the MVP
