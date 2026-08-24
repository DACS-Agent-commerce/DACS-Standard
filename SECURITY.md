# Security Policy

DACS is a draft standard under active development, validated against the
[Demos Network](https://demos.sh). We take security reports seriously and
welcome coordinated disclosure from implementers and reviewers.

## Reporting a vulnerability — do NOT open a public issue

If you believe you have found a security vulnerability in the DACS specification,
a reference implementation, or the substrate primitives DACS depends on, **please
report it privately**. Publicly filing an exploitable issue exposes an attack
surface before it can be fixed.

### Preferred channel — GitHub Private Vulnerability Reporting

The *Security* tab → *Report a vulnerability*. This keeps the report private until a
fix ships, and is the channel this policy is written around.

> **Status on this repository: NOT YET ENABLED.** Enabling it needs elevated repository
> security authority — repository admin, an organization owner, or a security manager —
> under *Settings → Code security → Private vulnerability reporting*. Until then the
> *Security* tab shows no reporting form here. `DACS-Agent-commerce/dacs-sdk` has it
> enabled and is the working reference.

### If Private Vulnerability Reporting is unavailable

*Proposed interim guidance — maintainers should amend or replace this. It is added
because the policy currently has no answer for this case, not because the answer below
is settled.*

Until the preferred channel is enabled and while no monitored security address is
listed below, **do not post the finding publicly, and do not send it to a third-party
reviewer.** Instead, open a public issue that contains only:

- that you have a security finding against this repository,
- its rough area (spec §, or "reference evaluator"), and
- a request for a private channel.

No reproduction, no vectors, no impact detail. That avoids publishing reproductions or
exploit-enabling details while still putting the steward on the clock in public, which a
silent private queue does not. Naming the rough area is itself a small signal; the
judgement here is that it is a smaller one than either a full public write-up or an
indefinitely stalled report.

### Dedicated security contact

*None currently published for this repository.* When the steward lists a monitored
address here, it becomes a valid alternative to the *Security* tab.

A high-signal report names: the **affected component** (spec §, file path, or
contract), the **impact** (what an attacker gains), a **minimal reproduction / PoC**
where possible, and a **suggested fix direction**.

## Scope

In scope: spec rules with security impact (signature/replay/atomicity/authorization
defects), the reference implementations, and the substrate primitives (SR-1…SR-5) as
they back conformant DACS flows — including bridge/settlement custody, L2PS channel
confidentiality/soundness, consensus/validator enforcement, and key handling.

## Coordinated disclosure

We ask reporters to give the steward reasonable time to ship a fix before any public
write-up, and we will credit reporters who wish to be named. For pre-mainnet issues,
the goal is to fix quietly and disclose together once patched.

## Signed advisories (optional)

Reporters MAY attach a **signed advisory** — an attestation binding the report to a
keypair (e.g. the DACS-5 envelope-receipt format) so the steward can verify the
report's integrity and provenance. This is optional but encouraged for high-severity
findings; it dogfoods the same verification discipline DACS specifies.
