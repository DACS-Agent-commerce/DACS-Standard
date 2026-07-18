# Executable minimum-conformant lifecycle walkthrough

This non-normative, dependency-free walkthrough builds one deterministic,
current-profile `Identify → Vet → Negotiate → Settle → Verify` flow from public
test keys. It is reference tooling for builders; the normative source remains
[`spec/`](../../spec/).

Run it from a clean checkout with Python 3:

```sh
python3 scripts/run_lifecycle_walkthrough.py --check
```

Use `--json` to inspect the complete trace. The five stages contain eleven signed
artifacts: one listing, two claim-level verification results, two counterparty
composite vet records, one payee-bound agreement, payment and delivery evidence,
and buyer/seller/orchestrator bundle copies.
Every artifact includes:

- the artifact and its canonical UTF-8 bytes;
- the full vector content hash and the normative signature-scope hash;
- the domain separator, exact signature payload, and Ed25519 verification result;
- a fake-SR-2 `AttestationRef`, with the logical identifier kept separate from
  the fake substrate's opaque native address and an explicit published binding;
- the applicable rule IDs and conformance vector IDs.

The chain uses recursive NFC normalisation (CF-1), strict unpadded Base64URL
signature values (SIG-6), a pipeline with both payment and delivery (PIPE-1 and
PIPE-3), final payment/delivery references propagated into DACS-5, and all
required signatures on each role-specific bundle copy. No legacy pre-SIG-6
lifecycle fixture is used as current conformance input.

The walkthrough also executes five deterministic negative examples: malformed
identity, an agreement selecting a rail outside listing policy, a duplicate
settlement transaction ID, delivery failure after payment, and divergent
buyer/seller bundles. The substrate adapter is deliberately fake and local.
Live Demos operational bindings remain tracked in [#212](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/212)
and [#242](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/242), so
this tool does not embed version-sensitive SDK imports or method names.

`PINS.json` binds CI to the current profile, conformance manifest, the SB-2
negative vector, and complete emitted trace. After an intentional profile or
fixture update, inspect the new trace and obtain proposed pins with:

```sh
python3 scripts/run_lifecycle_walkthrough.py --print-pins
```

Update the pins only when the corresponding drift is expected and reviewed.
