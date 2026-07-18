# Executable minimum-conformant lifecycle walkthrough

This non-normative, dependency-free walkthrough turns the current conformance
fixtures into one executable `Identify → Vet → Negotiate → Settle → Verify`
flow. It is reference tooling for builders; the normative source remains
[`spec/`](../../spec/).

Run it from a clean checkout with Python 3:

```sh
python3 scripts/run_lifecycle_walkthrough.py --check
```

Use `--json` to inspect the complete trace. Every stage includes:

- the artifact and its canonical UTF-8 bytes;
- the full vector content hash and the normative signature-scope hash;
- the domain separator, exact signature payload, and Ed25519 verification result;
- a fake-SR-2 `AttestationRef`; and
- the applicable rule IDs and conformance vector IDs.

The walkthrough also executes five deterministic negative examples: malformed
identity, an agreement selecting a rail outside listing policy, a duplicate
settlement transaction ID, delivery failure after payment, and divergent
buyer/seller bundles. The substrate adapter is deliberately fake and local.
Live Demos operational bindings remain tracked in [#212](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/212)
and [#242](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/242), so
this tool does not embed version-sensitive SDK imports or method names.

`PINS.json` binds CI to the current profile, conformance manifest, source vector,
and complete emitted trace. After an intentional profile or fixture update,
inspect the new trace and obtain proposed pins with:

```sh
python3 scripts/run_lifecycle_walkthrough.py --print-pins
```

Update the pins only when the corresponding drift is expected and reviewed.
