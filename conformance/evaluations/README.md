# DACS evaluation proposals

Everything in this directory is proposed and non-normative. These packages
support bounded evaluation design, reproducibility, and review. They do not add
requirements to the DACS Standard, change the conformance manifest, establish
release gates, or turn proposal cases into golden vectors.

Each package must identify its exact repository revision, environment,
expected results, forbidden effects, evidence, and limitations. Offline,
Harbor/model, SDK interoperability, and live-system evidence remain separate
assurance classes.

- [`pr362-verifyresult-pilot/`](./pr362-verifyresult-pilot/) packages the bounded
  VerifyResult identity/authentication pilot proposed in #401.
