import { expect, test } from "bun:test";
import {
  DACS_SDK_TARGET,
  artifacts,
  conformance,
  demosRails,
  validators,
} from "../src";

test("targets DACS v0.1", () => {
  expect(DACS_SDK_TARGET).toEqual({
    standard: "DACS",
    version: "v0.1",
  });
});

test("exposes planned module buckets", () => {
  expect(artifacts.ARTIFACT_MODULE).toBe("artifacts");
  expect(validators.VALIDATORS_MODULE).toBe("validators");
  expect(demosRails.DEMOS_RAILS_MODULE).toBe("rails/demos");
  expect(conformance.CONFORMANCE_MODULE).toBe("conformance");
});
