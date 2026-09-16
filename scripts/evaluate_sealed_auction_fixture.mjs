#!/usr/bin/env node
// Independent JavaScript reproduction for the byte-stable SAC fixture controls.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";


const path = process.argv[2];
if (!path) {
  throw new Error("usage: node evaluate_sealed_auction_fixture.mjs <vector-file>");
}


function canonical(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}


function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}


function digest(value) {
  return sha256(Buffer.from(canonical(value), "utf8"));
}


function unsigned(value) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "signature" && key !== "signatures"));
}


function equal(left, right) {
  return canonical(left) === canonical(right);
}


function bidHash(bid, saltText) {
  const salt = Buffer.from(saltText, "base64url");
  const bidDigest = createHash("sha256").update(Buffer.from(canonical(bid), "utf8")).digest();
  return createHash("sha256")
    .update(Buffer.from("dacs-sealed-bid:v1:", "ascii"))
    .update(bidDigest)
    .update(salt)
    .digest("hex");
}


function decimalParts(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?(?![\s\S])/.test(value)) {
    return null;
  }
  const [whole, fraction = ""] = value.split(".");
  return { whole, fraction };
}


function inspectAmount(value) {
  const parts = decimalParts(value);
  if (parts) return { status: value === "0" ? "non-positive" : "positive", parts };
  if (typeof value === "string" && value.startsWith("-")) {
    const magnitude = decimalParts(value.slice(1));
    if (magnitude) return { status: "non-positive", parts: magnitude };
  }
  return { status: "malformed", parts: null };
}


function inspectPrice(price) {
  if (price === null || typeof price !== "object" || Array.isArray(price)) {
    return { status: "malformed", parts: null };
  }
  const keys = Object.keys(price);
  if (!keys.includes("amount") || !keys.includes("currency")
      || keys.some((key) => !["amount", "currency", "unit"].includes(key))
      || typeof price.currency !== "string"
      || (Object.hasOwn(price, "unit") && typeof price.unit !== "string")) {
    return { status: "malformed", parts: null };
  }
  return inspectAmount(price.amount);
}


function recordShapeValid(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return false;
  const commonKeys = [
    "sealedAuctionRecordVersion", "recordKind", "jobId", "listingRef",
    "phaseIndex", "bidderClaim", "bidHash", "createdAt", "signature",
  ];
  const expectedKeys = record.recordKind === "commit"
    ? commonKeys
    : record.recordKind === "reveal"
      ? [...commonKeys, "commitRef", "bid", "salt"]
      : [];
  const signature = record.signature;
  return equal(Object.keys(record).sort(), expectedKeys.sort())
    && record.sealedAuctionRecordVersion === "1"
    && signature !== null && typeof signature === "object" && !Array.isArray(signature)
    && equal(Object.keys(signature).sort(), ["algorithm", "signer", "value"])
    && signature.algorithm === "ed25519"
    && typeof signature.signer === "string"
    && typeof signature.value === "string";
}


function compareDecimalParts(a, b) {
  if (a.whole.length !== b.whole.length) return a.whole.length < b.whole.length ? -1 : 1;
  if (a.whole !== b.whole) return a.whole < b.whole ? -1 : 1;
  for (let index = 0; index < Math.max(a.fraction.length, b.fraction.length); index += 1) {
    const left = a.fraction[index] ?? "0";
    const right = b.fraction[index] ?? "0";
    if (left !== right) return left < right ? -1 : 1;
  }
  return 0;
}


function reproduce(vector) {
  const { receipt, agreement, context, listing } = vector;
  const records = context.resolvedRecords;
  const result = {
    name: vector.name,
    recordSetHash: digest(receipt.entries),
    receiptContentHash: digest(unsigned(receipt)),
  };
  const invocation = context.authenticatedInvocation;
  const binding = listing.parameters?.candidateSetBinding;
  const resolution = context.bindingResolution;
  const phaseKind = listing.phaseKind;
  const modePresent = Object.hasOwn(listing.parameters ?? {}, "auctionMode");
  const mode = listing.parameters?.auctionMode;
  if (invocation === null || invocation === undefined || resolution === null || resolution === undefined) {
    return { ...result, verdict: "indeterminate" };
  }
  if (invocation.authenticated !== true
      || !equal(listing.listingRef, invocation.listingRef)
      || listing.phaseIndex !== invocation.phaseIndex
      || phaseKind !== invocation.phaseKind
      || listing.publisherClaim !== invocation.publisherClaim
      || listing.parameters.selectionRule !== invocation.selectionRule
      || !equal(binding, invocation.candidateSetBinding)
      || listing.pricingCurrency !== invocation.pricingCurrency
      || receipt.jobId !== invocation.jobId
      || !equal(receipt.listingRef, invocation.listingRef)
      || receipt.phaseIndex !== invocation.phaseIndex
      || receipt.phaseKind !== invocation.phaseKind
      || !equal(receipt.candidateSetBinding, binding)
      || receipt.collectionPrefix !== `dacs3:auction:${encodeURIComponent(invocation.jobId)}`) {
    return { ...result, verdict: "fail" };
  }
  if ((phaseKind === "negotiate-sealed-envelope-complete" && modePresent && mode !== "demand")
      || (phaseKind === "negotiate-sealed-envelope-procurement-complete"
          && (!modePresent || mode !== "procurement"))) {
    return { ...result, verdict: "fail" };
  }
  if (resolution.authenticated !== true
      || resolution.registryId !== context.bindingRegistryAuthority?.registryId
      || resolution.governanceClaim !== context.bindingRegistryAuthority?.governanceClaim
      || resolution.bindingId !== binding.bindingId
      || resolution.bindingVersion !== binding.bindingVersion
      || typeof binding.bindingVersion !== "string"
      || !/^[1-9][0-9]*$/.test(binding.bindingVersion)
      || !equal(resolution.definitionRef, binding.definitionRef)
      || binding.definitionRef.signer !== context.bindingRegistryAuthority?.governanceClaim
      || digest(resolution.definition) !== binding.definitionRef.contentHash
      || resolution.definition.bindingId !== binding.bindingId
      || resolution.definition.bindingVersion !== binding.bindingVersion) {
    return { ...result, verdict: "fail" };
  }
  if (receipt.entries.length > Number(resolution.definition.limits.maximumRecords)
      || Buffer.byteLength(canonical(receipt.entries), "utf8")
      > Number(resolution.definition.limits.maximumBytes)) {
    return { ...result, verdict: "fail" };
  }
  const revealDeadline = listing.parameters.commitDeadline + listing.parameters.revealWindow * 1000;
  if (receipt.completenessEvidence.finalizedState.timestamp < revealDeadline) {
    return { ...result, verdict: "fail" };
  }
  let reserve = null;
  if (listing.pricing !== undefined) {
    const pricing = listing.pricing;
    if (pricing === null || typeof pricing !== "object" || Array.isArray(pricing)
        || pricing.kind !== "auction" || pricing.selectionRule !== receipt.selectionRule) {
      return { ...result, verdict: "fail" };
    }
    if (Object.hasOwn(pricing, "reservePrice")) {
      const inspected = inspectPrice(pricing.reservePrice);
      if (inspected.status !== "positive" || pricing.reservePrice.currency !== listing.pricingCurrency) {
        return { ...result, verdict: "fail" };
      }
      reserve = inspected.parts;
    }
  }
  const commitDeadline = listing.parameters.commitDeadline;
  const recordRevealDeadline = commitDeadline + listing.parameters.revealWindow * 1000;
  const commits = new Map();
  const reveals = new Map();
  let malformedPriceCount = 0;

  for (const entry of receipt.entries) {
    const record = records[entry.recordRef.contentHash];
    if (!recordShapeValid(record)) {
      return { ...result, verdict: "fail" };
    }
    const timestamp = entry.anchorReceipt.blockRef.timestamp;
    if (record.recordKind === "commit" && timestamp <= commitDeadline) {
      const values = commits.get(record.bidderClaim) ?? [];
      values.push({ entry, record });
      commits.set(record.bidderClaim, values);
    }
    if (record.recordKind === "reveal" && timestamp <= recordRevealDeadline) {
      const values = reveals.get(record.bidderClaim) ?? [];
      values.push({ entry, record });
      reveals.set(record.bidderClaim, values);
    }
  }

  const eligible = [];
  for (const [bidder, values] of commits.entries()) {
    values.sort((left, right) => {
      const time = left.entry.anchorReceipt.blockRef.timestamp - right.entry.anchorReceipt.blockRef.timestamp;
      return time || left.record.bidHash.localeCompare(right.record.bidHash);
    });
    const authoritative = values[0];
    const reveal = (reveals.get(bidder) ?? []).find((candidate) =>
      equal(candidate.record.commitRef, authoritative.entry.recordRef)
      && candidate.record.bidHash === authoritative.record.bidHash
      && bidHash(candidate.record.bid, candidate.record.salt) === authoritative.record.bidHash
    );
    if (reveal) {
      const price = reveal.record.bid?.price;
      const inspected = inspectPrice(price);
      if (inspected.status === "malformed") {
        malformedPriceCount += 1;
        continue;
      }
      if (price.currency === listing.pricingCurrency && inspected.status === "positive") {
        const reserveOrder = reserve === null ? 0 : compareDecimalParts(inspected.parts, reserve);
        const outsideReserve = reserve !== null && (
          (receipt.selectionRule === "lowest-price" && reserveOrder > 0)
          || (receipt.selectionRule === "highest-price" && reserveOrder < 0)
        );
        if (!outsideReserve) eligible.push({ commit: authoritative, reveal, amount: inspected.parts });
      }
    }
  }

  if (malformedPriceCount) return { ...result, verdict: "fail", malformedPriceCount };
  eligible.sort((left, right) => {
    const price = compareDecimalParts(left.amount, right.amount);
    const directed = receipt.selectionRule === "lowest-price" ? price : -price;
    if (directed) return directed;
    const time = left.commit.entry.anchorReceipt.blockRef.timestamp - right.commit.entry.anchorReceipt.blockRef.timestamp;
    return time || left.commit.record.bidHash.localeCompare(right.commit.record.bidHash);
  });
  const winner = eligible[0];
  if (!winner) return { ...result, verdict: "fail" };
  const buyers = agreement.parties.filter((party) => party.role === "buyer");
  const sellers = agreement.parties.filter((party) => party.role === "seller");
  const expectedBuyer = phaseKind === "negotiate-sealed-envelope-complete"
    ? winner.commit.record.bidderClaim : listing.publisherClaim;
  const expectedSeller = phaseKind === "negotiate-sealed-envelope-complete"
    ? listing.publisherClaim : winner.commit.record.bidderClaim;
  if (buyers.length !== 1 || sellers.length !== 1
      || buyers[0].primaryClaim !== expectedBuyer
      || sellers[0].primaryClaim !== expectedSeller) {
    return { ...result, verdict: "fail" };
  }
  return {
    ...result,
    verdict: "pass",
    winnerBidderClaim: winner.commit.record.bidderClaim,
    winnerBidHash: winner.commit.record.bidHash,
  };
}


const data = JSON.parse(readFileSync(path, "utf8"));
const controls = new Set([
  "complete-lowest-price",
  "complete-demand-absent-auction-mode",
  "complete-demand-explicit-auction-mode",
  "demand-phase-procurement-mode-rejected",
  "procurement-phase-demand-mode-rejected",
  "demand-role-direction-rejected",
  "auction-pricing-without-reserve",
  "complete-highest-price",
  "finalized-state-at-reveal-deadline",
  "finalized-state-before-reveal-deadline-rejected",
  "binding-definition-unavailable",
  "definition-content-hash-substitution-rejected",
  "definition-ref-substitution-rejected",
  "self-selected-definition-key-rejected",
  "binding-id-substitution-rejected",
  "binding-version-substitution-rejected",
  "noncanonical-binding-version-rejected",
  "binding-record-ceiling-exceeded",
  "equal-price-earliest-commit",
  "equal-price-equal-time-bidhash",
  "fractional-price-full-precision",
  "nonfinite-price-amounts-rejected",
  "trailing-linebreak-price-amounts-rejected",
  "snan-and-exponent-price-amounts-rejected",
  "non-string-price-amounts-rejected",
  "malformed-price-shapes-rejected",
  "noncanonical-price-amounts-rejected",
  "noncanonical-decimal-shapes-rejected",
  "non-usd-listing-matching-bids",
  "non-usd-listing-usd-bids-excluded",
  "non-usd-listing-third-currency-reserve-rejected",
  "zero-and-negative-prices-excluded",
  "long-integer-lowest-price",
  "long-integer-highest-price",
  "long-fraction-lowest-price",
  "long-fraction-highest-price",
  "long-fraction-inclusive-reserve-ceiling",
  "long-fraction-inclusive-reserve-floor",
  "resigned-cross-job-artifacts-rejected",
  "resigned-cross-listing-artifacts-rejected",
  "resigned-cross-phase-artifacts-rejected",
  "signed-commit-extra-member-rejected",
  "signed-commit-missing-member-rejected",
  "signed-reveal-extra-member-rejected",
  "signed-reveal-missing-member-rejected",
  "signed-commit-wrong-version-rejected",
  "signed-reveal-wrong-version-rejected",
  "signed-commit-signature-extra-member-rejected",
  "signed-reveal-signature-extra-member-rejected",
]);
const output = data.vectors.filter((vector) => controls.has(vector.name)).map(reproduce);
process.stdout.write(`${JSON.stringify(output)}\n`);
