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
  const [whole, fraction = ""] = value.split(".");
  return { whole: whole.replace(/^0+(?=\d)/, ""), fraction };
}


function compareCanonicalDecimal(left, right) {
  const a = decimalParts(left);
  const b = decimalParts(right);
  if (a.whole.length !== b.whole.length) return a.whole.length < b.whole.length ? -1 : 1;
  if (a.whole !== b.whole) return a.whole < b.whole ? -1 : 1;
  const width = Math.max(a.fraction.length, b.fraction.length);
  const af = a.fraction.padEnd(width, "0");
  const bf = b.fraction.padEnd(width, "0");
  return af < bf ? -1 : af > bf ? 1 : 0;
}


function reproduce(vector) {
  const { receipt, context, listing } = vector;
  const records = context.resolvedRecords;
  const commitDeadline = listing.parameters.commitDeadline;
  const revealDeadline = commitDeadline + listing.parameters.revealWindow * 1000;
  const commits = new Map();
  const reveals = new Map();

  for (const entry of receipt.entries) {
    const record = records[entry.recordRef.contentHash];
    const timestamp = entry.anchorReceipt.blockRef.timestamp;
    if (record.recordKind === "commit" && timestamp <= commitDeadline) {
      const values = commits.get(record.bidderClaim) ?? [];
      values.push({ entry, record });
      commits.set(record.bidderClaim, values);
    }
    if (record.recordKind === "reveal" && timestamp <= revealDeadline) {
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
    if (reveal && reveal.record.bid.price.currency === "USD" && compareCanonicalDecimal(reveal.record.bid.price.amount, "0") > 0) {
      eligible.push({ commit: authoritative, reveal });
    }
  }

  eligible.sort((left, right) => {
    const price = compareCanonicalDecimal(left.reveal.record.bid.price.amount, right.reveal.record.bid.price.amount);
    const directed = receipt.selectionRule === "lowest-price" ? price : -price;
    if (directed) return directed;
    const time = left.commit.entry.anchorReceipt.blockRef.timestamp - right.commit.entry.anchorReceipt.blockRef.timestamp;
    return time || left.commit.record.bidHash.localeCompare(right.commit.record.bidHash);
  });
  const winner = eligible[0];
  return {
    name: vector.name,
    recordSetHash: digest(receipt.entries),
    receiptContentHash: digest(unsigned(receipt)),
    winnerBidderClaim: winner.commit.record.bidderClaim,
    winnerBidHash: winner.commit.record.bidHash,
  };
}


const data = JSON.parse(readFileSync(path, "utf8"));
const controls = new Set([
  "complete-lowest-price",
  "complete-highest-price",
  "equal-price-earliest-commit",
  "equal-price-equal-time-bidhash",
  "fractional-price-full-precision",
]);
const output = data.vectors.filter((vector) => controls.has(vector.name)).map(reproduce);
process.stdout.write(`${JSON.stringify(output)}\n`);
