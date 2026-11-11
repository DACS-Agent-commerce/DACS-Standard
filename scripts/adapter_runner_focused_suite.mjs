/** Verify the complete top-level summary emitted by Node's TAP reporter. */
export function parseFocusedSuite(output) {
  const expected = { tests: 16, pass: 16, fail: 0, skipped: 0, cancelled: 0, todo: 0 };
  const lines = output.split(/\r?\n/);
  const counts = {};
  for (const [key, value] of Object.entries(expected)) {
    // Count even malformed declarations, so a valid line cannot hide a bad twin.
    // Indented subtest diagnostics are not the top-level summary.
    const declarations = lines.filter(line => new RegExp(`^#[ \\t]*${key}\\b`).test(line));
    if (declarations.length !== 1 || !new RegExp(`^# ${key} (0|[1-9][0-9]*)$`).test(declarations[0])) {
      throw new Error(`contributor focused suite has missing, duplicate or malformed ${key} count`);
    }
    counts[key] = Number(declarations[0].slice(key.length + 3));
    if (counts[key] !== value) {
      throw new Error(`contributor focused suite expected ${key}=${value}, got ${counts[key]}`);
    }
  }
  return counts;
}
