// Runs every attack-test suite against the real migrations (in PGlite, an
// in-memory Postgres) and prints a summary. Exit code 1 if anything fails.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const migrations = path.join(here, "..", "migrations");
const suites = fs.readdirSync(here).filter((f) => f.endsWith(".test.mjs")).sort();

let totalPass = 0;
let totalFail = 0;
const rows = [];
for (const suite of suites) {
  const run = spawnSync(process.execPath, [path.join(here, suite), migrations], { encoding: "utf8" });
  const out = `${run.stdout}${run.stderr}`;
  const match = out.match(/(\d+) passed, (\d+) failed/);
  const pass = match ? Number(match[1]) : 0;
  const fail = match ? Number(match[2]) : 1;
  totalPass += pass;
  totalFail += fail;
  rows.push({ suite: suite.replace(".test.mjs", ""), pass, fail });
  if (fail > 0 || run.status !== 0) {
    console.log(`\n--- ${suite} ---`);
    console.log(out.split("\n").filter((l) => !l.startsWith("PASS")).join("\n"));
  }
}

console.log("\nGameArena database attack tests");
console.table(rows);
console.log(`${totalPass} attacks blocked / behaviours confirmed, ${totalFail} failed`);
process.exit(totalFail === 0 ? 0 : 1);
