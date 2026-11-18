const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

test("history date filters preserve the configured time zone and reject nonexistent wall times", async () => {
  const context = vm.createContext({});
  const source = fs.readFileSync(path.join(__dirname, "../src/lib/time.js"), "utf8");
  const module = new vm.SourceTextModule(source, { context });
  await module.link(() => new vm.SyntheticModule(["reactive"], function () {
    this.setExport("reactive", (value) => value);
  }, { context }));
  await module.evaluate();
  const { setTimeZone, zonedDateTimeToDate } = module.namespace;

  setTimeZone("Asia/Shanghai");
  assert.equal(zonedDateTimeToDate("2026-11-19T14:31").toISOString(), "2026-11-19T06:31:00.000Z");
  assert.equal(zonedDateTimeToDate("2026-11-32T14:31"), null);

  setTimeZone("America/Los_Angeles");
  assert.equal(zonedDateTimeToDate("2026-03-08T04:30:15").toISOString(), "2026-03-08T11:30:15.000Z");
  assert.equal(zonedDateTimeToDate("2026-03-08T02:30"), null);
});
