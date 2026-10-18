// Entry point so that `node --test test/manager/` works on Node 22, where directory arguments
// are no longer expanded to the test files inside them (package.json "main" points here).
import "./crypto.test.mjs";
import "./e2e.test.mjs";
import "./selfupgrade.test.mjs";
