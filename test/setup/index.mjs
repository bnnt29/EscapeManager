// Entry point so that `node --test test/setup/` works on Node 22, where directory arguments
// are no longer expanded to the test files inside them (package.json "main" points here).
import "./setup.test.mjs";
