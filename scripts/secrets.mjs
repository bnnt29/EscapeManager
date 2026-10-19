// Reads the [secrets] section of the untracked secrets.ini (see secrets.ini.example) so the scripts use the
// same tokens and Wi-Fi settings as the builds. Missing file or key = "" (callers fall back to the public
// default token). ESCAPE_SECRETS_FILE names another file.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function readSecrets(file = process.env.ESCAPE_SECRETS_FILE || path.join(root, "secrets.ini")) {
  const out = {};
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { return out; }
  let section = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    const header = /^\[(.+)\]$/.exec(line);
    if (header) { section = header[1].trim(); continue; }
    if (section !== "secrets") continue;
    const eq = line.indexOf("=");
    if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

export const secrets = readSecrets();
