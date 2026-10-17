// Entry point of the inline crypto bundle of src/manager/manager.html.
// Built by scripts/build_manager_crypto.mjs (esbuild, IIFE, minified) and pasted between
// the /*EM-CRYPTO-BEGIN*/ ... /*EM-CRYPTO-END*/ markers of the manager.
//
// Why this exists: browsers only expose WebCrypto (crypto.subtle) on secure origins, but the
// manager is served over plain http:// from the devices. Only crypto.getRandomValues is used
// from the platform. Everything else is @noble (audited, pure JS).
//
// Wire format: see PROTOCOL.md sections 3 and 4.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";

const KDF_SALT = "EscapeManager/2/token";
const MAX_ITERATIONS = 100000; // PROTOCOL.md section 3: refuse anything above
const B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_INDEX = (() => {
  const index = new Int16Array(128).fill(-1);
  for (let i = 0; i < 64; i++) index[B64U_ALPHABET.charCodeAt(i)] = i;
  return index;
})();

// ---- UTF-8 (no TextEncoder/TextDecoder dependency, lone surrogates become U+FFFD like the platform does) ----

function utf8Encode(text) {
  const s = String(text);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

function utf8Decode(input) {
  const bytes = toBytes(input);
  let out = "";
  let chunk = [];
  const flush = () => { out += String.fromCharCode.apply(null, chunk); chunk = []; };
  const push = (unit) => { chunk.push(unit); if (chunk.length >= 4096) flush(); };
  for (let i = 0; i < bytes.length;) {
    const b = bytes[i];
    let need = 0, cp = 0, min = 0;
    if (b < 0x80) { push(b); i++; continue; }
    else if (b >= 0xc2 && b <= 0xdf) { need = 1; cp = b & 0x1f; min = 0x80; }
    else if (b >= 0xe0 && b <= 0xef) { need = 2; cp = b & 0x0f; min = 0x800; }
    else if (b >= 0xf0 && b <= 0xf4) { need = 3; cp = b & 0x07; min = 0x10000; }
    else { push(0xfffd); i++; continue; }
    let j = 1;
    for (; j <= need; j++) {
      const n = bytes[i + j];
      if (n === undefined || (n & 0xc0) !== 0x80) break;
      cp = (cp << 6) | (n & 63);
    }
    if (j <= need || cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      push(0xfffd);
      i += Math.max(1, j); // resynchronise after the valid prefix
      continue;
    }
    if (cp >= 0x10000) { cp -= 0x10000; push(0xd800 + (cp >> 10)); push(0xdc00 + (cp & 0x3ff)); }
    else push(cp);
    i += need + 1;
  }
  flush();
  return out;
}

// Accepts strings (UTF-8 encoded) and any typed array/ArrayBuffer view, also from another realm.
function toBytes(value) {
  if (typeof value === "string") return utf8Encode(value);
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Object.prototype.toString.call(value) === "[object ArrayBuffer]") return new Uint8Array(value);
  throw new TypeError("bytes or string expected");
}

// ---- base64url, strict canonical (PROTOCOL.md: unused trailing bits must be zero) ----

function b64uEncode(input) {
  const bytes = toBytes(input);
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64U_ALPHABET[n >> 18] + B64U_ALPHABET[(n >> 12) & 63] + B64U_ALPHABET[(n >> 6) & 63] + B64U_ALPHABET[n & 63];
  }
  if (bytes.length - i === 1) {
    const n = bytes[i] << 16;
    out += B64U_ALPHABET[n >> 18] + B64U_ALPHABET[(n >> 12) & 63];
  } else if (bytes.length - i === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64U_ALPHABET[n >> 18] + B64U_ALPHABET[(n >> 12) & 63] + B64U_ALPHABET[(n >> 6) & 63];
  }
  return out;
}

// Returns null for anything that is not canonical unpadded base64url.
function b64uDecode(text) {
  if (typeof text !== "string") return null;
  const len = text.length;
  if (len % 4 === 1) return null;
  const values = new Array(len);
  for (let i = 0; i < len; i++) {
    const c = text.charCodeAt(i);
    const v = c < 128 ? B64U_INDEX[c] : -1;
    if (v < 0) return null;
    values[i] = v;
  }
  const out = new Uint8Array(Math.floor((len * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 3 < len; i += 4) {
    const n = (values[i] << 18) | (values[i + 1] << 12) | (values[i + 2] << 6) | values[i + 3];
    out[o++] = n >> 16; out[o++] = (n >> 8) & 255; out[o++] = n & 255;
  }
  const rest = len - i;
  if (rest === 2) {
    if (values[i + 1] & 15) return null; // non-zero unused bits
    out[o++] = (values[i] << 2) | (values[i + 1] >> 4);
  } else if (rest === 3) {
    if (values[i + 2] & 3) return null;
    out[o++] = (values[i] << 2) | (values[i + 1] >> 4);
    out[o++] = ((values[i + 1] & 15) << 4) | (values[i + 2] >> 2);
  }
  return out;
}

// ---- primitives ----

function sha256(data) { return nobleSha256(toBytes(data)); }
function hmacSha256(key, message) { return hmac(nobleSha256, toBytes(key), toBytes(message)); }

function constantTimeEqual(a, b) {
  const x = toBytes(a), y = toBytes(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// AES-256-GCM, 12 byte IV, 16 byte tag appended to the ciphertext.
function gcmSeal(key, iv, aad, plain) {
  return gcm(toBytes(key), toBytes(iv), toBytes(aad)).encrypt(toBytes(plain));
}

// Returns the plaintext bytes, or null when the tag does not verify / the input is malformed.
function gcmOpen(key, iv, aad, cipherAndTag) {
  try {
    const sealed = toBytes(cipherAndTag);
    if (sealed.length < 16) return null;
    return gcm(toBytes(key), toBytes(iv), toBytes(aad)).decrypt(sealed);
  } catch {
    return null;
  }
}

function randomBytes(count) {
  const out = new Uint8Array(count);
  crypto.getRandomValues(out); // the only platform primitive used
  return out;
}

// ---- key schedule (PROTOCOL.md section 3), PBKDF2 runs once per (token, iterations) ----

const keyCache = new Map();

function deriveKeys(token, iterations) {
  const iter = iterations === undefined ? 2048 : iterations;
  if (!Number.isInteger(iter) || iter < 1 || iter > MAX_ITERATIONS) throw new RangeError("kdf iterations out of range");
  const cacheKey = iter + ":" + token;
  const hit = keyCache.get(cacheKey);
  if (hit) return hit;
  const master = pbkdf2(nobleSha256, utf8Encode(token), utf8Encode(KDF_SALT), { c: iter, dkLen: 32 });
  const expand = (info) => hkdf(nobleSha256, master, new Uint8Array(0), utf8Encode(info), 32);
  const keys = Object.freeze({ req: expand("EM2 req"), resp: expand("EM2 resp"), mac: expand("EM2 mac") });
  if (keyCache.size >= 16) keyCache.delete(keyCache.keys().next().value);
  keyCache.set(cacheKey, keys);
  return keys;
}

// Exposed only for the RFC 5869 check in the test suite.
function hkdfSha256(ikm, salt, info, length) {
  return hkdf(nobleSha256, toBytes(ikm), toBytes(salt), toBytes(info), length);
}

globalThis.EscapeCrypto = Object.freeze({
  deriveKeys, hmacSha256, sha256, gcmSeal, gcmOpen, b64uEncode, b64uDecode,
  utf8Encode, utf8Decode, constantTimeEqual, randomBytes, hkdfSha256,
});
