// aesGcm.js
// React-friendly Web Crypto AES-GCM encryption/decryption with PBKDF2 (SHA-512).
// Assumptions: PBKDF2 with SHA-512, 100000 iterations, AES-256-GCM, 12-byte IV, 16-byte salt.

const ITERATIONS = 1000;
const KEY_LENGTH_BITS = 256; // AES-256
const SALT_LENGTH = 16; // bytes
const IV_LENGTH = 12; // bytes (96 bits) recommended for GCM
const GCM_TAG_LENGTH = 128; // bits

// Helpers
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function toBase64(buffer: any) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

function fromBase64(b64: any) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function concatBuffers(...buffers: any[]) {
  const total = buffers.reduce((sum, b) => sum + b.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of buffers) {
    out.set(new Uint8Array(b), offset);
    offset += b.byteLength;
  }
  return out.buffer;
}

async function deriveKey(password: string, salt: ArrayBuffer, keyLength: number, iterations: number) {
  // password: string, salt: ArrayBuffer
  const pwKey = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: iterations,
      hash: "SHA-512",
    },
    pwKey,
    { name: "AES-GCM", length: keyLength },
    false,
    ["encrypt", "decrypt"]
  );
}

function validateKey(keyLength: number) {
  if (keyLength !== 128 && keyLength !== 256) {
    return "AES key length must be 128 or 256 bits";
  }
  return null;
}

function validateTagLength(tagLength: number) {
  if (tagLength && tagLength < 129) {
    const modulus = tagLength % 32;
    if (modulus !== 0 && tagLength !== 120) {
      return "The tag length is invalid: Must be 32, 64, 96, 104, 112, 120, or 128 bits";
    }
  } else {
    return "The tag length is invalid: Must be 32, 64, 96, 104, 112, 120, or 128 bits";
  }

  return null;
}

//

/**
 * Encrypts plaintext using password-derived AES-GCM.
 * Returns base64 string containing: salt || iv || ciphertext
 *
 * @param {string} plaintext
 * @param {string} password
 * @param {number} keyLength default value 256. AES key length must be 128 or 256 bits
 * @param {number} saltLength default value 16
 * @param {number} ivLength default value 12
 * @param {number} tagLength default value 128. The tag length Must be 32, 64, 96, 104, 112, 120, or 128 bits
 * @param {number} iterations default value 1000
 * @returns {Promise<string>} base64(salt|iv|ciphertext)
 */
export async function encrypt(
  plaintext: string,
  password: string,
  keyLength = KEY_LENGTH_BITS,
  saltLength = SALT_LENGTH,
  ivLength = IV_LENGTH,
  tagLength = GCM_TAG_LENGTH,
  iterations = ITERATIONS
) {
  const isKeyValid = validateKey(keyLength);
  if (isKeyValid) {
    return Promise.reject(new Error(isKeyValid));
  }
  const isTagValid = validateTagLength(tagLength);
  if (isTagValid) {
    return Promise.reject(new Error(isTagValid));
  }
  const salt = crypto.getRandomValues(new Uint8Array(saltLength));
  const iv = crypto.getRandomValues(new Uint8Array(ivLength));

  const key = await deriveKey(password, salt.buffer, keyLength, iterations);

  const encodedPlain = textEncoder.encode(plaintext);
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: tagLength,
    },
    key,
    encodedPlain
  );

  // Output: salt || iv || ciphertext (ArrayBuffer)
  const combined = concatBuffers(salt.buffer, iv.buffer, cipherBuffer);
  return toBase64(combined);
}

/**
 * Decrypts base64(salt|iv|ciphertext) with password.
 *
 * @param {string} combinedB64 - base64 string produced by encryptAesGcm
 * @param {string} password
 * @param {number} keyLength default value 256. AES key length must be 128 or 256 bits
 * @param {number} saltLength default value 16
 * @param {number} ivLength default value 12
 * @param {number} tagLength default value 128. The tag length Must be 32, 64, 96, 104, 112, 120, or 128 bits
 * @param {number} iterations default value 1000
 * @returns {Promise<string>} plaintext
 */
export async function decrypt(
  combinedB64: string,
  password: string,
  keyLength = KEY_LENGTH_BITS,
  saltLength = SALT_LENGTH,
  ivLength = IV_LENGTH,
  tagLength = GCM_TAG_LENGTH,
  iterations = ITERATIONS
) {
  const isKeyValid = validateKey(keyLength);
  if (isKeyValid) {
    return Promise.reject(new Error(isKeyValid));
  }
  const isTagValid = validateTagLength(tagLength);
  if (isTagValid) {
    return Promise.reject(new Error(isTagValid));
  }
  const combinedBuff = fromBase64(combinedB64);
  const combined = new Uint8Array(combinedBuff);

  // Extract salt, iv, ciphertext
  const salt = combined.slice(0, saltLength).buffer;
  const iv = combined.slice(saltLength, saltLength + ivLength).buffer;
  const cipher = combined.slice(saltLength + ivLength).buffer;

  const key = await deriveKey(password, salt, keyLength, iterations);

  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: tagLength,
    },
    key,
    cipher
  );

  return textDecoder.decode(plainBuffer);
}
