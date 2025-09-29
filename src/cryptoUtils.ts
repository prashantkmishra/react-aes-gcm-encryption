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

async function deriveKey(password: string, salt: ArrayBuffer) {
  // password: string, salt: ArrayBuffer
  const pwKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: ITERATIONS,
      hash: 'SHA-512',
    },
    pwKey,
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts plaintext using password-derived AES-GCM.
 * Returns base64 string containing: salt || iv || ciphertext
 *
 * @param {string} plaintext
 * @param {string} password
 * @returns {Promise<string>} base64(salt|iv|ciphertext)
 */
export async function encrypt(plaintext: string, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const key = await deriveKey(password, salt.buffer);

  const encodedPlain = textEncoder.encode(plaintext);
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: GCM_TAG_LENGTH,
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
 * @returns {Promise<string>} plaintext
 */
export async function decrypt(combinedB64: String, password: string) {
  const combinedBuff = fromBase64(combinedB64);
  const combined = new Uint8Array(combinedBuff);

  // Extract salt, iv, ciphertext
  const salt = combined.slice(0, SALT_LENGTH).buffer;
  const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH).buffer;
  const cipher = combined.slice(SALT_LENGTH + IV_LENGTH).buffer;

  const key = await deriveKey(password, salt);

  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: GCM_TAG_LENGTH,
    },
    key,
    cipher
  );

  return textDecoder.decode(plainBuffer);
}
