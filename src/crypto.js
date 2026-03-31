// ============================================================================
// src/crypto.js - End-to-end encryption for FriendsForum
//
// All encryption/decryption happens in the browser. The server and Storacha
// only ever see ciphertext. Private keys never leave the device.
//
// Post encryption:
//   1. Generate random AES-256-GCM key (content key)
//   2. Encrypt post content with the content key
//   3. For each friend: ECDH(author_private, friend_public) → shared secret
//      → wrap the content key with the shared secret
//   4. Upload: { ciphertext, iv, recipientKeys: [{ fingerprint, wrappedKey, iv }] }
//
// Post decryption:
//   1. Find your entry in recipientKeys by fingerprint
//   2. ECDH(your_private, author_public) → same shared secret
//   3. Unwrap the content key
//   4. Decrypt ciphertext with the content key
//
// ============================================================================

const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/**
 * Encrypt post content for a set of recipients.
 *
 * @param {string} plaintext - The post content (text)
 * @param {CryptoKey} authorEncPrivateKey - Author's ECDH private key
 * @param {CryptoKey} authorEncPublicKey - Author's ECDH public key (to encrypt for self)
 * @param {string} authorFingerprint - Author's fingerprint
 * @param {Array<{fingerprint: string, encryptionPublicKey: CryptoKey}>} recipients
 *        - List of friends with their public encryption keys
 * @returns {Object} Encrypted post envelope ready for upload
 */
export async function encryptPost(plaintext, authorEncPrivateKey, authorEncPublicKey, authorFingerprint, recipients) {
  // 1. Generate random content key
  const contentKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );

  // 2. Encrypt the content
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    contentKey,
    new TextEncoder().encode(plaintext)
  );

  // 3. Wrap content key for each recipient (friends + self)
  const allRecipients = [
    { fingerprint: authorFingerprint, encryptionPublicKey: authorEncPublicKey },
    ...recipients,
  ];

  const recipientKeys = [];
  for (const recipient of allRecipients) {
    try {
      const wrapped = await wrapKeyForRecipient(
        contentKey, authorEncPrivateKey, recipient.encryptionPublicKey
      );
      recipientKeys.push({
        fingerprint: recipient.fingerprint,
        wrappedKey: toB64(wrapped.wrappedKey),
        iv: toB64(wrapped.iv),
      });
    } catch (err) {
      console.warn(`[crypto] Failed to wrap key for ${recipient.fingerprint}:`, err.message);
    }
  }

  return {
    ciphertext: toB64(new Uint8Array(ciphertext)),
    iv: toB64(iv),
    recipientKeys,
  };
}

/**
 * Decrypt post content.
 *
 * @param {Object} encryptedPost - The encrypted envelope from IPFS
 * @param {string} myFingerprint - Your fingerprint to find your wrapped key
 * @param {CryptoKey} myEncPrivateKey - Your ECDH private key
 * @param {CryptoKey} authorEncPublicKey - The post author's ECDH public key
 * @returns {string|null} Decrypted plaintext, or null if not authorized
 */
export async function decryptPost(encryptedPost, myFingerprint, myEncPrivateKey, authorEncPublicKey) {
  // Find our wrapped key
  const myKeyData = encryptedPost.recipientKeys?.find(
    rk => rk.fingerprint === myFingerprint
  );

  if (!myKeyData) {
    return null; // Not shared with us
  }

  try {
    // Unwrap the content key
    const contentKey = await unwrapKeyFromSender(
      fromB64(myKeyData.wrappedKey),
      fromB64(myKeyData.iv),
      myEncPrivateKey,
      authorEncPublicKey
    );

    // Decrypt the content
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(encryptedPost.iv) },
      contentKey,
      fromB64(encryptedPost.ciphertext)
    );

    return new TextDecoder().decode(plaintext);
  } catch (err) {
    console.error("[crypto] Decryption failed:", err.message);
    return null;
  }
}

/**
 * Encrypt a file (image, attachment) with a random key.
 * Returns the encrypted data and the key (which should be wrapped per-recipient).
 */
export async function encryptFile(fileData) {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, fileData
  );
  return {
    encrypted: new Uint8Array(ciphertext),
    iv: toB64(iv),
    key, // Wrap this for recipients the same way as post content keys
  };
}

/**
 * Decrypt a file with a known key.
 */
export async function decryptFile(encryptedData, key, iv) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(iv) }, key, encryptedData
  );
  return new Uint8Array(plaintext);
}

// ============================================================================
// Key wrapping internals (ECDH key agreement + AES-GCM key wrap)
// ============================================================================

/**
 * Wrap a content key for a specific recipient using ECDH.
 */
async function wrapKeyForRecipient(contentKey, senderPrivateKey, recipientPublicKey) {
  const sharedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientPublicKey },
    senderPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = await crypto.subtle.wrapKey(
    "raw", contentKey, sharedKey, { name: "AES-GCM", iv }
  );

  return { wrappedKey: new Uint8Array(wrappedKey), iv };
}

/**
 * Unwrap a content key received from a sender using ECDH.
 */
async function unwrapKeyFromSender(wrappedKeyData, iv, recipientPrivateKey, senderPublicKey) {
  const sharedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: senderPublicKey },
    recipientPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );

  return crypto.subtle.unwrapKey(
    "raw", wrappedKeyData, sharedKey,
    { name: "AES-GCM", iv },
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// ============================================================================
// Public key import/export helpers
// ============================================================================

/**
 * Import a base64-encoded ECDH public key for use in key wrapping.
 */
export async function importEncryptionPublicKey(b64) {
  return crypto.subtle.importKey(
    "raw", fromB64(b64),
    { name: "ECDH", namedCurve: "P-256" },
    true, []
  );
}

/**
 * Export an ECDH public key to base64.
 */
export async function exportEncryptionPublicKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return toB64(new Uint8Array(raw));
}

/**
 * Compute a fingerprint from a signing public key (base64).
 */
export async function computeFingerprint(signingPublicKeyB64) {
  const raw = fromB64(signingPublicKeyB64);
  const hash = await crypto.subtle.digest("SHA-256", raw);
  return Array.from(new Uint8Array(hash).slice(0, 8))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("").match(/.{4}/g).join("-");
}
