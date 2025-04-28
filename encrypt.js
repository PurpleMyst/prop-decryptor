/**
 * encrypt.js
 *
 * Usage: node encrypt.js <inputFile> <password>
 *
 * Encrypts the specified file using AES-256-GCM with a PBKDF2-derived key.
 * The output file (<inputFile>.enc) has the following format:
 *   [16 bytes salt][12 bytes IV][ciphertext][16 bytes auth tag]
 *
 * The corresponding browser decryptor reads the salt and IV, derives
 * the same key via PBKDF2 (100k iterations, SHA-256), and decrypts
 * the AES-GCM ciphertext (with tag) to recover the original data.
 */

import { randomBytes, pbkdf2Sync, createCipheriv } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { basename } from "path";

// Ensure correct usage
if (process.argv.length < 4) {
  console.error("Usage: node encrypt.js <inputFile> <password>");
  process.exit(1);
}

const inputPath = process.argv[2];
const password = process.argv[3];
// Output file: original filename + .enc extension
const outputPath = "src/" + basename(inputPath) + ".enc";

// Read input file into buffer
const fileData = readFileSync(inputPath);

// Generate a random 16-byte salt and 12-byte IV
const salt = randomBytes(16);
const iv = randomBytes(12);

// Derive a 32-byte key using PBKDF2 (100,000 iterations, SHA-256)
const key = pbkdf2Sync(
  password, // password
  salt, // salt
  100000, // iterations
  32, // key length (bytes)
  "sha256", // hash function
);

// Create AES-256-GCM cipher instance
const cipher = createCipheriv("aes-256-gcm", key, iv);

// Encrypt the file data
const encrypted = Buffer.concat([cipher.update(fileData), cipher.final()]);

// Get the authentication tag (16 bytes)
const authTag = cipher.getAuthTag();

// Concatenate salt + iv + ciphertext + authTag
const outputBuffer = Buffer.concat([salt, iv, encrypted, authTag]);

// Write the encrypted blob to disk
writeFileSync(outputPath, outputBuffer);
console.log(`Encrypted '${basename(inputPath)}' → '${basename(outputPath)}'`);
