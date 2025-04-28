import "./style.css";
import encHtml from "./index.html.enc?url";

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function decryptPage() {
  const password = decodeURIComponent(location.hash.substring(1));
  if (!password) {
    console.error("No password provided in fragment.");
    return;
  }

  try {
    const response = await fetch(encHtml);
    const data = new Uint8Array(await response.arrayBuffer());

    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ct = data.slice(28);

    const key = await deriveKey(password, salt);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    const html = new TextDecoder().decode(plain);

    document.open();
    document.write(html);
    document.close();
  } catch (err) {
    console.error("Decryption failed:", err);
    alert("Decryption failed — wrong password or corrupted data.");
  }
}

window.addEventListener("load", decryptPage);
