import crypto from "crypto";

const ALGO = "aes-256-gcm";
const ENC_KEY = crypto.createHash("sha256").update(process.env.PHONE_ENCRYPTION_KEY || "insecure-default-change-me").digest();
const HASH_KEY = process.env.PHONE_HASH_KEY || "insecure-default-change-me-too";

// Детерминированный отпечаток телефона — по нему ищем в базе (сам номер
// не хранится и не ищется в открытом виде).
export function hashPhone(phone) {
  return crypto.createHmac("sha256", HASH_KEY).update(phone).digest("hex");
}

export function encryptPhone(phone) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(phone, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decryptPhone(payload) {
  const buf = Buffer.from(payload, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

export function maskPhone(phone) {
  return phone.slice(0, -4).replace(/\d/g, "•") + phone.slice(-4);
}

// ---------- Шифрование записей хранилища "Данные" (ключ = пароль пользователя) ----------
export function deriveVaultKey(password, userId) {
  return crypto.createHmac("sha256", `${password}:${userId}`).update("vault-v1").digest();
}

export function encryptWithKey(key, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decryptWithKey(key, payload) {
  try {
    const buf = Buffer.from(payload, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}
