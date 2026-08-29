import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import http from "http";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool, initDb, ADMIN_PHONE } from "./db.js";
import { hashPhone, encryptPhone, decryptPhone, maskPhone, deriveVaultKey, encryptWithKey, decryptWithKey } from "./crypto.js";

const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || "";
const MAX_OTP_ATTEMPTS = 5;
const SESSION_TTL_MS = 5 * 60 * 1000;

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors()); // сюда всё равно не достучаться без internalOnly-ключа ниже
app.use(express.json({ limit: "1mb" }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

// ---------------------------------------------------------------------
// КРИТИЧНО: этот сервер не предназначен для прямых обращений из браузера.
// Единственный легитимный клиент — messenger-server (сервер-к-серверу).
// Каждый запрос обязан нести правильный x-internal-key — иначе 403.
// Если развернёшь этот сервис на Render и НЕ поставишь x-internal-key
// в переменные окружения — сервер откажется стартовать вообще (см. ниже).
// ---------------------------------------------------------------------
function internalOnly(req, res, next) {
  if (!INTERNAL_API_KEY || req.headers["x-internal-key"] !== INTERNAL_API_KEY) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}
app.use("/internal", internalOnly);

function generateCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
async function sendSms(phone, code) { console.log(`\n📱 [DEV-РЕЖИМ, identity-server] Код для ${phone}: ${code}\n`); }

const ADJ = ["swift", "quiet", "bright", "calm", "bold", "quick", "warm", "cool", "sharp", "kind"];
const NOUN = ["fox", "wave", "spark", "cloud", "river", "ember", "comet", "maple", "hawk", "pine"];
async function generateUsername() {
  for (let i = 0; i < 20; i++) {
    const c = `${ADJ[Math.floor(Math.random() * ADJ.length)]}_${NOUN[Math.floor(Math.random() * NOUN.length)]}${Math.floor(Math.random() * 900 + 100)}`;
    const exists = await pool.query("SELECT 1 FROM identities WHERE username = $1", [c]);
    if (!exists.rows.length) return c;
  }
  return `user${Date.now()}`;
}

// ---------- Вход: запросить код ----------
app.post("/internal/auth/request-code", async (req, res) => {
  try {
    const identifier = (req.body.identifier || "").trim();
    let phone;
    if (/^\+?\d{10,15}$/.test(identifier.replace(/[\s()-]/g, ""))) {
      phone = identifier.replace(/[\s()-]/g, "");
    } else {
      const r = await pool.query("SELECT phone_enc FROM identities WHERE username = $1", [identifier]);
      if (!r.rows.length) return res.status(404).json({ error: "Такого юзернейма нет. Для первого входа используй номер телефона." });
      phone = decryptPhone(r.rows[0].phone_enc);
    }

    const phoneHash = hashPhone(phone);
    const banned = await pool.query("SELECT is_banned FROM identities WHERE phone_hash = $1", [phoneHash]);
    if (banned.rows[0]?.is_banned) return res.status(403).json({ error: "Этот аккаунт заблокирован" });

    const code = generateCode();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await pool.query(
      `INSERT INTO otp_codes (phone_hash, code, expires_at, attempts) VALUES ($1, $2, $3, 0)
       ON CONFLICT (phone_hash) DO UPDATE SET code = $2, expires_at = $3, attempts = 0`,
      [phoneHash, code, expiresAt]
    );
    await sendSms(phone, code);
    res.json({ ok: true, phoneHint: maskPhone(phone) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Не удалось отправить код" });
  }
});

// ---------- Вход: подтвердить код, создать/найти пользователя, выдать JWT ----------
app.post("/internal/auth/verify-code", async (req, res) => {
  try {
    const identifier = (req.body.identifier || "").trim();
    const code = (req.body.code || "").trim();

    let phone;
    if (/^\+?\d{10,15}$/.test(identifier.replace(/[\s()-]/g, ""))) {
      phone = identifier.replace(/[\s()-]/g, "");
    } else {
      const r = await pool.query("SELECT phone_enc FROM identities WHERE username = $1", [identifier]);
      if (!r.rows.length) return res.status(404).json({ error: "Пользователь не найден" });
      phone = decryptPhone(r.rows[0].phone_enc);
    }
    const phoneHash = hashPhone(phone);

    const otpRes = await pool.query("SELECT * FROM otp_codes WHERE phone_hash = $1", [phoneHash]);
    const otp = otpRes.rows[0];
    if (!otp || new Date(otp.expires_at) < new Date()) return res.status(401).json({ error: "Код истёк, запроси новый" });
    if (otp.attempts >= MAX_OTP_ATTEMPTS) return res.status(429).json({ error: "Слишком много попыток, запроси новый код" });
    if (otp.code !== code) {
      await pool.query("UPDATE otp_codes SET attempts = attempts + 1 WHERE phone_hash = $1", [phoneHash]);
      const left = MAX_OTP_ATTEMPTS - otp.attempts - 1;
      return res.status(401).json({ error: left > 0 ? `Неверный код. Осталось попыток: ${left}` : "Попытки закончились, запроси новый код" });
    }
    await pool.query("DELETE FROM otp_codes WHERE phone_hash = $1", [phoneHash]);

    let r = await pool.query("SELECT * FROM identities WHERE phone_hash = $1", [phoneHash]);
    let identity = r.rows[0];
    const isAdmin = phone === ADMIN_PHONE;

    if (!identity) {
      const username = await generateUsername();
      const insert = await pool.query(
        "INSERT INTO identities (phone_hash, phone_enc, phone_hint, username) VALUES ($1, $2, $3, $4) RETURNING *",
        [phoneHash, encryptPhone(phone), maskPhone(phone), username]
      );
      identity = insert.rows[0];
    }
    if (identity.is_banned) return res.status(403).json({ error: "Этот аккаунт заблокирован" });

    const token = jwt.sign({ userId: identity.id, phoneHash }, JWT_SECRET, { expiresIn: "30d" });
    res.json({
      token,
      user: { id: identity.id, username: identity.username, phoneHint: identity.phone_hint, isAdmin, isNew: !r.rows.length },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Не удалось подтвердить код" });
  }
});

function requireUser(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Нет токена" });
  try {
    const payload = jwt.verify(header.replace("Bearer ", ""), JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ error: "Токен недействителен" });
  }
}

// ---------- Профиль: юзернейм, свой номер (только себе, замаскированный) ----------
app.get("/internal/users/:id", async (req, res) => {
  const r = await pool.query("SELECT id, username, phone_hint FROM identities WHERE id = $1", [req.params.id]);
  if (!r.rows.length) return res.status(404).json({ error: "not found" });
  res.json(r.rows[0]);
});

app.get("/internal/users/search", async (req, res) => {
  const q = `%${(req.query.q || "").replace(/[\s()-]/g, "")}%`;
  const r = await pool.query(
    "SELECT id, username, phone_hint FROM identities WHERE (username ILIKE $1 OR phone_hash = $2) AND is_banned = FALSE LIMIT 20",
    [q, hashPhone((req.query.q || "").replace(/[\s()-]/g, ""))]
  );
  res.json(r.rows);
});

app.patch("/internal/users/:id/username", async (req, res) => {
  const username = (req.body.username || "").trim();
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: "Юзернейм: 3-20 символов" });
  const taken = await pool.query("SELECT 1 FROM identities WHERE username = $1 AND id != $2", [username, req.params.id]);
  if (taken.rows.length) return res.status(409).json({ error: "Юзернейм уже занят" });
  await pool.query("UPDATE identities SET username = $1 WHERE id = $2", [username, req.params.id]);
  res.json({ ok: true, username });
});

app.get("/internal/users/:id/phone", requireUser, async (req, res) => {
  if (Number(req.params.id) !== req.userId) return res.status(403).json({ error: "Только свой номер" });
  const r = await pool.query("SELECT phone_enc FROM identities WHERE id = $1", [req.params.id]);
  if (!r.rows.length) return res.status(404).json({ error: "not found" });
  res.json({ phone: decryptPhone(r.rows[0].phone_enc) });
});

// ---------- Админ: список/бан (messenger-server сам решает, кто admin, и дергает эти internal-роуты) ----------
app.get("/internal/admin/users", async (req, res) => {
  const r = await pool.query("SELECT id, username, phone_hint, is_banned, created_at FROM identities ORDER BY id DESC");
  res.json(r.rows);
});
app.post("/internal/admin/ban", async (req, res) => {
  await pool.query("UPDATE identities SET is_banned = TRUE WHERE id = $1", [req.body.userId]);
  res.json({ ok: true });
});
app.post("/internal/admin/unban", async (req, res) => {
  await pool.query("UPDATE identities SET is_banned = FALSE WHERE id = $1", [req.body.userId]);
  res.json({ ok: true });
});

// ============================================================
// Хранилище "Данные" — здесь же, вместе с паролем и номером,
// это самая защищённая часть всего проекта
// ============================================================

const vaultSessions = new Map(); // vaultToken -> { key, userId, expiresAt }
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of vaultSessions) if (s.expiresAt < now) vaultSessions.delete(t);
}, 60000).unref();

app.get("/internal/vault/status", requireUser, async (req, res) => {
  const r = await pool.query("SELECT vault_password_hash FROM identities WHERE id = $1", [req.userId]);
  res.json({ isSetup: Boolean(r.rows[0]?.vault_password_hash) });
});

app.post("/internal/vault/setup", requireUser, async (req, res) => {
  const r = await pool.query("SELECT vault_password_hash FROM identities WHERE id = $1", [req.userId]);
  const has = Boolean(r.rows[0]?.vault_password_hash);
  if (!has) {
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ error: "Пароль хранилища должен быть не короче 6 символов" });
    await pool.query("UPDATE identities SET vault_password_hash = $1 WHERE id = $2", [bcrypt.hashSync(password, 10), req.userId]);
    return res.json({ ok: true, created: true });
  }
  const { oldPassword, newPassword } = req.body;
  if (!bcrypt.compareSync(oldPassword || "", r.rows[0].vault_password_hash)) return res.status(401).json({ error: "Старый пароль неверный" });
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "Новый пароль должен быть не короче 6 символов" });
  await pool.query("UPDATE identities SET vault_password_hash = $1 WHERE id = $2", [bcrypt.hashSync(newPassword, 10), req.userId]);
  res.json({ ok: true, created: false });
});

app.post("/internal/vault/request-code", requireUser, async (req, res) => {
  const r = await pool.query("SELECT phone_enc FROM identities WHERE id = $1", [req.userId]);
  const phone = decryptPhone(r.rows[0].phone_enc);
  const phoneHash = hashPhone(phone);
  const code = generateCode();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await pool.query(
    `INSERT INTO otp_codes (phone_hash, code, expires_at, attempts) VALUES ($1, $2, $3, 0)
     ON CONFLICT (phone_hash) DO UPDATE SET code = $2, expires_at = $3, attempts = 0`,
    [phoneHash, code, expiresAt]
  );
  await sendSms(phone, code);
  res.json({ ok: true });
});

app.post("/internal/vault/unlock", requireUser, async (req, res) => {
  const { password, code } = req.body;
  const r = await pool.query("SELECT phone_enc, vault_password_hash FROM identities WHERE id = $1", [req.userId]);
  const row = r.rows[0];
  if (!row?.vault_password_hash) return res.status(400).json({ error: "Хранилище ещё не настроено" });
  if (!bcrypt.compareSync(password || "", row.vault_password_hash)) return res.status(401).json({ error: "Неверный пароль хранилища" });

  const phone = decryptPhone(row.phone_enc);
  const phoneHash = hashPhone(phone);
  const otpRes = await pool.query("SELECT * FROM otp_codes WHERE phone_hash = $1", [phoneHash]);
  const otp = otpRes.rows[0];
  if (!otp || new Date(otp.expires_at) < new Date()) return res.status(401).json({ error: "Код истёк, запроси новый" });
  if (otp.attempts >= MAX_OTP_ATTEMPTS) return res.status(429).json({ error: "Слишком много попыток" });
  if (otp.code !== (code || "").trim()) {
    await pool.query("UPDATE otp_codes SET attempts = attempts + 1 WHERE phone_hash = $1", [phoneHash]);
    return res.status(401).json({ error: "Неверный код" });
  }
  await pool.query("DELETE FROM otp_codes WHERE phone_hash = $1", [phoneHash]);

  const key = deriveVaultKey(password, req.userId);
  const vaultToken = Buffer.from(`${Date.now()}-${Math.random()}`).toString("hex").slice(0, 48);
  vaultSessions.set(vaultToken, { key, userId: req.userId, expiresAt: Date.now() + SESSION_TTL_MS });
  res.json({ vaultToken, expiresInSeconds: SESSION_TTL_MS / 1000 });
});

function vaultAuth(req, res, next) {
  const token = req.headers["x-vault-token"];
  const s = token && vaultSessions.get(token);
  if (!s || s.expiresAt < Date.now() || s.userId !== req.userId) return res.status(401).json({ error: "Сессия хранилища истекла" });
  s.expiresAt = Date.now() + SESSION_TTL_MS;
  req.vaultKey = s.key;
  next();
}

app.get("/internal/vault/items", requireUser, vaultAuth, async (req, res) => {
  const r = await pool.query("SELECT id, title, value_encrypted, created_at FROM vault_items WHERE user_id = $1 ORDER BY id DESC", [req.userId]);
  res.json(r.rows.map((row) => ({ id: row.id, title: row.title, created_at: row.created_at, value: decryptWithKey(req.vaultKey, row.value_encrypted) ?? "[ошибка расшифровки]" })));
});
app.post("/internal/vault/items", requireUser, vaultAuth, async (req, res) => {
  const { title, value } = req.body;
  if (!title || !value) return res.status(400).json({ error: "Нужны title и value" });
  const enc = encryptWithKey(req.vaultKey, String(value));
  const r = await pool.query("INSERT INTO vault_items (user_id, title, value_encrypted) VALUES ($1, $2, $3) RETURNING id, created_at", [req.userId, String(title).slice(0, 100), enc]);
  res.json({ id: r.rows[0].id, title, value, created_at: r.rows[0].created_at });
});
app.delete("/internal/vault/items/:id", requireUser, vaultAuth, async (req, res) => {
  await pool.query("DELETE FROM vault_items WHERE id = $1 AND user_id = $2", [req.params.id, req.userId]);
  res.json({ ok: true });
});
app.post("/internal/vault/lock", requireUser, (req, res) => {
  vaultSessions.delete(req.headers["x-vault-token"]);
  res.json({ ok: true });
});

app.get("/", (req, res) => res.json({ ok: true, service: "identity-server", note: "internal use only" }));

const PORT = process.env.PORT || 4001;

if (!INTERNAL_API_KEY) {
  console.error("❌ INTERNAL_API_KEY не задан — сервер отказывается запускаться без него (иначе телефоны были бы доступны кому угодно).");
  process.exit(1);
}

initDb()
  .then(() => http.createServer(app).listen(PORT, () => console.log(`identity-server запущен на порту ${PORT}`)))
  .catch((err) => { console.error("Не удалось подключиться к базе данных:", err); process.exit(1); });
