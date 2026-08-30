import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
});

export const ADMIN_PHONE = "+79950023339";

export async function initDb() {
  await pool.query(`
    -- Единственное место во всём проекте, где вообще хранится номер
    -- телефона и пароль хранилища. phone_enc — зашифрован (AES-256-GCM),
    -- phone_hash — детерминированный HMAC для поиска (по нему ищем при
    -- входе, сам телефон в открытом виде для поиска не используется).
    CREATE TABLE IF NOT EXISTS identities (
      id SERIAL PRIMARY KEY,
      phone_hash TEXT UNIQUE NOT NULL,
      phone_enc TEXT NOT NULL,
      phone_hint TEXT NOT NULL,
      username TEXT UNIQUE,
      vault_password_hash TEXT,
      telegram_chat_id BIGINT,
      is_banned BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
      phone_hash TEXT PRIMARY KEY,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS telegram_link_codes (
      code TEXT PRIMARY KEY,
      phone_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vault_items (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES identities(id),
      title TEXT NOT NULL,
      value_encrypted TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE identities ADD COLUMN IF NOT EXISTS telegram_chat_id BIGINT;`);

  if (!process.env.INTERNAL_API_KEY) {
    console.warn("⚠️  INTERNAL_API_KEY не задан — этот сервер НЕЛЬЗЯ включать без него, любой сможет читать телефоны!");
  }
  if (!process.env.PHONE_ENCRYPTION_KEY) {
    console.warn("⚠️  PHONE_ENCRYPTION_KEY не задан — телефоны шифруются дефолтным ключом, смени в .env!");
  }

  console.log("identity-server: база готова (телефоны + пароли хранилища, изолированно)");
}
