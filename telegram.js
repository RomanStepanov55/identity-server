import "dotenv/config";

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
export const WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET || "alontito-tg-secret-change-me";

export function isTelegramConfigured() {
  return Boolean(BOT_TOKEN && process.env.TELEGRAM_BOT_USERNAME);
}

export function telegramDeepLink(code) {
  return `https://t.me/${process.env.TELEGRAM_BOT_USERNAME}?start=${code}`;
}

// Регистрирует вебхук у Telegram один раз при старте сервера — сам находит
// свой публичный адрес (Render сам прописывает RENDER_EXTERNAL_URL).
export async function registerWebhookIfNeeded() {
  if (!BOT_TOKEN) return;
  const publicUrl = process.env.RENDER_EXTERNAL_URL || process.env.PUBLIC_URL;
  if (!publicUrl) {
    console.warn("⚠️  Не удалось определить публичный адрес для Telegram-вебхука — задай PUBLIC_URL в .env вручную");
    return;
  }
  try {
    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: `${publicUrl}/telegram/webhook`, secret_token: WEBHOOK_SECRET }),
    });
    const data = await res.json();
    if (data.ok) console.log("✅ Telegram-бот подключён, вебхук зарегистрирован");
    else console.error("Не удалось зарегистрировать Telegram-вебхук:", data);
  } catch (err) {
    console.error("Ошибка регистрации Telegram-вебхука:", err);
  }
}

export async function sendTelegramMessage(chatId, text) {
  if (!BOT_TOKEN) return false;
  try {
    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text }),
    });
    const data = await res.json();
    return data.ok === true;
  } catch {
    return false;
  }
}
