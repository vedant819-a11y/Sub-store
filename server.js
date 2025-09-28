// server.js
require('dotenv').config();
const express = require('express');
const { Telegraf } = require('telegraf');
const crypto = require('crypto');
const fetch = require('node-fetch'); // use node-fetch@2 (npm install node-fetch@2) if Node <18

const app = express();
app.use(express.json());

// ---------- CONFIG ----------
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const DOMAIN = (process.env.DOMAIN || 'http://localhost:3000').replace(/\/$/, '');
const SHORTLINKER_API = process.env.SHORTLINKER_API || ''; // optional external shortener
const ADMIN_IDS = (process.env.ADMIN_IDS || '')
  .split(',')
  .map(s => Number(s.trim()))
  .filter(Boolean);
const SIGNING_SECRET = process.env.SIGNING_SECRET || ''; // set to enable signed URLs
const LINK_TTL_MINUTES = Number(process.env.LINK_TTL_MINUTES || '60'); // default 60 minutes
const PORT = Number(process.env.PORT || 3000);

if (!BOT_TOKEN) {
  console.error('ERROR: TELEGRAM_BOT_TOKEN is required in .env');
  process.exit(1);
}

// ---------- In-memory stores (demo) ----------
const users = new Map(); // telegram_id -> { is_premium: bool, premium_expires: ts }
const links = new Map(); // token -> { owner, original_url, short_url, created_at }
const shorts = new Map(); // for local short fallback: shortId -> original_url

// ---------- helpers ----------
function genToken(len = 16) {
  return crypto.randomBytes(len).toString('hex');
}

async function createShort(url) {
  if (SHORTLINKER_API) {
    const res = await fetch(SHORTLINKER_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`Shortlinker error: ${res.status} ${txt}`);
    }
    const json = await res.json();
    return json.short_url || json.shortUrl || json.url || null;
  } else {
    // local short: DOMAIN/s/<id>
    const shortId = genToken(4);
    shorts.set(shortId, url);
    return `${DOMAIN}/s/${shortId}`;
  }
}

function signToken(token, tg, exp) {
  if (!SIGNING_SECRET) return '';
  return crypto.createHmac('sha256', SIGNING_SECRET)
    .update(`${token}|${tg}|${exp}`)
    .digest('hex');
}

function verifySignature(token, tg, exp, sig) {
  if (!SIGNING_SECRET) return true; // no signing configured
  if (!token || !tg || !exp || !sig) return false;
  const expected = signToken(token, tg, exp);
  return expected === sig && Number(exp) > Date.now();
}

// ---------- Telegram bot ----------
const bot = new Telegraf(BOT_TOKEN);

// /start
bot.start((ctx) => {
  ctx.reply('Welcome! Use /shorten <url> to create a link.\nAdmin commands: /makepremium /removepremium /status');
  console.log('User started bot:', ctx.from.id, ctx.from.username || '');
});

// /shorten <url>
bot.command('shorten', async (ctx) => {
  try {
    const parts = ctx.message.text.split(' ').filter(Boolean);
    if (parts.length < 2) return ctx.reply('Usage: /shorten <full-url>');
    const url = parts[1].trim();

    // create monetized short_url (external or local fallback)
    const short = await createShort(url);

    const token = genToken(12);
    links.set(token, {
      owner: ctx.from.id,
      original_url: url,
      short_url: short,
      created_at: Date.now()
    });

    // Prepare signed (or plain) redirect URL
    const tg = ctx.from.id;
    if (SIGNING_SECRET) {
      const exp = Date.now() + LINK_TTL_MINUTES * 60 * 1000;
      const sig = signToken(token, tg, exp);
      const redirectUrl = `${DOMAIN}/r/${token}?tg=${tg}&exp=${exp}&sig=${sig}`;
      await ctx.reply(`✅ Link created (valid for ${LINK_TTL_MINUTES} minutes):\n${redirectUrl}`);
    } else {
      // insecure fallback (anyone with this URL will be treated as owner when tg param present)
      const redirectUrl = `${DOMAIN}/r/${token}?tg=${tg}`;
      await ctx.reply(`✅ Link created:\n${redirectUrl}\n\n⚠️ WARNING: You do not have SIGNING_SECRET set. This link can be copied and used by others.`);
    }
  } catch (err) {
    console.error('shorten error:', err);
    ctx.reply('Error creating short link: ' + (err.message || err));
  }
});

// Admin: /makepremium <telegram_id> <days>
bot.command('makepremium', (ctx) => {
  if (!ADMIN_IDS.includes(ctx.from.id)) return ctx.reply('⛔ Permission denied.');
  const args = ctx.message.text.split(' ').slice(1);
  if (args.length < 2) return ctx.reply('Usage: /makepremium <telegram_id> <days>');
  const telegramId = Number(args[0]);
  const days = Number(args[1]);
  if (!telegramId || !days) return ctx.reply('Invalid arguments.');
  users.set(telegramId, { is_premium: true, premium_expires: Date.now() + days * 24 * 3600 * 1000 });
  ctx.reply(`✅ User ${telegramId} given premium for ${days} days.`);
});

// Admin: /removepremium <telegram_id>
bot.command('removepremium', (ctx) => {
  if (!ADMIN_IDS.includes(ctx.from.id)) return ctx.reply('⛔ Permission denied.');
  const args = ctx.message.text.split(' ').slice(1);
  if (args.length < 1) return ctx.reply('Usage: /removepremium <telegram_id>');
  const telegramId = Number(args[0]);
  if (!telegramId) return ctx.reply('Invalid telegram_id.');
  users.set(telegramId, { is_premium: false, premium_expires: null });
  ctx.reply(`❌ User ${telegramId} premium removed.`);
});

// /status <telegram_id?> (if no arg, shows your own status)
bot.command('status', (ctx) => {
  const args = ctx.message.text.split(' ').slice(1);
  const id = args.length ? Number(args[0]) : ctx.from.id;
  if (!id) return ctx.reply('Usage: /status <telegram_id> or /status');
  const u = users.get(id);
  if (!u || !u.is_premium || !(u.premium_expires > Date.now())) {
    return ctx.reply(`User ${id} is NOT premium.`);
  } else {
    const expires = new Date(u.premium_expires).toLocaleString();
    return ctx.reply(`User ${id} is PREMIUM until ${expires}`);
  }
});

bot.launch().then(() => console.log('Telegram bot started'));

// ---------- Express routes ----------

// Redirect handler
app.get('/r/:token', (req, res) => {
  const token = req.params.token;
  const record = links.get(token);
  if (!record) return res.status(404).send('Invalid or expired link.');

  const tg = req.query.tg ? Number(req.query.tg) : null;
  const exp = req.query.exp ? Number(req.query.exp) : null;
  const sig = req.query.sig ? String(req.query.sig) : null;

  // Validate signature if SIGNING_SECRET is set, else insecure accept tg param
  const sigValid = verifySignature(token, tg, exp, sig);

  if (!sigValid) {
    console.warn('Signature invalid or expired for token', token);
    // For invalid signature, DO NOT grant direct access. Redirect to short_url (monetized).
    return res.redirect(record.short_url);
  }

  // Check premium: allow direct if tg === record.owner OR tg is premium
  const isOwner = tg === record.owner;
  let isPremium = false;
  if (tg && users.has(tg)) {
    const u = users.get(tg);
    if (u.is_premium && u.premium_expires > Date.now()) isPremium = true;
  }

  if (isOwner || isPremium) {
    return res.redirect(record.original_url);
  } else {
    return res.redirect(record.short_url);
  }
});

// Local short fallback route (if no external shortlinker)
app.get('/s/:shortId', (req, res) => {
  const id = req.params.shortId;
  const orig = shorts.get(id);
  if (!orig) return res.status(404).send('Short link not found.');
  return res.redirect(orig);
});

// Health
app.get('/_health', (_, res) => res.send('OK'));

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Domain: ${DOMAIN}`);
  if (SIGNING_SECRET) {
    console.log('Signed URL mode: ON (LINK TTL mins =', LINK_TTL_MINUTES, ')');
  } else {
    console.log('Signed URL mode: OFF (INSECURE tg param will be used)');
  }
});