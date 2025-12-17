import express from "express";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";
import dns from "dns/promises";
import net from "net";
import iconv from "iconv-lite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ==============================
// Security / Basic settings
// ==============================

// Reverse-proxy (Render等) で rateLimit を正しく効かせる
app.set("trust proxy", 1);

// JSON body limit
app.use(express.json({ limit: "200kb" }));

// Simple rate limit（乱用・連打対策）
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Static hosting
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// ==============================
// Constants
// ==============================
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const MAX_HTML_BYTES = 900_000; // 0.9MB
const FETCH_TIMEOUT_MS = 12_000;
const MAX_FOLLOWUP_PAGES = 4; // 特商法/返品等の追加クロール上限
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36 Labelly/1.0";

// ==============================
// Helpers: URL / SSRF guard
// ==============================
function safeParseUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (!ALLOWED_PROTOCOLS.has(u.protocol)) return null;
  // ユーザー名/パスワード入りURLは禁止
  if (u.username || u.password) return null;
  return u;
}

function isPrivateIp(ip) {
  // IPv4 private / loopback / link-local
  if (net.isIP(ip) === 4) {
    const parts = ip.split(".").map((n) => Number(n));
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
  }
  // IPv6: loopback / link-local / unique local
  if (net.isIP(ip) === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return true;
    if (lower.startsWith("fe80:")) return true; // link-local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
    return false;
  }
  return true; // unknown => block
}

async function ssrfGuard(hostname) {
  // DNS resolveして private ip なら拒否
  // （Render環境によってはIPv6も返るので all:true）
  const res = await dns.lookup(hostname, { all: true });
  for (const r of res) {
    if (isPrivateIp(r.address)) return false;
  }
  return true;
}

// ==============================
// Helpers: Fetch + Decode
// ==============================
function extractCharset(contentType) {
  const m = /charset\s*=\s*([^;]+)/i.exec(contentType || "");
  return m ? m[1].trim().toLowerCase() : "";
}

function decodeBuffer(buf, charset) {
  // 主要な日本語charsetに対応（EUC-JP/Shift_JIS等）
  const cs = (charset || "").toLowerCase();
  try {
    if (cs.includes("euc-jp") || cs.includes("eucjp")) return iconv.decode(Buffer.from(buf), "euc-jp");
    if (cs.includes("shift_jis") || cs.includes("shift-jis") || cs.includes("sjis"))
      return iconv.decode(Buffer.from(buf), "shift_jis");
    if (cs.includes("iso-2022-jp")) return iconv.decode(Buffer.from(buf), "iso-2022-jp");
  } catch {
    // fallthrough
  }
  // default utf-8
  try {
    return new TextDecoder("utf-8").decode(buf);
  } catch {
    return Buffer.from(buf).toString("utf8");
  }
}

async function fetchHtml(url, debug = false) {
  const u = new URL(url);
  const ok = await ssrfGuard(u.hostname);
  if (!ok) return { ok: false, reason: "blocked_private_network" };

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": UA,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
      },
    });

    const ct = (res.headers.get("content-type") || "").toLowerCase();
    const charset = extractCharset(ct);

    if (debug) console.log(`[fetch] ${url} ${res.status} ${ct || "-"}`);

    if (!res.ok) return { ok: false, reason: `http_${res.status}` };
    if (!ct.includes("text/html")) return { ok: false, reason: "not_html" };

    const buf = await res.arrayBuffer();
    if (debug) console.log(`[size] ${buf.byteLength}`);
    if (buf.byteLength > MAX_HTML_BYTES) return { ok: false, reason: "too_large" };

    const html = decodeBuffer(buf, charset);
    return { ok: true, html, contentType: ct, charset, finalUrl: res.url || url, headers: res.headers };
  } catch {
    return { ok: false, reason: "fetch_failed" };
  } finally {
    clearTimeout(t);
  }
}

// ==============================
// Platform detection
// ==============================
function detectPlatform({ html = "", headers = null, finalUrl = "" }) {
  const h = html || "";
  const u = (finalUrl || "").toLowerCase();

  // Amazon / Rakuten are usually easy by hostname
  const hostname = (() => {
    try {
      return new URL(finalUrl).hostname.toLowerCase();
    } catch {
      return "";
    }
  })();

  if (hostname.includes("amazon.") || hostname.endsWith("amazon.co.jp")) return "amazon";
  if (hostname.includes("rakuten.co.jp")) return "rakuten";

  // BASE
  // base shops often include these hints
  if (h.includes("thebase.in") || /base\s*ec/i.test(h) || h.includes("BASE株式会社")) return "base";
  if (u.includes(".thebase.in") || u.includes("thebase.in")) return "base";

  // Shopify
  if (h.includes("cdn.shopify.com") || h.includes("Shopify") || h.includes("x-shopify")) return "shopify";
  if (h.includes("shopify-section") || h.includes("shopify-payment-button")) return "shopify";

  // STORES
  if (h.includes("stores.jp") || h.includes("STORES") || h.includes("stl.stores")) return "stores";

  // Header hints（あれば）
  const sp = headers?.get?.("server") || "";
  if (String(sp).toLowerCase().includes("shopify")) return "shopify";

  return "unknown";
}

// ==============================
// Signals (main + policy pages)
// ==============================
function hasAny(text, patterns) {
  return patterns.some((re) => re.test(text));
}

function pickSnippets(html, patterns, max = 2) {
  const out = [];
  for (const re of patterns) {
    const m = html.match(re);
    if (m && m[0]) {
      const snip = m[0].trim().replace(/\s+/g, " ");
      out.push(snip.length > 160 ? snip.slice(0, 160) + "…" : snip);
    }
    if (out.length >= max) break;
  }
  return out;
}

const PAT = {
  jpUi: [/日本語/i, /配送/i, /税込/i, /カート/i, /購入/i],
  jpy: [/¥/i, /jpy/i, /円/i],
  tokusho: [/特定商取引法/i, /特商法/i, /commercial transactions/i, /特定商取引/i],
  address: [
    /〒\s?\d{3}-?\d{4}/i,
    /(東京都|北海道|大阪府|京都府|神奈川県|埼玉県|千葉県|愛知県|福岡県|沖縄県)/i,
  ],
  phone: [/(0\d{1,4}-\d{1,4}-\d{3,4})/i, /電話番号/i],
  email: [/[@＠][a-z0-9._-]+\.[a-z]{2,}/i, /メール/i, /email/i],
  daysDelivery: [/(\d{1,2})\s?(営業日|日)以内/i, /即日発送/i, /翌日発送/i],
  longDelivery: [/(\d{1,2})\s?(週間|週)/i, /(\d{1,2})\s?(ヶ月|か月|月)/i, /2週間以上/i],
  overseasShip: [/海外発送/i, /海外倉庫/i, /海外から発送/i, /international shipping/i],
  returnInfo: [/返品/i, /キャンセル/i, /返金/i, /交換/i],
  overseasReturn: [/海外返品/i, /返送料.*負担/i, /international return/i],
};

function analyzeSignals(html) {
  const signals = {
    isJapaneseUi: hasAny(html, PAT.jpUi),
    isJpy: hasAny(html, PAT.jpy),
    hasTokusho: hasAny(html, PAT.tokusho),
    hasAddress: hasAny(html, PAT.address),
    hasPhone: hasAny(html, PAT.phone),
    hasEmail: hasAny(html, PAT.email),
    hasDaysDelivery: hasAny(html, PAT.daysDelivery),
    hasLongDelivery: hasAny(html, PAT.longDelivery),
    hasOverseasShip: hasAny(html, PAT.overseasShip),
    hasReturnInfo: hasAny(html, PAT.returnInfo),
    hasOverseasReturn: hasAny(html, PAT.overseasReturn),
  };

  const snippets = {
    ui: [...pickSnippets(html, PAT.tokusho, 1), ...pickSnippets(html, PAT.jpy, 1)].slice(0, 2),
    ship: [
      ...pickSnippets(html, PAT.overseasShip, 1),
      ...pickSnippets(html, PAT.longDelivery, 1),
      ...pickSnippets(html, PAT.daysDelivery, 1),
    ].slice(0, 2),
    ret: [...pickSnippets(html, PAT.returnInfo, 1), ...pickSnippets(html, PAT.overseasReturn, 1)].slice(0, 2),
    contact: [
      ...pickSnippets(html, PAT.address, 1),
      ...pickSnippets(html, PAT.phone, 1),
      ...pickSnippets(html, PAT.email, 1),
    ].slice(0, 3),
  };

  return { signals, snippets };
}

// ==============================
// Find policy links (tokusho / shipping / returns)
// ==============================
function extractLinks(baseUrl, html) {
  const links = new Set();
  const re = /<a\s[^>]*href=["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const href = (m[1] || "").trim();
    if (!href) continue;
    if (href.startsWith("javascript:") || href.startsWith("mailto:") || href.startsWith("#")) continue;

    try {
      const abs = new URL(href, baseUrl).href;
      links.add(abs);
    } catch {
      // ignore
    }
  }
  return Array.from(links);
}

function pickPolicyCandidates(platform, baseUrl, html) {
  const candidates = [];
  const links = extractLinks(baseUrl, html);

  // keyword match from in-page links
  const kw = [
    /特定商取引/i,
    /特商法/i,
    /tokusho/i,
    /law/i,
    /返品/i,
    /キャンセル/i,
    /返金/i,
    /配送/i,
    /shipping/i,
    /refund/i,
    /policy/i,
  ];

  for (const l of links) {
    if (kw.some((re) => re.test(l))) candidates.push(l);
  }

  // platform common paths (fallback guesses)
  const u = new URL(baseUrl);
  const origin = u.origin;

  if (platform === "shopify") {
    candidates.push(
      `${origin}/policies/refund-policy`,
      `${origin}/policies/shipping-policy`,
      `${origin}/policies/terms-of-service`,
      `${origin}/policies/privacy-policy`
    );
  }

  if (platform === "base") {
    candidates.push(`${origin}/law`, `${origin}/shop/law`, `${origin}/about`, `${origin}/company`);
  }

  if (platform === "stores") {
    candidates.push(`${origin}/about`, `${origin}/terms`, `${origin}/privacy`, `${origin}/specified_commercial_transaction`);
  }

  // generic guesses
  candidates.push(`${origin}/law`, `${origin}/tokusho`, `${origin}/terms`, `${origin}/privacy`, `${origin}/about`);

  // unique & same-origin prefer
  const uniq = [];
  const seen = new Set();
  for (const c of candidates) {
    try {
      const cu = new URL(c);
      // 同一オリジン優先（別ドメイン飛びは後回し＝上限内で）
      const key = cu.href;
      if (seen.has(key)) continue;
      seen.add(key);
      uniq.push(key);
    } catch {
      // ignore
    }
  }

  // sort: same origin first
  uniq.sort((a, b) => {
    try {
      const A = new URL(a).origin === origin ? 0 : 1;
      const B = new URL(b).origin === origin ? 0 : 1;
      return A - B;
    } catch {
      return 0;
    }
  });

  return uniq.slice(0, MAX_FOLLOWUP_PAGES);
}

// ==============================
// Scoring + label decision
// ==============================
function scoreFromSignals(platform, s) {
  let score = 0;

  // platform known adds some confidence (but not "safe" guarantee)
  if (platform !== "unknown") score += 8;

  if (s.hasTokusho) score += 28;
  if (s.hasAddress) score += 18;
  if (s.hasPhone) score += 10;
  if (s.hasEmail) score += 6;

  if (s.hasReturnInfo) score += 10;

  // shipping
  if (s.hasDaysDelivery) score += 8;
  if (s.hasLongDelivery) score -= 10;
  if (s.hasOverseasShip) score -= 18;
  if (s.hasOverseasReturn) score -= 8;

  // language/currency hints
  if (s.isJapaneseUi) score += 4;
  if (s.isJpy) score += 4;

  // clamp
  if (score < 0) score = 0;
  if (score > 100) score = 100;
  return score;
}

function labelFromScoreAndSignals(score, s) {
  // “緑/黄/橙” の基準（実用寄りに）
  // 緑: スコア高 + 特商法 + 住所 + 返品 + 海外系強いシグナルなし
  const isGreen =
    score >= 70 && s.hasTokusho && s.hasAddress && s.hasReturnInfo && !s.hasOverseasShip && !s.hasLongDelivery;

  // 黄: 中間（海外/長納期の可能性がある、または情報はあるが揃いきってない）
  const isYellow = score >= 40 && score < 70;

  if (isGreen) {
    return {
      color: "green",
      labelText: "安心して購入しやすいEC",
      oneLine: "結論：国内向けの購入はスムーズになりやすい。通常用途なら安心して進めてOK。",
      delivery: "国内向け発送が前提の可能性が高い",
      eta: "1〜5営業日程度",
      ret: "一般的な条件で対応される可能性が高い",
      notes: ["最終的な配送日数・返品条件は購入前に公式表記で確認してください。"],
      good: ["日常利用", "急ぎの買い物"],
      caution: ["限定商品の在庫切れ", "セール時の在庫変動"],
    };
  }

  if (isYellow) {
    return {
      color: "yellow",
      labelText: "条件を確認してから買うのが安心なEC",
      oneLine: "結論：情報はあるが、納期や発送形態がブレやすい。購入前に条件確認を。",
      delivery: "国内/海外・取り寄せ等が混在する可能性",
      eta: "数日〜数週間（商品や在庫で変動）",
      ret: "条件確認推奨（ページで要確認）",
      notes: ["配送/返品/特商法のページを先にチェックすると事故りにくいです。"],
      good: ["種類の豊富さ重視", "時間に余裕がある購入"],
      caution: ["プレゼント用途（期日固定）", "イベント直前の購入"],
    };
  }

  return {
    color: "orange",
    labelText: "購入前に条件整理が必要なEC",
    oneLine: "結論：公開情報が取得できなかったため、購入前の自己確認が必須です。",
    delivery: "サーバーから公開情報を取得できないため、前提が読み取りにくい可能性",
    eta: "日〜週（情報不足のため幅を想定）",
    ret: "ページ確認推奨（事前確認が安心）",
    notes: ["公式ページ（配送/返品/特商法）を直接確認してください。"],
    good: ["時間に余裕がある購入"],
    caution: ["即決購入", "イベント用途"],
  };
}

// ==============================
// API: diagnose
// ==============================
app.post("/api/diagnose", async (req, res) => {
  const rawUrl = String(req.body?.url || "").trim();
  const u = safeParseUrl(rawUrl);
  if (!u) return res.status(400).json({ error: "invalid_url" });

  // 1) fetch main page
  const main = await fetchHtml(u.href, true);

  // 取得できないケース（BASE/Shopifyでも Cloudflare 等で弾かれることは普通にある）
  if (!main.ok) {
    const label = labelFromScoreAndSignals(0, {
      hasTokusho: false,
      hasAddress: false,
      hasPhone: false,
      hasEmail: false,
      hasReturnInfo: false,
      hasDaysDelivery: false,
      hasLongDelivery: false,
      hasOverseasShip: false,
      hasOverseasReturn: false,
      isJapaneseUi: false,
      isJpy: false,
    });

    return res.json({
      url: u.href,
      platform: "unknown",
      score: 0,
      ...label,
      delivery: label.delivery,
      eta: label.eta,
      return: label.ret,
      evidence: {
        ui: [`ドメイン：${u.hostname}`, `※取得不可：${main.reason}`],
        ship: [],
        ret: [],
        urlsChecked: [u.href],
        snippets: { ui: ["（抜粋なし：取得不可）"], ship: ["（抜粋なし）"], ret: ["（抜粋なし）"], contact: [] },
      },
    });
  }

  const platform = detectPlatform({
    html: main.html,
    headers: main.headers,
    finalUrl: main.finalUrl,
  });

  // 2) analyze main signals
  const mainA = analyzeSignals(main.html);
  let mergedSignals = { ...mainA.signals };
  let mergedSnippets = { ...mainA.snippets };

  const urlsChecked = [main.finalUrl || u.href];

  // 3) find & crawl policy pages (tokusho/returns/shipping)
  const candidates = pickPolicyCandidates(platform, main.finalUrl || u.href, main.html);

  for (const link of candidates) {
    // already checked
    if (urlsChecked.includes(link)) continue;

    const sub = await fetchHtml(link, false);
    if (!sub.ok) continue;

    urlsChecked.push(sub.finalUrl || link);

    const subA = analyzeSignals(sub.html);

    // merge signals (OR)
    for (const k of Object.keys(mergedSignals)) {
      mergedSignals[k] = mergedSignals[k] || subA.signals[k];
    }

    // merge snippets (keep a few)
    mergedSnippets.ui = Array.from(new Set([...(mergedSnippets.ui || []), ...(subA.snippets.ui || [])])).slice(0, 3);
    mergedSnippets.ship = Array.from(new Set([...(mergedSnippets.ship || []), ...(subA.snippets.ship || [])])).slice(
      0,
      3
    );
    mergedSnippets.ret = Array.from(new Set([...(mergedSnippets.ret || []), ...(subA.snippets.ret || [])])).slice(0, 3);
    mergedSnippets.contact = Array.from(
      new Set([...(mergedSnippets.contact || []), ...(subA.snippets.contact || [])])
    ).slice(0, 3);

    // enough confidence? stop early
    if (mergedSignals.hasTokusho && mergedSignals.hasAddress && mergedSignals.hasReturnInfo) break;
  }

  // 4) score & label
  const score = scoreFromSignals(platform, mergedSignals);
  const label = labelFromScoreAndSignals(score, mergedSignals);

  // 5) evidence building
  const evidence = {
    ui: [`ドメイン：${new URL(main.finalUrl || u.href).hostname}`, `プラットフォーム推定：${platform}`, `スコア：${score}/100`],
    ship: [],
    ret: [],
    urlsChecked,
    snippets: mergedSnippets,
  };

  if (mergedSignals.hasTokusho) evidence.ret.push("特商法ページらしき記載あり");
  if (mergedSignals.hasAddress) evidence.ret.push("住所らしき記載あり");
  if (mergedSignals.hasPhone) evidence.ret.push("電話番号らしき記載あり");
  if (mergedSignals.hasEmail) evidence.ret.push("メールアドレスらしき記載あり");
  if (mergedSignals.hasReturnInfo) evidence.ret.push("返品/キャンセルらしき記載あり");

  if (mergedSignals.hasDaysDelivery) evidence.ship.push("日数ベースの配送表現あり");
  if (mergedSignals.hasLongDelivery) evidence.ship.push("週〜月の配送表現あり");
  if (mergedSignals.hasOverseasShip) evidence.ship.push("海外発送/海外倉庫らしき表現あり");

  // 6) response
  return res.json({
    url: main.finalUrl || u.href,
    platform,
    score,
    labelText: label.labelText,
    color: label.color,
    oneLine: label.oneLine,
    delivery: label.delivery,
    eta: label.eta,
    return: label.ret,
    notes: label.notes,
    good: label.good,
    caution: label.caution,
    evidence,
  });
});

// ==============================
// SPA / fallback routing
// ==============================
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Labelly MVP server running on http://localhost:${PORT}`);
});
