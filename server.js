import express from "express";
import iconv from "iconv-lite";
import rateLimit from "express-rate-limit";
import dns from "node:dns/promises";
import net from "node:net";

const app = express();
const PORT = process.env.PORT || 3000;

// ==============================
// Settings
// ==============================
app.use(express.json({ limit: "200kb" }));
app.use(express.static("public", { extensions: ["html"] }));

// Rate limit（雑に守るだけでも効果大）
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000, // 1分
    max: 30, // 1分あたり最大30回（MVP）
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// ==============================
// Limits / Security (MVP hardening)
// ==============================
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const ALLOWED_PORTS = new Set(["", "80", "443"]); // 明示ポートは基本拒否（必要なら増やす）
const MAX_HTML_BYTES = 1_200_000; // 1.2MB
const FETCH_TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 5;

// SSRF: ブロックするホスト名（ドメインリバインドやローカル参照をざっくり防ぐ）
const BLOCKED_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /^localhost\./i,
  /\.local$/i,
  /\.internal$/i,
  /\.intra$/i,
];

// ==============================
// Utilities
// ==============================
function safeParseUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (!ALLOWED_PROTOCOLS.has(u.protocol)) return null;
  if (!ALLOWED_PORTS.has(u.port || "")) return null;
  return u;
}

function parseCharset(contentType) {
  const m = /charset\s*=\s*([^\s;]+)/i.exec(contentType || "");
  return (m?.[1] || "utf-8").toLowerCase();
}

function hasAny(text, patterns) {
  return patterns.some((re) => re.test(text));
}

function pickSnippets(html, patterns, max = 2) {
  const out = [];
  for (const re of patterns) {
    const m = html.match(re);
    if (m && m[0]) {
      const snip = m[0].trim().replace(/\s+/g, " ");
      out.push(snip.length > 140 ? snip.slice(0, 140) + "…" : snip);
    }
    if (out.length >= max) break;
  }
  return out;
}

function isBlockedHostname(hostname) {
  const h = (hostname || "").toLowerCase();
  if (!h) return true;
  if (BLOCKED_HOSTNAME_PATTERNS.some((re) => re.test(h))) return true;
  // 直IP指定（v4/v6）をブロック（DNSチェック前に落とす）
  if (net.isIP(h) !== 0) return true;
  return false;
}

// プライベート/ローカル/リンクローカル/予約済みをブロック（MVP）
function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const parts = ip.split(".").map((n) => Number(n));
    const [a, b] = parts;

    // 0.0.0.0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16
    if (a === 0) return true;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;

    // 100.64/10 (CGNAT)
    if (a === 100 && b >= 64 && b <= 127) return true;

    return false;
  }

  if (v === 6) {
    const s = ip.toLowerCase();
    // ::1 loopback, fc00::/7 ULA, fe80::/10 link-local
    if (s === "::1") return true;
    if (s.startsWith("fc") || s.startsWith("fd")) return true;
    if (s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb"))
      return true;
    return false;
  }

  return true; // 不明は拒否
}

async function assertPublicHost(urlObj) {
  const hostname = urlObj.hostname;

  if (isBlockedHostname(hostname)) {
    throw new Error("blocked_hostname");
  }

  // DNS解決して、返ってきたIPが全部パブリックか確認（DNS rebinding対策の最低ライン）
  const results = await dns.lookup(hostname, { all: true, verbatim: true });

  if (!results || results.length === 0) throw new Error("dns_failed");

  for (const r of results) {
    if (!r.address || isPrivateIp(r.address)) {
      throw new Error("blocked_ip");
    }
  }
}

// ==============================
// Fetch HTML (manual redirect with re-validation)
// ==============================
async function fetchHtmlWithValidation(urlObj) {
  // URL毎にSSRFチェック（リダイレクト先でも再実施する）
  await assertPublicHost(urlObj);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(urlObj.href, {
      redirect: "manual", // 手動で追う
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
      },
    });

    const ct = res.headers.get("content-type") || "";
    console.log("[fetch]", urlObj.href, res.status, ct);

    // Redirect
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return { html: null, finalUrl: urlObj.href, status: res.status };

      const next = new URL(loc, urlObj); // 相対対応
      return { redirectTo: next, finalUrl: next.href, status: res.status };
    }

    if (!res.ok) return { html: null, finalUrl: urlObj.href, status: res.status };

    if (!ct.toLowerCase().includes("text/html")) {
      return { html: null, finalUrl: urlObj.href, status: res.status };
    }

    const buf = await res.arrayBuffer();
    console.log("[size]", buf.byteLength);

    if (buf.byteLength > MAX_HTML_BYTES) {
      return { html: null, finalUrl: urlObj.href, status: 413 };
    }

    const charset = parseCharset(ct);
    const buffer = Buffer.from(buf);

    let html;
    if (charset.includes("euc-jp")) html = iconv.decode(buffer, "euc-jp");
    else if (charset.includes("shift_jis") || charset.includes("sjis")) html = iconv.decode(buffer, "shift_jis");
    else html = buffer.toString("utf8");

    return { html, finalUrl: urlObj.href, status: res.status };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchHtml(urlStr) {
  let u = new URL(urlStr);
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const out = await fetchHtmlWithValidation(u);
    if (out.redirectTo) {
      u = out.redirectTo;
      continue;
    }
    return out.html || null;
  }
  return null;
}

// ==============================
// Related pages discovery (URL + anchor text)
// ==============================
function extractCandidateLinksWithText(html, baseUrl) {
  const base = new URL(baseUrl);
  const found = [];

  // <a ... href="...">TEXT</a> をざっくり拾う（MVP）
  const reA = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = reA.exec(html)) !== null) {
    const href = m[1];
    const text = (m[2] || "").replace(/<[^>]+>/g, "").trim(); // 内部タグ除去（簡易）

    if (!href || href.startsWith("#") || href.startsWith("javascript:")) continue;

    try {
      const u = new URL(href, base);
      if (u.origin !== base.origin) continue;
      found.push({ url: u.href, text });
    } catch { }
  }

  // キーワード（URLとテキスト両方でスコアリング）
  const keywords = [
    { type: "tokusho", keys: ["特定商取引", "特商法", "law", "tokusho", "commercial"] },
    { type: "shipping", keys: ["配送", "送料", "お届け", "発送", "shipping", "delivery"] },
    { type: "return", keys: ["返品", "返金", "交換", "キャンセル", "return", "refund", "cancel"] },
    { type: "company", keys: ["会社概要", "運営", "法人", "所在地", "about", "company"] },
  ];

  const map = new Map(); // url -> best
  for (const it of found) {
    const u = it.url;
    const sUrl = u.toLowerCase();
    const sText = (it.text || "").toLowerCase();

    let best = map.get(u) || { url: u, score: 0, type: null };

    for (const k of keywords) {
      for (const key of k.keys) {
        const kk = key.toLowerCase();
        if (sUrl.includes(kk)) {
          best.score += 2;
          best.type = best.type || k.type;
        }
        if (sText.includes(kk)) {
          best.score += 3; // テキスト一致の方を強く
          best.type = best.type || k.type;
        }
      }
    }

    map.set(u, best);
  }

  // スコア順に最大3つ
  const ranked = [...map.values()]
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

  return ranked;
}

async function fetchRelatedPagesAndCombine(topHtml, baseUrl) {
  const ranked = extractCandidateLinksWithText(topHtml, baseUrl);
  const pages = ranked.map((r) => ({ type: r.type || "unknown", url: r.url }));

  if (pages.length === 0) {
    return { combinedHtml: topHtml, pagesUsed: [] };
  }

  console.log("[related candidates]", pages.map((p) => p.url));

  let combined = topHtml;
  const used = [];

  for (const p of pages) {
    const h = await fetchHtml(p.url);
    if (h) {
      combined += "\n\n<!-- related -->\n\n" + h;
      used.push(p);
      console.log("[related fetched]", p.url);
    } else {
      console.log("[related failed]", p.url);
    }
  }

  return { combinedHtml: combined, pagesUsed: used };
}

// ==============================
// Analyze signals
// ==============================
function analyzeHtmlSignals(html) {
  const jpUiPatterns = [/日本語/i, /税込/i, /カート/i, /購入/i, /ご注文/i, /お届け/i, /配送/i];
  const jpyPatterns = [/¥/i, /円/i, /jpy/i];

  const tokushoPatterns = [/特定商取引法/i, /特商法/i];
  const jpAddressPatterns = [
    /〒\s?\d{3}-?\d{4}/i,
    /(東京都|北海道|大阪府|京都府|神奈川県|埼玉県|千葉県|愛知県|福岡県)/i,
  ];

  const daysDeliveryPatterns = [
    /(\d{1,2})\s?(営業日|日)以内/i,
    /(\d{1,2})\s?(営業日|日)で(発送|出荷)/i,
    /即日発送/i,
    /当日発送/i,
    /翌日発送/i,
    /最短\s?\d{1,2}\s?(日|営業日)/i,
    /2〜3日/i,
    /3〜5日/i,
  ];
  const longDeliveryPatterns = [
    /(\d{1,2})\s?(週間|週)/i,
    /(\d{1,2})\s?(ヶ月|か月|月)/i,
    /2週間/i,
    /予約商品/i,
    /入荷次第/i,
  ];
  const overseasShipPatterns = [
    /海外発送/i,
    /海外倉庫/i,
    /海外から発送/i,
    /international shipping/i,
    /ships from overseas/i,
  ];

  const returnInfoPatterns = [/返品/i, /返金/i, /交換/i, /キャンセル/i];
  const overseasReturnPatterns = [/海外返品/i, /返送料.*負担/i, /international return/i];

  const signals = {
    isJapaneseUi: hasAny(html, jpUiPatterns),
    isJpy: hasAny(html, jpyPatterns),
    hasTokusho: hasAny(html, tokushoPatterns),
    hasJpAddress: hasAny(html, jpAddressPatterns),
    hasDaysDelivery: hasAny(html, daysDeliveryPatterns),
    hasLongDelivery: hasAny(html, longDeliveryPatterns),
    hasOverseasShip: hasAny(html, overseasShipPatterns),
    hasReturnInfo: hasAny(html, returnInfoPatterns),
    hasOverseasReturn: hasAny(html, overseasReturnPatterns),
  };

  const snippets = {
    ui: [
      ...pickSnippets(html, tokushoPatterns, 1),
      ...pickSnippets(html, jpyPatterns, 1),
    ].slice(0, 2),
    ship: [
      ...pickSnippets(html, overseasShipPatterns, 1),
      ...pickSnippets(html, longDeliveryPatterns, 1),
      ...pickSnippets(html, daysDeliveryPatterns, 1),
    ].slice(0, 2),
    ret: [
      ...pickSnippets(html, overseasReturnPatterns, 1),
      ...pickSnippets(html, returnInfoPatterns, 1),
    ].slice(0, 2),
  };

  return { signals, snippets };
}

// ==============================
// Score & Copy (刺さるコピー + 説明文)
// ==============================
function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function scoreFromSignals(s) {
  let score = 0;

  if (s.isJapaneseUi) score += 10;
  if (s.isJpy) score += 10;
  if (s.hasTokusho) score += 25;
  if (s.hasJpAddress) score += 20;
  if (s.hasReturnInfo) score += 15;
  if (s.hasDaysDelivery) score += 10;

  if (s.hasOverseasShip) score -= 20;
  if (s.hasLongDelivery) score -= 10;
  if (s.hasOverseasReturn) score -= 10;

  return clamp(score, 0, 100);
}

function buildExplanation(label, s) {
  // 断定を避けつつ、腹落ちする文章
  if (label === "yellow") {
    return [
      "このサイトは日本語表示・円表記が確認できる一方で、長めの納期表現や海外流通を示す記載が含まれる可能性があります。",
      "表示が日本向けでも、発送元や返品条件が海外基準の場合があるため、購入前に配送・返品ページの条件確認をおすすめします。",
    ].join(" ");
  }
  if (label === "green") {
    const parts = [];
    parts.push("このサイトでは特定商取引法の表記など、国内向け運営を示す要素が確認できました。");
    if (s.hasJpAddress) parts.push("日本国内の住所情報が確認できる可能性があります。");
    if (s.hasReturnInfo) parts.push("返品・キャンセル等の案内が見つかる可能性があります。");
    if (!s.hasDaysDelivery) parts.push("ただし納期表記は見つからない場合があるため、商品ページや配送ページでの確認をおすすめします。");
    return parts.join(" ");
  }
  return [
    "トップページや関連ページから、配送・返品など購入に重要な前提条件が十分に読み取れない可能性があります。",
    "購入前に「配送」「返品」「特定商取引法」ページの有無と内容確認をおすすめします。",
  ].join(" ");
}

// ==============================
// Diagnosis (SSRF hardened + improved copy)
// ==============================
function diagnoseFromSignals(urlObj, signals, snippets, pagesUsed) {
  const evidence = {
    ui: [`ドメイン：${urlObj.hostname}`],
    ship: [],
    ret: [],
    snippets,
    pages: pagesUsed || [], // 根拠ページURLを返す
  };

  if (signals.isJapaneseUi) evidence.ui.push("日本語UIの可能性");
  if (signals.isJpy) evidence.ui.push("円表記の可能性");

  if (signals.hasDaysDelivery) evidence.ship.push("短納期表現あり");
  if (signals.hasLongDelivery) evidence.ship.push("長納期・予約/入荷待ち表現あり");
  if (signals.hasOverseasShip) evidence.ship.push("海外発送の可能性");

  if (signals.hasTokusho) evidence.ret.push("特定商取引法表記あり");
  if (signals.hasJpAddress) evidence.ret.push("日本住所表記あり");
  if (signals.hasReturnInfo) evidence.ret.push("返品/キャンセル情報あり");
  if (signals.hasOverseasReturn) evidence.ret.push("海外返品条件あり");

  // ✅ ルール：🟡優先（海外/長納期の兆候があるとき）
  const isYellow =
    signals.isJapaneseUi &&
    signals.isJpy &&
    (signals.hasOverseasShip || signals.hasLongDelivery);

  // ✅ 🟢（国内寄り）：特商法 + (住所 or 返品) が揃えば納期未記載でも🟢寄り
  const isGreen =
    signals.isJapaneseUi &&
    signals.hasTokusho &&
    (signals.hasJpAddress || signals.hasReturnInfo) &&
    !signals.hasOverseasShip;

  const score = scoreFromSignals(signals);

  if (isYellow) {
    return {
      url: urlObj.href,
      labelText: "🟡 日本語表示だが、海外流通の可能性あり",
      subText: "表示は日本向けでも、配送や返品は海外基準の可能性があります。",
      color: "yellow",
      score,
      explanation: buildExplanation("yellow", signals),
      delivery: "届くまでに時間がかかる可能性があります",
      eta: "2週間〜6週間程度（幅あり）",
      return: "返品できない／送料が高額になる可能性があります（事前確認推奨）",
      notes: [
        "「発送元」「配送日数」「関税/手数料」などの表記を確認",
        "返品条件（返送料・可否）は事前確認がおすすめ",
      ],
      good: ["品揃え・デザイン重視", "納期に余裕がある購入"],
      caution: ["プレゼント用途（期日固定）", "イベント直前の購入"],
      evidence,
    };
  }

  if (isGreen) {
    return {
      url: urlObj.href,
      labelText: "🟢 国内向け運営が確認できる通販サイト",
      subText: "事業者情報・返品条件などが確認できる可能性があります。",
      color: "green",
      score,
      explanation: buildExplanation("green", signals),
      delivery: "国内向けの運営情報が見つかる可能性が高い",
      eta: signals.hasDaysDelivery
        ? "1〜5営業日程度（商品により変動）"
        : "納期表記が見つからないため、配送ページの確認推奨",
      return: "条件が明記されている可能性（購入前に要確認）",
      notes: ["取寄せ商品が混在する可能性があります", "納期は商品ごとに差がある場合があります"],
      good: ["安心感を重視する購入", "国内向け対応を重視する購入"],
      caution: ["在庫が動きやすい時期のサイズ選択"],
      evidence,
    };
  }

  return {
    url: urlObj.href,
    labelText: "🟠 購入前に条件確認をおすすめする通販サイト",
    subText: "配送・返品の前提がトップページから読み取りにくい状態です。",
    color: "orange",
    score,
    explanation: buildExplanation("orange", signals),
    delivery: "公開情報だけでは流通の前提が読み取りにくい可能性",
    eta: "日〜週（情報不足のため幅を想定）",
    return: "ページ確認推奨（条件差が大きい可能性）",
    notes: ["配送・返品ページの有無と内容を確認してください", "特定商取引法表記の場所を確認してください"],
    good: ["購入前にページを確認できるケース", "急ぎではない購入"],
    caution: ["納期が固定の用途", "返品が前提の購入"],
    evidence,
  };
}

// ==============================
// API
// ==============================
app.post("/api/diagnose", async (req, res) => {
  const rawUrl = (req.body?.url || "").trim();
  const u = safeParseUrl(rawUrl);
  if (!u) return res.status(400).json({ error: "invalid_url" });

  try {
    // まずトップページを取得（SSRFチェック内包）
    const topHtml = await fetchHtml(u.href);

    if (!topHtml) {
      return res.json({
        url: u.href,
        labelText: "🟠 購入前に条件確認をおすすめする通販サイト",
        subText: "公開情報を取得できず、前提が読み取りにくい状態です。",
        color: "orange",
        score: 0,
        explanation:
          "サーバーから公開情報を取得できないため、配送・返品など購入に重要な前提条件が判断しにくい可能性があります。購入前に公式ページで条件確認をおすすめします。",
        delivery: "サーバーから公開情報を取得できませんでした",
        eta: "不明",
        return: "不明",
        notes: ["サイト側の制限（ブロック/タイムアウト/サイズ超過）の可能性"],
        good: [],
        caution: [],
        evidence: {
          ui: [`ドメイン：${u.hostname}`, "※取得不可（ブロック/タイムアウト/サイズ超過等）"],
          ship: [],
          ret: [],
          snippets: { ui: [], ship: [], ret: [] },
          pages: [],
        },
      });
    }

    // 関連ページも最大3つ取得して解析（根拠URLも返す）
    const { combinedHtml, pagesUsed } = await fetchRelatedPagesAndCombine(topHtml, u.href);

    const { signals, snippets } = analyzeHtmlSignals(combinedHtml);
    console.log("[signals]", signals);

    const result = diagnoseFromSignals(u, signals, snippets, pagesUsed);
    result.evidence.ui.push("サーバー取得に成功（公開情報から推定）");

    return res.json(result);
  } catch (e) {
    // SSRFブロック等はこちらに来る
    console.log("[api error]", e?.message || e);
    return res.status(400).json({ error: "blocked_or_failed" });
  }
});

app.listen(PORT, () => {
  console.log(`Labelly MVP server running on http://localhost:${PORT}`);
});
