import express from "express";
import path from "path";

const app = express();
const PORT = process.env.PORT || 3000;

// ==============================
// Basic settings
// ==============================
app.use(express.json({ limit: "200kb" }));
app.use(express.static("public"));

// ==============================
// Safety settings
// ==============================
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const FETCH_TIMEOUT_MS = 10000;
const MAX_HTML_BYTES = 700_000;

// ==============================
// Utils
// ==============================
function safeParseUrl(raw) {
  try {
    const u = new URL(raw);
    if (!ALLOWED_PROTOCOLS.has(u.protocol)) return null;
    return u;
  } catch {
    return null;
  }
}

function hasAny(text, patterns) {
  return patterns.some((re) => re.test(text));
}

// ==============================
// Fetch HTML
// ==============================
async function fetchHtml(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "Labelly/1.0" }
    });

    if (!res.ok) return null;

    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("text/html")) return null;

    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_HTML_BYTES) return null;

    return new TextDecoder("utf-8").decode(buf);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ==============================
// Analyze signals
// ==============================
function analyze(html) {
  return {
    jpUi: hasAny(html, [/日本語/i, /税込/i, /カート/i, /購入/i]),
    jpy: hasAny(html, [/¥/i, /円/i, /JPY/i]),
    tokusho: hasAny(html, [/特定商取引/i]),
    overseas: hasAny(html, [/海外/i, /international/i]),
    longDelivery: hasAny(html, [/週/i, /ヶ月/i, /か月/i])
  };
}

// ==============================
// Diagnose logic (A-1 + A-1.5)
// ==============================
function diagnose(signals) {

  // 🟢 GREEN
  if (signals.jpUi && signals.tokusho && !signals.overseas) {
    return {
      color: "green",
      labelText: "🟢 安心して購入しやすいEC",
      summary:
        "結論：国内向けの購入はスムーズになりやすい。通常用途なら安心して進めてOK。",
      delivery: "国内向け発送が前提の可能性が高い",
      eta: "1〜5営業日程度",
      return: "一般的な条件で対応される可能性が高い",
      notes: [
        "□ 配送日数の最終確認",
        "□ セール時の在庫変動に注意"
      ],
      good: [
        "日常利用",
        "急ぎの買い物"
      ],
      caution: [
        "限定商品の在庫切れ"
      ]
    };
  }

  // 🟡 YELLOW
  if (signals.jpUi && signals.jpy && (signals.overseas || signals.longDelivery)) {
    return {
      color: "yellow",
      labelText: "🟡 買えるが、事前確認がおすすめなEC",
      summary:
        "結論：急がない買い物ならOK。イベント・贈り物用途は配送と返品条件だけ先に確認。",
      delivery:
        "国内向け表示はありますが、海外発送を含む可能性があります",
      eta:
        "約2〜6週間（商品・在庫状況により変動）",
      return:
        "条件次第で手続きが煩雑になる可能性があります",
      notes: [
        "□ 配送元（国内 / 海外）を確認",
        "□ 到着までの目安日数を確認",
        "□ 返品可否と送料負担を事前確認"
      ],
      good: [
        "到着まで多少待てる",
        "価格やデザインの選択肢を重視したい"
      ],
      caution: [
        "誕生日・イベントなど到着日が決まっている",
        "返品前提で購入を考えている"
      ]
    };
  }

  // 🟠 ORANGE
  return {
    color: "orange",
    labelText: "🟠 購入前に条件整理が必要なEC",
    summary:
      "結論：購入前に配送元・納期・返品条件を整理してから判断するのがおすすめ。",
    delivery:
      "公式ページに情報はあるかもしれませんが、初見では把握しづらい構成の可能性があります",
    eta:
      "日〜週（情報不足のため幅を想定）",
    return:
      "ページ確認推奨（事前確認が安心）",
    notes: [
      "□ 配送情報ページを確認",
      "□ 特定商取引法表記を確認",
      "□ 返品条件を必ず確認"
    ],
    good: [
      "購入前にページを確認できる",
      "急ぎではない買い物"
    ],
    caution: [
      "納期が固定の用途",
      "返品が前提の購入"
    ]
  };
}

// ==============================
// API
// ==============================
app.post("/api/diagnose", async (req, res) => {
  const rawUrl = (req.body?.url || "").trim();
  const u = safeParseUrl(rawUrl);
  if (!u) return res.status(400).json({ error: "invalid_url" });

  const html = await fetchHtml(u.href);

  if (!html) {
    return res.json({
      color: "orange",
      labelText: "🟠 購入前に条件整理が必要なEC",
      summary:
        "結論：公開情報が取得できなかったため、購入前の自己確認が必須です。",
      delivery:
        "サーバーから公開情報を取得できないため、前提が読み取りにくい可能性",
      eta:
        "日〜週（情報不足のため幅を想定）",
      return:
        "ページ確認推奨（事前確認が安心）",
      notes: [
        "□ 公式ページ（配送 / 返品 / 特商法）を直接確認してください"
      ],
      good: [
        "時間に余裕がある購入"
      ],
      caution: [
        "即決購入",
        "イベント用途"
      ]
    });
  }

  const signals = analyze(html);
  const result = diagnose(signals);
  res.json(result);
});

// ==============================
// Static routing (Render対策)
// ==============================
app.get("/", (req, res) => {
  res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

// ==============================
// Start server
// ==============================
app.listen(PORT, () => {
  console.log(`Labelly running on http://localhost:${PORT}`);
});
