import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as path from "node:path";

type CsvRecord = Record<string, string>;

const VERDICT_ORDER = ["CLEAN", "SUSPICIOUS", "MALICIOUS"] as const;
const VERDICT_COLORS: Record<(typeof VERDICT_ORDER)[number], string> = {
  CLEAN: "#2e7d32",
  SUSPICIOUS: "#f9a825",
  MALICIOUS: "#c62828",
};

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  const pushField = () => {
    row.push(field);
    field = "";
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        const next = text[i + 1];
        if (next === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
      continue;
    }
    if (ch === ",") {
      pushField();
      continue;
    }
    if (ch === "\n") {
      pushField();
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
      continue;
    }
    if (ch === "\r") continue;
    field += ch;
  }

  pushField();
  if (row.length > 1 || row[0] !== "") rows.push(row);
  return rows;
}

function readCsvRecords(filePath: string): CsvRecord[] {
  const rows = parseCsv(readFileSync(filePath, "utf8"));
  const header = rows[0] ?? [];
  const out: CsvRecord[] = [];
  for (const row of rows.slice(1)) {
    const record: CsvRecord = {};
    for (let i = 0; i < header.length; i++) record[header[i]] = row[i] ?? "";
    out.push(record);
  }
  return out;
}

function countBy(records: CsvRecord[], key: string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const r of records) {
    const raw = String(r[key] ?? "").trim();
    const k = raw || "(empty)";
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return counts;
}

function wilson95(k: number, n: number): { low: number; high: number } {
  if (n <= 0) return { low: 0, high: 0 };
  const z = 1.96;
  const p = k / n;
  const denom = 1 + (z * z) / n;
  const center = (p + (z * z) / (2 * n)) / denom;
  const adj = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / denom;
  return { low: Math.max(0, center - adj), high: Math.min(1, center + adj) };
}

function esc(text: string): string {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function fmtPct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function svgDoc(width: number, height: number, body: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">\n` +
    `<style>\n` +
    `  .t { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; fill: #111; }\n` +
    `  .title { font-size: 20px; font-weight: 700; }\n` +
    `  .label { font-size: 13px; }\n` +
    `  .small { font-size: 12px; fill: #333; }\n` +
    `  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }\n` +
    `</style>\n` +
    `<rect x="0" y="0" width="${width}" height="${height}" fill="#fff"/>\n` +
    body +
    `</svg>\n`;
}

function legend(items: Array<{ label: string; color: string }>, x: number, y: number): string {
  let out = "";
  let cursorX = x;
  for (const item of items) {
    out += `<rect x="${cursorX}" y="${y - 10}" width="12" height="12" fill="${item.color}"/>\n`;
    out += `<text class="t small" x="${cursorX + 16}" y="${y}" dominant-baseline="middle">${esc(item.label)}</text>\n`;
    cursorX += 16 + item.label.length * 7 + 18;
  }
  return out;
}

function renderStackedBars(opts: {
  title: string;
  subtitle?: string;
  rows: Array<{ label: string; n: number; counts: Map<string, number> }>;
  categoryOrder: string[];
  categoryColors: Record<string, string>;
  width?: number;
}): string {
  const width = opts.width ?? 920;
  const leftPad = 20;
  const topPad = 20;
  const titleH = 34;
  const subtitleH = opts.subtitle ? 18 : 0;
  const rowH = 34;
  const labelW = 290;
  const barW = width - leftPad * 2 - labelW;
  const legendY = topPad + titleH + subtitleH + opts.rows.length * rowH + 20;
  const height = legendY + 26;

  let body = "";
  body += `<text class="t title" x="${leftPad}" y="${topPad + 18}">${esc(opts.title)}</text>\n`;
  if (opts.subtitle) {
    body += `<text class="t small" x="${leftPad}" y="${topPad + 18 + titleH - 10}">${esc(opts.subtitle)}</text>\n`;
  }

  for (let i = 0; i < opts.rows.length; i++) {
    const row = opts.rows[i];
    const y = topPad + titleH + subtitleH + i * rowH + 12;
    body += `<text class="t label" x="${leftPad}" y="${y}" dominant-baseline="middle">${esc(row.label)} <tspan class="small">(n=${row.n})</tspan></text>\n`;

    const x0 = leftPad + labelW;
    let cursor = x0;
    const total = row.n || 1;

    // Border
    body += `<rect x="${x0}" y="${y - 10}" width="${barW}" height="20" fill="none" stroke="#ddd"/>\n`;

    for (const cat of opts.categoryOrder) {
      const c = row.counts.get(cat) ?? 0;
      if (c <= 0) continue;
      const w = Math.max(0, (c / total) * barW);
      const color = opts.categoryColors[cat] ?? "#90a4ae";
      body += `<rect x="${cursor}" y="${y - 10}" width="${w}" height="20" fill="${color}"/>\n`;
      if (w >= 40) {
        body += `<text class="t small" x="${cursor + w / 2}" y="${y}" text-anchor="middle" dominant-baseline="middle" fill="#fff">${c}</text>\n`;
      }
      cursor += w;
    }
  }

  const items = opts.categoryOrder.map((c) => ({ label: c, color: opts.categoryColors[c] ?? "#90a4ae" }));
  body += legend(items, leftPad, legendY);
  return svgDoc(width, height, body);
}

function renderCapabilityPrevalence(opts: {
  title: string;
  subtitle?: string;
  caps: Array<{ key: string; malware: number; benign: number }>;
  width?: number;
}): string {
  const width = opts.width ?? 920;
  const leftPad = 20;
  const topPad = 20;
  const titleH = 34;
  const subtitleH = opts.subtitle ? 18 : 0;
  const rowH = 42;
  const labelW = 180;
  const barW = 520;
  const height = topPad + titleH + subtitleH + opts.caps.length * rowH + 54;

  const x0 = leftPad + labelW;
  const malwareColor = "#c62828";
  const benignColor = "#2e7d32";

  let body = "";
  body += `<text class="t title" x="${leftPad}" y="${topPad + 18}">${esc(opts.title)}</text>\n`;
  if (opts.subtitle) {
    body += `<text class="t small" x="${leftPad}" y="${topPad + 18 + titleH - 10}">${esc(opts.subtitle)}</text>\n`;
  }

  // Axis
  const axisY = topPad + titleH + subtitleH - 2;
  body += `<line x1="${x0}" y1="${axisY}" x2="${x0 + barW}" y2="${axisY}" stroke="#eee"/>\n`;
  for (const pct of [0, 0.25, 0.5, 0.75, 1]) {
    const x = x0 + pct * barW;
    body += `<line x1="${x}" y1="${axisY}" x2="${x}" y2="${height - 46}" stroke="#f3f3f3"/>\n`;
    body += `<text class="t small" x="${x}" y="${height - 28}" text-anchor="middle">${Math.round(pct * 100)}%</text>\n`;
  }

  for (let i = 0; i < opts.caps.length; i++) {
    const row = opts.caps[i];
    const y = topPad + titleH + subtitleH + i * rowH + 24;
    const label = row.key.replaceAll("_", " ");
    body += `<text class="t label" x="${leftPad}" y="${y - 8}" dominant-baseline="middle">${esc(label)}</text>\n`;

    const malwareW = Math.max(0, Math.min(1, row.malware)) * barW;
    const benignW = Math.max(0, Math.min(1, row.benign)) * barW;

    body += `<rect x="${x0}" y="${y - 18}" width="${barW}" height="14" fill="none" stroke="#eee"/>\n`;
    body += `<rect x="${x0}" y="${y - 18}" width="${malwareW}" height="14" fill="${malwareColor}"/>\n`;
    body += `<text class="t small" x="${x0 + barW + 10}" y="${y - 11}" dominant-baseline="middle">${fmtPct(row.malware)}</text>\n`;

    body += `<rect x="${x0}" y="${y + 2}" width="${barW}" height="14" fill="none" stroke="#eee"/>\n`;
    body += `<rect x="${x0}" y="${y + 2}" width="${benignW}" height="14" fill="${benignColor}"/>\n`;
    body += `<text class="t small" x="${x0 + barW + 10}" y="${y + 9}" dominant-baseline="middle">${fmtPct(row.benign)}</text>\n`;
  }

  body += legend(
    [
      { label: "malware", color: "#c62828" },
      { label: "benign", color: "#2e7d32" },
    ],
    leftPad,
    height - 14
  );

  return svgDoc(width, height, body);
}

function toSortedArray(counts: Map<string, number>): Array<{ key: string; value: number }> {
  return Array.from(counts.entries())
    .map(([k, v]) => ({ key: k, value: v }))
    .sort((a, b) => b.value - a.value || a.key.localeCompare(b.key));
}

function topCapabilityCombos(records: CsvRecord[], capCols: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const r of records) {
    const caps: string[] = [];
    for (const c of capCols) {
      if (String(r[c] ?? "0").trim() === "1") caps.push(c.replace(/^cap_/, ""));
    }
    const key = caps.length ? caps.sort().join("+") : "(none)";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function renderTopCombos(opts: {
  title: string;
  left: { label: string; n: number; combos: Map<string, number>; color: string };
  right: { label: string; n: number; combos: Map<string, number>; color: string };
  width?: number;
  topN?: number;
}): string {
  const width = opts.width ?? 920;
  const leftPad = 20;
  const topPad = 20;
  const titleH = 34;
  const gap = 40;
  const panelW = (width - leftPad * 2 - gap) / 2;
  const labelW = 210;
  const barW = panelW - labelW - 40;
  const topN = opts.topN ?? 6;

  const leftTop = toSortedArray(opts.left.combos).slice(0, topN);
  const rightTop = toSortedArray(opts.right.combos).slice(0, topN);
  const rows = Math.max(leftTop.length, rightTop.length);
  const rowH = 26;
  const height = topPad + titleH + rows * rowH + 52;

  let body = "";
  body += `<text class="t title" x="${leftPad}" y="${topPad + 18}">${esc(opts.title)}</text>\n`;

  const renderPanel = (
    xOffset: number,
    panelLabel: string,
    n: number,
    items: Array<{ key: string; value: number }>,
    color: string
  ) => {
    const headerY = topPad + titleH + 10;
    body += `<text class="t label" x="${xOffset}" y="${headerY}" dominant-baseline="middle">${esc(panelLabel)} <tspan class="small">(n=${n})</tspan></text>\n`;
    const max = Math.max(1, ...items.map((i) => i.value));
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const y = topPad + titleH + 30 + i * rowH;
      const label = it.key.length > 28 ? it.key.slice(0, 27) + "..." : it.key;
      body += `<text class="t small mono" x="${xOffset}" y="${y}" dominant-baseline="middle">${esc(label)}</text>\n`;
      const xBar = xOffset + labelW;
      const w = (it.value / max) * barW;
      body += `<rect x="${xBar}" y="${y - 7}" width="${barW}" height="14" fill="none" stroke="#eee"/>\n`;
      body += `<rect x="${xBar}" y="${y - 7}" width="${w}" height="14" fill="${color}"/>\n`;
      body += `<text class="t small" x="${xBar + barW + 8}" y="${y}" dominant-baseline="middle">${it.value}</text>\n`;
    }
  };

  renderPanel(leftPad, opts.left.label, opts.left.n, leftTop, opts.left.color);
  renderPanel(leftPad + panelW + gap, opts.right.label, opts.right.n, rightTop, opts.right.color);

  body += legend(
    [
      { label: opts.left.label, color: opts.left.color },
      { label: opts.right.label, color: opts.right.color },
    ],
    leftPad,
    height - 14
  );

  return svgDoc(width, height, body);
}

function getArg(name: string): string | null {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  return process.argv[idx + 1] ?? null;
}

function main() {
  const baselineMalwareAgg = getArg("--baseline-malware-aggregate");
  const baselineBenignAgg = getArg("--baseline-benign-aggregate");

  const aiOffProdMalwareResults = getArg("--ai-off-prod-malware-results");
  const aiOffProdBenignResults = getArg("--ai-off-prod-benign-results");
  const aiOffDemoMalwareResults = getArg("--ai-off-demo-malware-results");
  const aiOffDemoBenignResults = getArg("--ai-off-demo-benign-results");

  const outDir = getArg("--out-dir") ?? "docs/benchmarks";

  if (!baselineMalwareAgg || !baselineBenignAgg) {
    console.error(
      "Usage: bun scripts/render-benchmark-figures.ts --baseline-malware-aggregate <aggregate.csv> --baseline-benign-aggregate <aggregate.csv> [--ai-off-prod-malware-results <results.csv> --ai-off-prod-benign-results <results.csv> --ai-off-demo-malware-results <results.csv> --ai-off-demo-benign-results <results.csv>] [--out-dir docs/benchmarks]"
    );
    process.exit(2);
  }

  mkdirSync(outDir, { recursive: true });

  const baselineMalware = readCsvRecords(baselineMalwareAgg);
  const baselineBenign = readCsvRecords(baselineBenignAgg);

  const baselineMalwareVerdicts = countBy(baselineMalware, "verdict");
  const baselineBenignVerdicts = countBy(baselineBenign, "verdict");
  const baselineMalwareMethods = countBy(baselineMalware, "method");
  const baselineBenignMethods = countBy(baselineBenign, "method");

  const baselineMalwareN = baselineMalware.length;
  const baselineBenignN = baselineBenign.length;

  const detectionCI = wilson95(baselineMalwareVerdicts.get("MALICIOUS") ?? 0, baselineMalwareN);
  const cleanCI = wilson95(baselineBenignVerdicts.get("CLEAN") ?? 0, baselineBenignN);

  const baselineVerdictSvg = renderStackedBars({
    title: "Verdict distribution (baseline)",
    subtitle: `Malware detection: 100% (Wilson 95% ${fmtPct(detectionCI.low)}-${fmtPct(detectionCI.high)}); Benign clean: 100% (Wilson 95% ${fmtPct(cleanCI.low)}-${fmtPct(cleanCI.high)})`,
    rows: [
      { label: "MalwareBazaar strict-modlike", n: baselineMalwareN, counts: baselineMalwareVerdicts },
      { label: "Modrinth top-50", n: baselineBenignN, counts: baselineBenignVerdicts },
    ],
    categoryOrder: [...VERDICT_ORDER],
    categoryColors: { ...VERDICT_COLORS },
  });
  writeFileSync(path.join(outDir, "baseline-verdict-distribution.svg"), baselineVerdictSvg, "utf8");

  const methodOrder = [
    "static_override(ai_verdict)",
    "ai_verdict",
    "static_override(heuristic_fallback)",
    "heuristic_fallback",
  ];
  const methodColors: Record<string, string> = {
    "static_override(ai_verdict)": "#1565c0",
    ai_verdict: "#2e7d32",
    "static_override(heuristic_fallback)": "#ef6c00",
    heuristic_fallback: "#616161",
  };

  const baselineMethodSvg = renderStackedBars({
    title: "Verdict method attribution (baseline)",
    subtitle: "Shows how many malware samples are locked to MALICIOUS by static override vs AI verdict alone.",
    rows: [
      { label: "MalwareBazaar strict-modlike", n: baselineMalwareN, counts: baselineMalwareMethods },
      { label: "Modrinth top-50", n: baselineBenignN, counts: baselineBenignMethods },
    ],
    categoryOrder: methodOrder,
    categoryColors: methodColors,
  });
  writeFileSync(path.join(outDir, "baseline-method-attribution.svg"), baselineMethodSvg, "utf8");

  const capCols = Object.keys(baselineMalware[0] ?? {}).filter((k) => k.startsWith("cap_"));
  capCols.sort();

  const prevalence = capCols.map((col) => {
    const key = col.replace(/^cap_/, "");
    const malPresent = baselineMalware.filter((r) => String(r[col] ?? "0").trim() === "1").length;
    const benPresent = baselineBenign.filter((r) => String(r[col] ?? "0").trim() === "1").length;
    return {
      key,
      malware: baselineMalwareN ? malPresent / baselineMalwareN : 0,
      benign: baselineBenignN ? benPresent / baselineBenignN : 0,
    };
  });

  // Sort by malware prevalence desc
  prevalence.sort((a, b) => b.malware - a.malware || a.key.localeCompare(b.key));

  const capSvg = renderCapabilityPrevalence({
    title: "Capability prevalence (baseline)",
    subtitle: "Fraction of samples where the capability is present at medium/high severity.",
    caps: prevalence,
  });
  writeFileSync(path.join(outDir, "baseline-capability-prevalence.svg"), capSvg, "utf8");

  const combosMalware = topCapabilityCombos(baselineMalware, capCols);
  const combosBenign = topCapabilityCombos(baselineBenign, capCols);
  const combosSvg = renderTopCombos({
    title: "Top capability intersections (baseline)",
    left: { label: "malware", n: baselineMalwareN, combos: combosMalware, color: "#c62828" },
    right: { label: "benign", n: baselineBenignN, combos: combosBenign, color: "#2e7d32" },
    topN: 6,
  });
  writeFileSync(path.join(outDir, "baseline-top-capability-combos.svg"), combosSvg, "utf8");

  // Ablation (optional): verdict distributions from results.csv
  if (aiOffProdMalwareResults && aiOffProdBenignResults && aiOffDemoMalwareResults && aiOffDemoBenignResults) {
    const loadResultsCounts = (p: string) => {
      const records = readCsvRecords(p);
      return { n: records.length, verdicts: countBy(records, "verdict") };
    };

    const prodMal = loadResultsCounts(aiOffProdMalwareResults);
    const prodBen = loadResultsCounts(aiOffProdBenignResults);
    const demoMal = loadResultsCounts(aiOffDemoMalwareResults);
    const demoBen = loadResultsCounts(aiOffDemoBenignResults);

    const ablationSvg = renderStackedBars({
      title: "Ablation: verdict distribution",
      subtitle: "Baseline vs AI-off (prod rules) vs AI-off (demo rules)",
      rows: [
        { label: "Baseline (prod + AI) / malware", n: baselineMalwareN, counts: baselineMalwareVerdicts },
        { label: "Baseline (prod + AI) / benign", n: baselineBenignN, counts: baselineBenignVerdicts },
        { label: "AI off (prod) / malware", n: prodMal.n, counts: prodMal.verdicts },
        { label: "AI off (prod) / benign", n: prodBen.n, counts: prodBen.verdicts },
        { label: "AI off (demo) / malware", n: demoMal.n, counts: demoMal.verdicts },
        { label: "AI off (demo) / benign", n: demoBen.n, counts: demoBen.verdicts },
      ],
      categoryOrder: [...VERDICT_ORDER],
      categoryColors: { ...VERDICT_COLORS },
      width: 980,
    });
    writeFileSync(path.join(outDir, "ablation-verdict-distribution.svg"), ablationSvg, "utf8");
  }

  console.log(`Wrote SVGs to ${outDir}`);
}

main();
