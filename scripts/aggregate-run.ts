import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

type JsonObject = Record<string, unknown>;

type ScanRunResponse = {
  scan_id?: string;
  sha256?: string;
  verdict?: {
    result?: string;
    confidence?: number;
    risk_score?: number;
    method?: string;
  };
  metadata?: { loader?: string | null };
  profile?: {
    mod_metadata?: { loader?: string | null };
    class_count?: number;
    jar_size_bytes?: number;
    capabilities?: Record<string, { present?: boolean }>;
    yara_hits?: Array<{ severity?: string }>;
  };
  capabilities?: Record<string, { present?: boolean }>;
  yara_hits?: Array<{ severity?: string }>;
  static_findings?: {
    matches?: Array<{
      extracted_urls?: string[] | null;
      extracted_commands?: string[] | null;
      extracted_file_paths?: string[] | null;
      source?: string;
      severity?: string;
    }>;
  };
};

const CAP_KEYS = [
  "network",
  "dynamic_loading",
  "execution",
  "credential_theft",
  "persistence",
  "native_loading",
  "filesystem",
  "deserialization",
] as const;

function asObject(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : null;
}

function normalizeSeverity(raw: unknown): "critical" | "high" | "medium" | "low" | "other" {
  const s = String(raw ?? "").trim().toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "med" || s === "medium") return "medium";
  if (s === "low") return "low";
  return "other";
}

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

function csvEscape(value: unknown): string {
  const s = String(value ?? "");
  if (/[\n\r,"]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

function walkFiles(rootDir: string): string[] {
  const out: string[] = [];
  const stack = [rootDir];
  while (stack.length) {
    const dir = stack.pop()!;
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name);
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (name === "jars" || name === "node_modules") continue;
        stack.push(full);
      } else {
        out.push(full);
      }
    }
  }
  return out;
}

function extractDomainsFromUrls(urls: Iterable<string>): Set<string> {
  const domains = new Set<string>();
  for (const raw of urls) {
    try {
      const u = new URL(raw);
      if (u.hostname) domains.add(u.hostname.trim().toLowerCase());
    } catch {
      // ignore
    }
  }
  return domains;
}

function coerceScanPayload(value: unknown): ScanRunResponse | null {
  const obj = asObject(value);
  if (!obj) return null;

  // Support wrapper shapes like { scan: { ... } }
  const wrapped = asObject(obj.scan);
  if (wrapped) return wrapped as unknown as ScanRunResponse;

  if (typeof obj.scan_id === "string" && asObject(obj.verdict)) {
    return obj as unknown as ScanRunResponse;
  }
  return null;
}

function main() {
  const argv = process.argv.slice(2);
  const runDir = argv[0];
  if (!runDir) {
    const self = path.basename(fileURLToPath(import.meta.url));
    console.error(`Usage: bun scripts/${self} <run-dir>`);
    process.exit(2);
  }

  const runJsonPath = path.join(runDir, "run.json");
  const resultsCsvPath = path.join(runDir, "results.csv");
  const aggregateCsvPath = path.join(runDir, "aggregate.csv");
  const summaryJsonPath = path.join(runDir, "summary.json");

  const runJson = JSON.parse(readFileSync(runJsonPath, "utf8")) as JsonObject;
  const runId = String(runJson.run_id ?? path.basename(runDir));
  const dataset = (() => {
    if (typeof runJson.dataset === "string" && runJson.dataset.trim()) return runJson.dataset.trim();
    const limit = typeof runJson.limit === "number" ? runJson.limit : Number(runJson.limit ?? 0);
    if (runJson.search_url && limit > 0) return `modrinth-top-${limit}`;
    return path.basename(runDir);
  })();

  const resultsMapByScanId = new Map<string, JsonObject>();
  const resultsMapBySha = new Map<string, JsonObject>();
  if (statSync(resultsCsvPath).isFile()) {
    const rows = parseCsv(readFileSync(resultsCsvPath, "utf8"));
    const header = rows[0] ?? [];
    for (const row of rows.slice(1)) {
      const record: JsonObject = {};
      for (let i = 0; i < header.length; i++) record[header[i]] = row[i] ?? "";
      const scanId = String(record.scan_id ?? "").trim();
      const sha = String(record.sha256 ?? "").trim();
      if (scanId) resultsMapByScanId.set(scanId, record);
      if (sha) resultsMapBySha.set(sha, record);
    }
  }

  const scanFiles = walkFiles(runDir).filter((p) => p.endsWith("-scan.json"));
  if (scanFiles.length === 0) {
    throw new Error(`No *-scan.json files found under: ${runDir}`);
  }

  const aggregateRows: JsonObject[] = [];

  for (const scanPath of scanFiles) {
    const parsed = JSON.parse(readFileSync(scanPath, "utf8"));
    const scan = coerceScanPayload(parsed);
    if (!scan) continue;

    const scanId = String(scan.scan_id ?? "");
    const verdict = scan.verdict ?? {};
    const sha = String(scan.sha256 ?? "").trim();
    const resultsRecord = (scanId && resultsMapByScanId.get(scanId)) || (sha && resultsMapBySha.get(sha)) || null;

    const slug = String(resultsRecord?.slug ?? "").trim();
    const filename = String(resultsRecord?.filename ?? resultsRecord?.file ?? "").trim();
    const sampleLabel = slug || filename || path.basename(scanPath).replace(/-scan\.json$/i, "");

    const loader =
      String(scan.metadata?.loader ?? scan.profile?.mod_metadata?.loader ?? "").trim() || "";

    const classCount = Number(scan.profile?.class_count ?? 0);
    const jarSizeBytes = Number(scan.profile?.jar_size_bytes ?? 0);

    const caps = scan.profile?.capabilities ?? scan.capabilities ?? {};
    const capFlags: Record<string, number> = {};
    for (const key of CAP_KEYS) {
      capFlags[`cap_${key}`] = caps[key]?.present ? 1 : 0;
    }

    const yaraHits = scan.yara_hits ?? scan.profile?.yara_hits ?? [];
    const yaraCounts = { critical: 0, high: 0, medium: 0, low: 0, other: 0 };
    for (const hit of yaraHits) {
      yaraCounts[normalizeSeverity(hit?.severity)]++;
    }

    const urls = new Set<string>();
    const commands = new Set<string>();
    const filePaths = new Set<string>();
    for (const m of scan.static_findings?.matches ?? []) {
      for (const u of m.extracted_urls ?? []) urls.add(u);
      for (const c of m.extracted_commands ?? []) commands.add(c);
      for (const pth of m.extracted_file_paths ?? []) filePaths.add(pth);
    }
    const domains = extractDomainsFromUrls(urls);

    aggregateRows.push({
      run_id: runId,
      dataset,
      sample: sampleLabel,
      sha256: sha || String(resultsRecord?.sha256 ?? ""),
      verdict: String(verdict.result ?? ""),
      confidence: Number(verdict.confidence ?? 0),
      risk_score: Number(verdict.risk_score ?? 0),
      method: String(verdict.method ?? ""),
      loader,
      class_count: classCount,
      jar_size_bytes: jarSizeBytes,
      ...capFlags,
      yara_critical: yaraCounts.critical,
      yara_high: yaraCounts.high,
      yara_medium: yaraCounts.medium,
      yara_low: yaraCounts.low,
      yara_other: yaraCounts.other,
      extracted_url_count: urls.size,
      extracted_domain_count: domains.size,
      extracted_command_count: commands.size,
      extracted_path_count: filePaths.size,
    });
  }

  // Stable sort: by risk_score desc then sample
  aggregateRows.sort((a, b) => {
    const ra = Number(a.risk_score ?? 0);
    const rb = Number(b.risk_score ?? 0);
    if (rb !== ra) return rb - ra;
    return String(a.sample ?? "").localeCompare(String(b.sample ?? ""));
  });

  const header = [
    "run_id",
    "dataset",
    "sample",
    "sha256",
    "verdict",
    "confidence",
    "risk_score",
    "method",
    "loader",
    "class_count",
    "jar_size_bytes",
    ...CAP_KEYS.map((k) => `cap_${k}`),
    "yara_critical",
    "yara_high",
    "yara_medium",
    "yara_low",
    "yara_other",
    "extracted_url_count",
    "extracted_domain_count",
    "extracted_command_count",
    "extracted_path_count",
  ];

  const csvLines = [header.join(",")];
  for (const row of aggregateRows) {
    csvLines.push(header.map((k) => csvEscape((row as JsonObject)[k])).join(","));
  }
  writeFileSync(aggregateCsvPath, csvLines.join("\n") + "\n", "utf8");

  const verdictCounts: Record<string, number> = {};
  const capPresentCounts: Record<string, number> = {};
  for (const cap of CAP_KEYS) capPresentCounts[cap] = 0;

  for (const row of aggregateRows) {
    const v = String(row.verdict ?? "UNKNOWN") || "UNKNOWN";
    verdictCounts[v] = (verdictCounts[v] ?? 0) + 1;
    for (const cap of CAP_KEYS) {
      if (Number((row as JsonObject)[`cap_${cap}`] ?? 0) === 1) capPresentCounts[cap]++;
    }
  }

  const topSuspicious = aggregateRows
    .filter((r) => String(r.verdict ?? "") !== "CLEAN")
    .slice(0, 20)
    .map((r) => ({
      sample: r.sample,
      sha256: r.sha256,
      verdict: r.verdict,
      risk_score: r.risk_score,
      method: r.method,
      yara_high_or_critical: Number(r.yara_high ?? 0) + Number(r.yara_critical ?? 0),
    }));

  const summary = {
    run_id: runId,
    dataset,
    sample_count: aggregateRows.length,
    verdict_counts: verdictCounts,
    capability_prevalence: Object.fromEntries(
      CAP_KEYS.map((cap) => [
        cap,
        {
          present: capPresentCounts[cap],
          fraction: aggregateRows.length ? capPresentCounts[cap] / aggregateRows.length : 0,
        },
      ])
    ),
    top_suspicious: topSuspicious,
  };
  writeFileSync(summaryJsonPath, JSON.stringify(summary, null, 2) + "\n", "utf8");

  console.log(`Wrote ${aggregateCsvPath}`);
  console.log(`Wrote ${summaryJsonPath}`);
}

main();
