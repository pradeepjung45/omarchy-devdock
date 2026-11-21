import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

function loadModel() {
  const src = fs.readFileSync(path.join(ROOT, "Model.js"), "utf8").replace(/^\.pragma library\s*/m, "");
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return sandbox;
}

const Model = loadModel();

test("parseSnapshot parses valid Rust scan payload", () => {
  const raw = JSON.stringify({
    version: 1,
    summary: {
      devPorts: 2,
      webPorts: 1,
      tunnels: 1,
      runningContainers: 1,
      failedServices: 0,
      kubeProd: true,
      kubeContext: "eks-prod-us"
    },
    host: {
      load1m: 1.42,
      memUsedGb: 16.5,
      memTotalGb: 32.0,
      memPct: 52,
      diskPct: 28,
      lanIp: "192.168.1.50",
      tailscaleIp: "100.64.0.1",
      hostname: "devbox"
    },
    ports: [
      {
        port: 3000,
        bindAddr: "0.0.0.0",
        exposedLan: true,
        pid: 4201,
        owned: true,
        comm: "node",
        framework: "Next.js",
        category: "web",
        isHttp: true,
        project: "saas-app",
        gitBranch: "feat/billing",
        memMb: 256.4,
        uptimeSec: 3665,
        url: "http://localhost:3000",
        lanUrl: "http://192.168.1.50:3000",
        containerName: ""
      },
      {
        port: 5432,
        bindAddr: "127.0.0.1",
        exposedLan: false,
        pid: 900,
        owned: false,
        comm: "postgres",
        framework: "PostgreSQL",
        category: "data",
        isHttp: false,
        project: "",
        gitBranch: "",
        memMb: 84.0,
        uptimeSec: 86400,
        url: "localhost:5432",
        lanUrl: "",
        containerName: "fpl-db"
      },
      {
        port: 44259,
        bindAddr: "127.0.0.1",
        exposedLan: false,
        pid: 39474,
        owned: true,
        comm: "java",
        framework: "Gradle Daemon",
        category: "system",
        isHttp: false,
        project: "8.10",
        gitBranch: "",
        memMb: 2048.0,
        uptimeSec: 500,
        url: "localhost:44259",
        lanUrl: "",
        containerName: ""
      }
    ],
    tunnels: [
      { pid: 777, kind: "ssh", direction: "L", localPort: 5433, target: "rds:5432", via: "bastion", owned: true }
    ],
    containers: {
      engine: "docker",
      available: true,
      runningCount: 1,
      items: [{ id: "abc", name: "kafka", image: "apache/kafka:3.7.0", state: "running", status: "Up 1h", ports: [9092] }]
    },
    kube: {
      available: true,
      currentContext: "eks-prod-us",
      currentNamespace: "payments",
      currentIsProd: true,
      awsProfile: "prod",
      contexts: [{ name: "eks-prod-us", namespace: "payments", cluster: "eks-prod", isProd: true }]
    },
    services: {
      failedCount: 0,
      failedUnits: [],
      daemons: [{ unit: "docker.service", label: "Docker", activeState: "active", subState: "running", memMb: 120, isUser: false }]
    }
  });

  const res = Model.parseSnapshot(raw);
  assert.equal(res.ok, true);
  assert.equal(res.data.summary.devPorts, 2);
  assert.equal(res.data.summary.kubeProd, true);
  assert.equal(Model.filterPorts(res.data.ports, "web", "").length, 1);
  assert.equal(Model.filterPorts(res.data.ports, "data", "").length, 1);
  assert.equal(Model.filterPorts(res.data.ports, "system", "").length, 1);
  assert.equal(Model.filterPorts(res.data.ports, "web", "billing").length, 1);
  assert.equal(Model.filterPorts(res.data.ports, "web", "nomatch").length, 0);
  assert.equal(Model.barUrgent(res.data.summary), true);
  assert.equal(Model.barLabel(res.data.summary, false), "PROD · 2 · ⇄1");

  const unk = Model.parseSnapshot(JSON.stringify({
    summary: { kubeUnknown: true, devPorts: 1 },
    kube: { available: true, targetUnknown: true, warningDetail: "invalid json" },
    security: { passCount: 10, infoCount: 1, warnCount: 0, failCount: 0, checks: [] }
  }));
  assert.equal(unk.ok, true);
  assert.equal(unk.data.kube.targetUnknown, true);
  assert.equal(unk.data.security.infoCount, 1);
  assert.equal(Model.barUrgent(unk.data.summary), true);
  assert.equal(Model.barLabel(unk.data.summary, false), "K8s? · 1");
});

test("parseSnapshot rejects empty or invalid JSON safely", () => {
  assert.equal(Model.parseSnapshot("").ok, false);
  assert.equal(Model.parseSnapshot("{not json").ok, false);
});

test("formatUptime and formatMem produce concise labels", () => {
  assert.equal(Model.formatUptime(42), "42s");
  assert.equal(Model.formatUptime(125), "2m");
  assert.equal(Model.formatUptime(3665), "1h 1m");
  assert.equal(Model.formatUptime(90000), "1d 1h");
  assert.equal(Model.formatMem(0), "");
  assert.equal(Model.formatMem(8.4), "8.4 MB");
  assert.equal(Model.formatMem(256.7), "257 MB");
  assert.equal(Model.formatMem(2048), "2.0 GB");
});

test("composeStacks groups multi-container compose projects with pinned IDs", () => {
  const stacks = Model.composeStacks([
    { id: "1", name: "pradeepos-db-1", state: "running", composeProject: "pradeepos" },
    { id: "2", name: "pradeepos-api-1", state: "exited", composeProject: "pradeepos" },
    { id: "3", name: "floci", state: "running", composeProject: "" },
  ]);
  assert.equal(stacks.length, 1);
  assert.equal(stacks[0].project, "pradeepos");
  assert.equal(stacks[0].total, 2);
  assert.equal(stacks[0].running, 1);
  assert.deepEqual([...stacks[0].stopIds], ["1"]);
  assert.deepEqual([...stacks[0].startIds], ["2"]);
});

test("resolvePalette resolves Auto, named presets, and Mono", () => {
  const autoPal = Model.resolvePalette("Auto", { green: "#4ecdc4", blue: "#6a85ff", purple: "#b388eb", cyan: "#a5f5ff", amber: "#f5b971", red: "#ff7b92" });
  assert.equal(autoPal.green, "#4ecdc4");
  assert.equal(autoPal.purple, "#b388eb");
  const crimson = Model.resolvePalette("Crimson", {});
  assert.equal(crimson.blue, "#ff4757");
  assert.equal(crimson.purple, "#ff2e63");
  const matrix = Model.resolvePalette("Matrix", {});
  assert.equal(matrix.green, "#00ff88");
  const cyber = Model.resolvePalette("Cyber", {});
  assert.equal(cyber.green, "#34d399");
  assert.equal(cyber.cyan, "#38bdf8");
  const mono = Model.resolvePalette("Mono", { green: "#4ecdc4" });
  assert.equal(mono.green, "");
  assert.equal(mono.purple, "");
  assert.equal(Model.COLOR_SCHEMES.length, 16);
  assert.equal(Model.schemeMeta("Crimson").desc, "Scarlet & ember");
});

test("manifest.json is valid and points to Panel.qml", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.id, "io.github.pradeepjung45.devdock");
  assert.deepEqual(manifest.kinds, ["bar-widget"]);
  assert.equal(manifest.entryPoints.barWidget, "Panel.qml");
});

test("EXPECTED_SOURCE_SHA256 matches the exact Rust source tree digest", () => {
  const files = ["Cargo.toml", "Cargo.lock", "build.rs"];
  const srcFiles = fs
    .readdirSync(path.join(ROOT, "src"))
    .filter((f) => f.endsWith(".rs"))
    .sort()
    .map((f) => `src/${f}`);
  files.push(...srcFiles);

  const hash = crypto.createHash("sha256");
  for (const rel of files) {
    const buf = fs.readFileSync(path.join(ROOT, rel));
    hash.update(rel);
    hash.update(Buffer.from([0]));
    hash.update(String(buf.length));
    hash.update(Buffer.from([0]));
    hash.update(buf);
  }
  assert.equal(Model.EXPECTED_SOURCE_SHA256, hash.digest("hex"));
});

test("QML security & Omarchy hygiene checks", () => {
  const panelQml = fs.readFileSync(path.join(ROOT, "Panel.qml"), "utf8");
  const serviceQml = fs.readFileSync(path.join(ROOT, "Service.qml"), "utf8");
  const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  const dockerRs = fs.readFileSync(path.join(ROOT, "src/docker.rs"), "utf8");

  // Never access IpcRegistry or spawn shell strings
  assert.equal(panelQml.includes("IpcRegistry"), false);
  assert.equal(serviceQml.includes("IpcRegistry"), false);
  assert.equal(serviceQml.includes("sh -c"), false);
  assert.equal(serviceQml.includes("/bin/sh"), false);
  assert.equal(panelQml.includes("Color.popups.text.r"), false);
  assert.equal(panelQml.includes("Qt.alpha("), false);
  assert.equal(panelQml.toLowerCase().includes("omaphoenix"), false);
  assert.equal(serviceQml.toLowerCase().includes("omaphoenix"), false);

  // Security review regression guards:
  // 1. Never pass raw inline logs via process argv
  assert.equal(panelQml.includes("copyText(devdock.logText"), false);
  assert.ok(panelQml.includes("copyContainerLogs("));
  // 2. Only run verified plugin-private bin/devdock (never ~/.local/bin or PATH)
  assert.equal(serviceQml.includes(".local/bin/devdock"), false);
  assert.equal(serviceQml.includes(".cargo/bin/devdock"), false);
  assert.ok(serviceQml.includes("EXPECTED_SOURCE_SHA256"));
  assert.ok(serviceQml.includes("sha256sum"));
  // 3. No prebuilt release binary download documented
  assert.equal(readme.includes("devdock-linux-x86_64"), false);
  // 4. Local UNIX socket only for container listing (no ambient CLI context fallback)
  assert.equal(dockerRs.includes("Command::new"), false);
  // 5. Log tail viewer guards against cross-container race conditions
  assert.ok(serviceQml.includes("_logRequestSeq"));
  assert.ok(serviceQml.includes("_logInFlightSeq"));

  // Every Text { block in Panel.qml must declare textFormat: Text.PlainText
  const textBlocks = [...panelQml.matchAll(/\bText\s*\{/g)];
  assert.ok(textBlocks.length >= 20, "expected Text elements in Panel.qml");
  for (const m of textBlocks) {
    const snippet = panelQml.slice(m.index, m.index + 240);
    assert.ok(
      snippet.includes("textFormat: Text.PlainText"),
      `Text element at offset ${m.index} missing textFormat: Text.PlainText:\n${snippet}`
    );
  }
});
