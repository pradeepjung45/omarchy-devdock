.pragma library

var EXPECTED_SOURCE_SHA256 = "b41d890e235db541294b1c59c790ea8a8e70379d1528985d16518f81035a60ec"

function emptySnapshot() {
  return {
    version: 2,
    summary: {
      devPorts: 0,
      webPorts: 0,
      tunnels: 0,
      runningContainers: 0,
      failedServices: 0,
      kubeProd: false,
      kubeUnknown: false,
      kubeContext: "",
      internetConns: 0,
      securityCritical: 0,
      securityWarnings: 0
    },
    host: {
      load1m: 0,
      memUsedGb: 0,
      memTotalGb: 0,
      memPct: 0,
      diskPct: 0,
      lanIp: "",
      tailscaleIp: "",
      hostname: "",
      palette: {
        red: "",
        green: "",
        amber: "",
        blue: "",
        purple: "",
        cyan: ""
      }
    },
    ports: [],
    tunnels: [],
    containers: {
      engine: "",
      available: false,
      runningCount: 0,
      items: []
    },
    kube: {
      available: false,
      targetUnknown: false,
      warningDetail: "",
      currentContext: "",
      currentNamespace: "",
      currentIsProd: false,
      awsProfile: "",
      contexts: []
    },
    services: {
      failedCount: 0,
      failedUnits: [],
      daemons: []
    },
    traffic: {
      timestampMs: 0,
      totalRxBytes: 0,
      totalTxBytes: 0,
      internetConns: 0,
      lanConns: 0,
      inboundConns: 0,
      cleartextConns: 0,
      criticalAlerts: [],
      ifaces: [],
      groups: []
    },
    security: {
      passCount: 0,
      infoCount: 0,
      warnCount: 0,
      failCount: 0,
      criticalCount: 0,
      checks: []
    },
    arch: {
      cpuModel: "",
      cpuCores: 0,
      cpuGovernor: "",
      gpuDriver: "",
      gpuPci: "",
      storageChain: "",
      btrfsSubvols: [],
      swapSummary: "",
      kernelRelease: "",
      kernelPreempt: "",
      uptimeSec: 0,
      modulesCount: 0,
      installedKernels: [],
      activeLsms: "",
      tainted: false,
      initComm: "",
      cgroupMode: "",
      cgroupControllers: "",
      processCount: 0,
      waylandDisplay: "",
      compositor: "",
      compositorMemMb: 0,
      shellMemMb: 0,
      audioEngine: "",
      displays: [],
      pacmanPkgCount: 0,
      lastPacmanSync: "",
      topProcs: []
    }
  }
}

function parseSnapshot(raw) {
  var text = String(raw || "").trim()
  if (text === "") return { ok: false, error: "Empty output from devdock" }
  try {
    var data = JSON.parse(text)
    if (!data || typeof data !== "object") {
      return { ok: false, error: "Invalid JSON snapshot" }
    }
    var base = emptySnapshot()
    if (data.summary && typeof data.summary === "object") {
      base.summary.devPorts = Number(data.summary.devPorts || 0)
      base.summary.webPorts = Number(data.summary.webPorts || 0)
      base.summary.tunnels = Number(data.summary.tunnels || 0)
      base.summary.runningContainers = Number(data.summary.runningContainers || 0)
      base.summary.failedServices = Number(data.summary.failedServices || 0)
      base.summary.kubeProd = data.summary.kubeProd === true
      base.summary.kubeUnknown = data.summary.kubeUnknown === true
      base.summary.kubeContext = String(data.summary.kubeContext || "")
      base.summary.internetConns = Number(data.summary.internetConns || 0)
      base.summary.securityCritical = Number(data.summary.securityCritical || 0)
      base.summary.securityWarnings = Number(data.summary.securityWarnings || 0)
    }
    if (data.host && typeof data.host === "object") {
      base.host.load1m = Number(data.host.load1m || 0)
      base.host.memUsedGb = Number(data.host.memUsedGb || 0)
      base.host.memTotalGb = Number(data.host.memTotalGb || 0)
      base.host.memPct = Number(data.host.memPct || 0)
      base.host.diskPct = Number(data.host.diskPct || 0)
      base.host.lanIp = String(data.host.lanIp || "")
      base.host.tailscaleIp = String(data.host.tailscaleIp || "")
      base.host.hostname = String(data.host.hostname || "")
      if (data.host.palette && typeof data.host.palette === "object") {
        base.host.palette.red = String(data.host.palette.red || "")
        base.host.palette.green = String(data.host.palette.green || "")
        base.host.palette.amber = String(data.host.palette.amber || "")
        base.host.palette.blue = String(data.host.palette.blue || "")
        base.host.palette.purple = String(data.host.palette.purple || "")
        base.host.palette.cyan = String(data.host.palette.cyan || "")
      }
    }
    if (Array.isArray(data.ports)) base.ports = data.ports
    if (Array.isArray(data.tunnels)) base.tunnels = data.tunnels
    if (data.containers && typeof data.containers === "object") {
      base.containers.engine = String(data.containers.engine || "")
      base.containers.available = data.containers.available === true
      base.containers.runningCount = Number(data.containers.runningCount || 0)
      base.containers.items = Array.isArray(data.containers.items) ? data.containers.items : []
    }
    if (data.kube && typeof data.kube === "object") {
      base.kube.available = data.kube.available === true
      base.kube.targetUnknown = data.kube.targetUnknown === true
      base.kube.warningDetail = String(data.kube.warningDetail || "")
      base.kube.currentContext = String(data.kube.currentContext || "")
      base.kube.currentNamespace = String(data.kube.currentNamespace || "")
      base.kube.currentIsProd = data.kube.currentIsProd === true
      base.kube.awsProfile = String(data.kube.awsProfile || "")
      base.kube.contexts = Array.isArray(data.kube.contexts) ? data.kube.contexts : []
    }
    if (data.services && typeof data.services === "object") {
      base.services.failedCount = Number(data.services.failedCount || 0)
      base.services.failedUnits = Array.isArray(data.services.failedUnits) ? data.services.failedUnits : []
      base.services.daemons = Array.isArray(data.services.daemons) ? data.services.daemons : []
    }
    if (data.traffic && typeof data.traffic === "object") {
      base.traffic.timestampMs = Number(data.traffic.timestampMs || 0)
      base.traffic.totalRxBytes = Number(data.traffic.totalRxBytes || 0)
      base.traffic.totalTxBytes = Number(data.traffic.totalTxBytes || 0)
      base.traffic.internetConns = Number(data.traffic.internetConns || 0)
      base.traffic.lanConns = Number(data.traffic.lanConns || 0)
      base.traffic.inboundConns = Number(data.traffic.inboundConns || 0)
      base.traffic.cleartextConns = Number(data.traffic.cleartextConns || 0)
      base.traffic.criticalAlerts = Array.isArray(data.traffic.criticalAlerts) ? data.traffic.criticalAlerts : []
      base.traffic.ifaces = Array.isArray(data.traffic.ifaces) ? data.traffic.ifaces : []
      base.traffic.groups = Array.isArray(data.traffic.groups) ? data.traffic.groups : []
    }
    if (data.security && typeof data.security === "object") {
      base.security.passCount = Number(data.security.passCount || 0)
      base.security.infoCount = Number(data.security.infoCount || 0)
      base.security.warnCount = Number(data.security.warnCount || 0)
      base.security.failCount = Number(data.security.failCount || 0)
      base.security.criticalCount = Number(data.security.criticalCount || 0)
      base.security.checks = Array.isArray(data.security.checks) ? data.security.checks : []
    }
    if (data.arch && typeof data.arch === "object") {
      var a = data.arch
      base.arch.cpuModel = String(a.cpuModel || "")
      base.arch.cpuCores = Number(a.cpuCores || 0)
      base.arch.cpuGovernor = String(a.cpuGovernor || "")
      base.arch.gpuDriver = String(a.gpuDriver || "")
      base.arch.gpuPci = String(a.gpuPci || "")
      base.arch.storageChain = String(a.storageChain || "")
      base.arch.btrfsSubvols = Array.isArray(a.btrfsSubvols) ? a.btrfsSubvols : []
      base.arch.swapSummary = String(a.swapSummary || "")
      base.arch.kernelRelease = String(a.kernelRelease || "")
      base.arch.kernelPreempt = String(a.kernelPreempt || "")
      base.arch.uptimeSec = Number(a.uptimeSec || 0)
      base.arch.modulesCount = Number(a.modulesCount || 0)
      base.arch.installedKernels = Array.isArray(a.installedKernels) ? a.installedKernels : []
      base.arch.activeLsms = String(a.activeLsms || "")
      base.arch.tainted = a.tainted === true
      base.arch.initComm = String(a.initComm || "")
      base.arch.cgroupMode = String(a.cgroupMode || "")
      base.arch.cgroupControllers = String(a.cgroupControllers || "")
      base.arch.processCount = Number(a.processCount || 0)
      base.arch.waylandDisplay = String(a.waylandDisplay || "")
      base.arch.compositor = String(a.compositor || "")
      base.arch.compositorMemMb = Number(a.compositorMemMb || 0)
      base.arch.shellMemMb = Number(a.shellMemMb || 0)
      base.arch.audioEngine = String(a.audioEngine || "")
      base.arch.displays = Array.isArray(a.displays) ? a.displays : []
      base.arch.pacmanPkgCount = Number(a.pacmanPkgCount || 0)
      base.arch.lastPacmanSync = String(a.lastPacmanSync || "")
      base.arch.topProcs = Array.isArray(a.topProcs) ? a.topProcs : []
    }
    return { ok: true, data: base }
  } catch (e) {
    return { ok: false, error: "Parse error: " + String(e) }
  }
}

function formatUptime(seconds) {
  var s = Math.max(0, Math.floor(Number(seconds || 0)))
  if (s < 60) return s + "s"
  var m = Math.floor(s / 60)
  if (m < 60) return m + "m"
  var h = Math.floor(m / 60)
  var remM = m % 60
  if (h < 24) return remM > 0 ? (h + "h " + remM + "m") : (h + "h")
  var d = Math.floor(h / 24)
  var remH = h % 24
  return remH > 0 ? (d + "d " + remH + "h") : (d + "d")
}

function formatMem(mb) {
  var v = Number(mb || 0)
  if (!isFinite(v) || v <= 0) return ""
  if (v >= 1024) return (v / 1024).toFixed(1) + " GB"
  if (v >= 10) return Math.round(v) + " MB"
  return v.toFixed(1) + " MB"
}

function formatBytes(bytes) {
  var b = Number(bytes || 0)
  if (!isFinite(b) || b <= 0) return "0 B"
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + " GB"
  if (b >= 1048576) return (b / 1048576).toFixed(0) + " MB"
  if (b >= 1024) return (b / 1024).toFixed(0) + " KB"
  return Math.round(b) + " B"
}

function formatRate(bytesPerSec) {
  var r = Number(bytesPerSec || 0)
  if (!isFinite(r) || r < 50) return "0 B/s"
  if (r >= 1048576) return (r / 1048576).toFixed(1) + " MB/s"
  if (r >= 1024) return (r / 1024).toFixed(1) + " KB/s"
  return Math.round(r) + " B/s"
}

function portTitle(port) {
  if (!port) return ""
  var proj = String(port.project || "").trim()
  var container = String(port.containerName || "").trim()
  var fw = String(port.framework || "").trim()
  var comm = String(port.comm || "").trim()
  if (proj !== "") return proj
  if (container !== "") return container
  if (fw !== "") return fw
  return comm || "process"
}

function portSubtitle(port) {
  if (!port) return ""
  var parts = []
  var fw = String(port.framework || "").trim()
  var title = portTitle(port)
  if (fw !== "" && fw !== title) parts.push(fw)
  var container = String(port.containerName || "").trim()
  if (container !== "" && container !== title) parts.push("ctr:" + container)
  if (port.pid > 0) parts.push("pid " + port.pid)
  var mem = formatMem(port.memMb)
  if (mem !== "") parts.push(mem)
  if (port.uptimeSec > 0) parts.push(formatUptime(port.uptimeSec))
  return parts.join(" · ")
}

function filterPorts(ports, category, query) {
  var list = Array.isArray(ports) ? ports : []
  var q = String(query || "").trim().toLowerCase()
  var out = []
  for (var i = 0; i < list.length; i++) {
    var p = list[i]
    if (!p) continue
    if (category === "dev") {
      if (p.category === "system") continue
    } else if (category !== "" && p.category !== category) {
      continue
    }
    if (q !== "") {
      var hay = (
        String(p.port || "") + " " +
        String(p.project || "") + " " +
        String(p.gitBranch || "") + " " +
        String(p.framework || "") + " " +
        String(p.comm || "") + " " +
        String(p.containerName || "") + " " +
        String(p.bindAddr || "")
      ).toLowerCase()
      if (hay.indexOf(q) === -1) continue
    }
    out.push(p)
  }
  return out
}

function filterTunnels(tunnels, query) {
  var list = Array.isArray(tunnels) ? tunnels : []
  var q = String(query || "").trim().toLowerCase()
  if (q === "") return list
  var out = []
  for (var i = 0; i < list.length; i++) {
    var t = list[i]
    var hay = (
      String(t.localPort || "") + " " +
      String(t.target || "") + " " +
      String(t.via || "") + " " +
      String(t.kind || "") + " " +
      String(t.direction || "")
    ).toLowerCase()
    if (hay.indexOf(q) !== -1) out.push(t)
  }
  return out
}

function filterContainers(items, query) {
  var list = Array.isArray(items) ? items : []
  var q = String(query || "").trim().toLowerCase()
  if (q === "") return list
  var out = []
  for (var i = 0; i < list.length; i++) {
    var c = list[i]
    var hay = (
      String(c.name || "") + " " +
      String(c.image || "") + " " +
      String(c.state || "") + " " +
      String(c.portsRaw || "") + " " +
      String(c.composeProject || "")
    ).toLowerCase()
    if (hay.indexOf(q) !== -1) out.push(c)
  }
  return out
}

function composeStacks(items) {
  var list = Array.isArray(items) ? items : []
  var byProject = {}
  var order = []
  for (var i = 0; i < list.length; i++) {
    var c = list[i]
    var proj = c && c.composeProject ? String(c.composeProject).trim() : ""
    if (proj === "") continue
    if (!byProject[proj]) {
      byProject[proj] = { project: proj, total: 0, running: 0, startIds: [], stopIds: [] }
      order.push(byProject[proj])
    }
    byProject[proj].total += 1
    var cid = c && c.id ? String(c.id).trim() : ""
    if (String(c.state || "").toLowerCase() === "running") {
      byProject[proj].running += 1
      if (cid !== "") byProject[proj].stopIds.push(cid)
    } else if (cid !== "") {
      byProject[proj].startIds.push(cid)
    }
  }
  return order
}

function filterTrafficGroups(groups, query) {
  var list = Array.isArray(groups) ? groups : []
  var q = String(query || "").trim().toLowerCase()
  if (q === "") return list
  var out = []
  for (var i = 0; i < list.length; i++) {
    var g = list[i]
    var hay = (String(g.comm || "") + " " + String(g.pid || "") + " " + String(g.exe || "") + " " + String(g.maxRisk || "")).toLowerCase()
    if (hay.indexOf(q) !== -1) {
      out.push(g)
      continue
    }
    var conns = Array.isArray(g.connections) ? g.connections : []
    for (var j = 0; j < conns.length; j++) {
      var c = conns[j]
      var chay = (String(c.remoteIp || "") + ":" + String(c.remotePort || "") + " " + String(c.service || "") + " " + String(c.scope || "")).toLowerCase()
      if (chay.indexOf(q) !== -1) {
        out.push(g)
        break
      }
    }
  }
  return out
}

function filterSecurityChecks(checks, query) {
  var list = Array.isArray(checks) ? checks : []
  var q = String(query || "").trim().toLowerCase()
  if (q === "") return list
  var out = []
  for (var i = 0; i < list.length; i++) {
    var c = list[i]
    var hay = (String(c.label || "") + " " + String(c.status || "") + " " + String(c.detail || "")).toLowerCase()
    if (hay.indexOf(q) !== -1) out.push(c)
  }
  return out
}

function filterContexts(contexts, query) {
  var list = Array.isArray(contexts) ? contexts : []
  var q = String(query || "").trim().toLowerCase()
  if (q === "") return list
  var out = []
  for (var i = 0; i < list.length; i++) {
    var c = list[i]
    var hay = (
      String(c.name || "") + " " +
      String(c.namespace || "") + " " +
      String(c.cluster || "")
    ).toLowerCase()
    if (hay.indexOf(q) !== -1) out.push(c)
  }
  return out
}

function filterDaemons(daemons, query) {
  var list = Array.isArray(daemons) ? daemons : []
  var q = String(query || "").trim().toLowerCase()
  if (q === "") return list
  var out = []
  for (var i = 0; i < list.length; i++) {
    var d = list[i]
    var hay = (
      String(d.unit || "") + " " +
      String(d.label || "") + " " +
      String(d.activeState || "") + " " +
      String(d.subState || "")
    ).toLowerCase()
    if (hay.indexOf(q) !== -1) out.push(d)
  }
  return out
}

function barLabel(summary, binaryMissing) {
  if (binaryMissing) return "setup"
  var s = summary || {}
  var ports = Number(s.devPorts || 0)
  var tunnels = Number(s.tunnels || 0)
  var ctrs = Number(s.runningContainers || 0)
  var failed = Number(s.failedServices || 0)
  var crit = Number(s.securityCritical || 0)
  var prod = s.kubeProd === true
  var kUnknown = s.kubeUnknown === true

  var parts = []
  if (prod) parts.push("PROD")
  else if (kUnknown) parts.push("K8s?")
  if (crit > 0) parts.push("SEC!" + crit)
  if (failed > 0) parts.push("!" + failed)
  if (ports > 0) parts.push(String(ports))
  if (tunnels > 0) parts.push("⇄" + tunnels)
  if (ports === 0 && tunnels === 0 && ctrs > 0) parts.push("ctr:" + ctrs)
  if (parts.length === 0) return "0"
  return parts.join(" · ")
}

function barUrgent(summary) {
  var s = summary || {}
  return s.kubeProd === true || s.kubeUnknown === true || Number(s.failedServices || 0) > 0 || Number(s.securityCritical || 0) > 0
}

function barActive(summary) {
  var s = summary || {}
  return Number(s.devPorts || 0) > 0 || Number(s.tunnels || 0) > 0 || Number(s.runningContainers || 0) > 0
}

function barTooltip(summary, host, binaryMissing) {
  if (binaryMissing) return "DevDock: devdock binary not found (click for setup)"
  var s = summary || {}
  var h = host || {}
  var parts = ["DevDock"]
  parts.push(Number(s.devPorts || 0) + " dev ports")
  if (Number(s.tunnels || 0) > 0) parts.push(s.tunnels + " tunnels")
  if (Number(s.runningContainers || 0) > 0) parts.push(s.runningContainers + " containers")
  if (Number(s.internetConns || 0) > 0) parts.push(s.internetConns + " net conns")
  if (s.kubeUnknown === true) {
    parts.push("K8s: TARGET UNKNOWN")
  } else if (String(s.kubeContext || "") !== "") {
    parts.push("K8s: " + s.kubeContext + (s.kubeProd ? " [PROD]" : ""))
  }
  if (Number(s.securityCritical || 0) > 0) parts.push(s.securityCritical + " security alert(s)")
  if (Number(s.failedServices || 0) > 0) parts.push(s.failedServices + " failed units")
  if (Number(h.memPct || 0) > 0) parts.push("RAM " + h.memPct + "%")
  return parts.join(" · ")
}

var COLOR_SCHEMES = [
  { id: "Auto", label: "Auto", desc: "Live Omarchy theme", green: "#4ecdc4", cyan: "#38bdf8", blue: "#60a5fa", purple: "#b388eb", amber: "#f5b971", red: "#ff7b92" },
  { id: "Crimson", label: "Crimson", desc: "Scarlet & ember", green: "#ff5c77", cyan: "#ff9f43", blue: "#ff4757", purple: "#ff2e63", amber: "#ffbe76", red: "#ff3838" },
  { id: "Bloodline", label: "Bloodline", desc: "Samurai red & rose", green: "#f43f5e", cyan: "#fda4af", blue: "#fb7185", purple: "#e11d48", amber: "#fb923c", red: "#ef4444" },
  { id: "Cyber", label: "Cyber", desc: "Vivid neon accents", green: "#34d399", cyan: "#38bdf8", blue: "#60a5fa", purple: "#c084fc", amber: "#fbbf24", red: "#fb7185" },
  { id: "Matrix", label: "Matrix", desc: "Phosphor terminal", green: "#00ff88", cyan: "#4ade80", blue: "#22c55e", purple: "#86efac", amber: "#bef264", red: "#ff5555" },
  { id: "Synthwave", label: "Synthwave", desc: "Outrun pink & laser", green: "#36f9f6", cyan: "#72f1b8", blue: "#ff7edb", purple: "#c084fc", amber: "#fede5d", red: "#fe4450" },
  { id: "AmberGold", label: "Amber", desc: "Obsidian & molten gold", green: "#fbbf24", cyan: "#fcd34d", blue: "#f59e0b", purple: "#fb923c", amber: "#fde047", red: "#ef4444" },
  { id: "Tokyo", label: "Tokyo", desc: "Tokyo Night", green: "#9ece6a", cyan: "#7dcfff", blue: "#7aa2f7", purple: "#bb9af7", amber: "#e0af68", red: "#f7768e" },
  { id: "Catppuccin", label: "Catppuccin", desc: "Mocha pastels", green: "#a6e3a1", cyan: "#94e2d5", blue: "#89b4fa", purple: "#cba6f7", amber: "#f9e2af", red: "#f38ba8" },
  { id: "RosePine", label: "Rosé Pine", desc: "Soho dusk & iris", green: "#9ccfd8", cyan: "#ebbcba", blue: "#56949f", purple: "#c4a7e7", amber: "#f6c177", red: "#eb6f92" },
  { id: "Dracula", label: "Dracula", desc: "Vampire neon", green: "#50fa7b", cyan: "#8be9fd", blue: "#bd93f9", purple: "#ff79c6", amber: "#f1fa8c", red: "#ff5555" },
  { id: "Kanagawa", label: "Kanagawa", desc: "Wave indigo & sakura", green: "#98bb6c", cyan: "#7fb4ca", blue: "#7e9cd8", purple: "#957fb8", amber: "#e6c384", red: "#e82424" },
  { id: "Everforest", label: "Everforest", desc: "Moss & pine", green: "#a7c080", cyan: "#83c092", blue: "#7fbbb3", purple: "#d699b6", amber: "#dbbc7f", red: "#e67e80" },
  { id: "Nord", label: "Nord", desc: "Arctic frost", green: "#a3be8c", cyan: "#88c0d0", blue: "#81a1c1", purple: "#b48ead", amber: "#ebcb8b", red: "#bf616a" },
  { id: "Gruvbox", label: "Gruvbox", desc: "Warm retro", green: "#b8bb26", cyan: "#8ec07c", blue: "#83a598", purple: "#d3869b", amber: "#fabd2f", red: "#fb4934" },
  { id: "Mono", label: "Mono", desc: "Minimalist theme", green: "", cyan: "", blue: "", purple: "", amber: "", red: "" }
]

function schemeMeta(schemeName) {
  var name = String(schemeName || "Auto")
  for (var i = 0; i < COLOR_SCHEMES.length; i++) {
    if (COLOR_SCHEMES[i].id === name) return COLOR_SCHEMES[i]
  }
  return COLOR_SCHEMES[0]
}

function resolvePalette(schemeName, hostPalette) {
  var name = String(schemeName || "Auto")
  if (name === "Mono") {
    return { green: "", cyan: "", blue: "", purple: "", amber: "", red: "" }
  }
  if (name === "Auto") {
    var hp = hostPalette || {}
    return {
      green: String(hp.green || "#4ade80"),
      cyan: String(hp.cyan || "#38bdf8"),
      blue: String(hp.blue || "#60a5fa"),
      purple: String(hp.purple || "#c084fc"),
      amber: String(hp.amber || "#f5b971"),
      red: String(hp.red || "")
    }
  }
  for (var i = 0; i < COLOR_SCHEMES.length; i++) {
    if (COLOR_SCHEMES[i].id === name) {
      var s = COLOR_SCHEMES[i]
      return { green: s.green, cyan: s.cyan, blue: s.blue, purple: s.purple, amber: s.amber, red: s.red }
    }
  }
  return resolvePalette("Auto", hostPalette)
}
