import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

Item {
  id: root

  property var settings: ({})
  property bool panelOpen: false

  property bool initialized: false
  property bool refreshing: false
  property bool binaryMissing: false
  property string resolvedBinary: ""
  property string statusText: "Scanning..."
  property string toastText: ""
  property bool toastIsError: false

  // Per-container optimistic pending state: { "<id>": "starting" | "stopping" | "restarting" }
  property var pendingContainers: ({})

  // Instant inline container log viewer state (direct Unix-socket tail)
  property string logContainerId: ""
  property string logContainerName: ""
  property string logText: ""
  property bool logLoading: false
  property bool logAutoRefresh: true
  property string logError: ""

  // Live network throughput delta (bytes/sec) + on-demand reverse DNS + HTTP probe caches
  property double rxRateBps: 0
  property double txRateBps: 0
  property var rdnsCache: ({})
  property var probeCache: ({})

  readonly property string pluginDirPath: Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "").replace(/\/$/, "")
  readonly property string setupCommand: "cd " + (pluginDirPath !== "" ? pluginDirPath : "~/.config/omarchy/plugins/io.github.pradeepjung45.devdock") + " && bash ./install.sh"
  readonly property bool crashNotifications: setting("crashNotifications", true) !== false

  property var _prevRunningContainers: ({})
  property var _prevDevPorts: ({})
  property var _manualStops: ({})
  property bool _watchdogPrimed: false
  property string _probeStdout: ""

  property var snapshot: Model.emptySnapshot()
  readonly property var summary: snapshot.summary
  readonly property var host: snapshot.host
  readonly property var ports: snapshot.ports
  readonly property var tunnels: snapshot.tunnels
  readonly property var containers: snapshot.containers
  readonly property var kube: snapshot.kube
  readonly property var services: snapshot.services
  readonly property var traffic: snapshot.traffic
  readonly property var security: snapshot.security
  readonly property var arch: snapshot.arch

  readonly property int refreshIntervalSec: intSetting("refreshIntervalSec", 5, 2, 60)
  readonly property bool busy: actionProcess.running

  property double _prevNetTs: 0
  property double _prevRxBytes: 0
  property double _prevTxBytes: 0
  property string _rdnsIp: ""
  property string _rdnsStdout: ""

  property int _probeIndex: 0
  property bool _scanInFlight: false
  property string _scanStdout: ""
  property string _scanStderr: ""
  property string _actionStdout: ""
  property string _actionStderr: ""
  property string _actionLabel: ""
  property bool _actionNeedsRefresh: false
  property string _ctrActionId: ""
  property string _ctrActionLabel: ""
  property string _ctrActionStdout: ""
  property string _ctrActionStderr: ""
  property string _logStdout: ""
  property string _logStderr: ""

  readonly property var _candidates: {
    var home = String(Quickshell.env("HOME") || "")
    var bundled = Qt.resolvedUrl("bin/devdock").toString().replace(/^file:\/\//, "")
    var list = []
    if (bundled !== "") list.push(bundled)
    if (home !== "") {
      list.push(home + "/.local/bin/devdock")
      list.push(home + "/.cargo/bin/devdock")
    }
    list.push("devdock")
    return list
  }

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function intSetting(name, fallback, min, max) {
    var n = parseInt(String(setting(name, fallback)), 10)
    if (!isFinite(n)) n = fallback
    if (n < min) n = min
    if (n > max) n = max
    return n
  }

  function pendingFor(containerId) {
    var id = String(containerId || "")
    return pendingContainers && pendingContainers[id] ? String(pendingContainers[id]) : ""
  }

  function _setPending(containerId, stateLabel) {
    var next = ({})
    for (var k in pendingContainers) next[k] = pendingContainers[k]
    if (stateLabel === "") delete next[String(containerId)]
    else next[String(containerId)] = stateLabel
    pendingContainers = next
  }

  function showToast(msg, isErr) {
    toastText = String(msg || "")
    toastIsError = isErr === true
    toastTimer.restart()
  }

  function retryProbe() {
    resolvedBinary = ""
    binaryMissing = false
    _probeIndex = 0
    refresh()
  }

  function refresh() {
    if (scanProcess.running || _scanInFlight) return
    var bin = resolvedBinary
    if (bin === "") {
      if (_probeIndex >= _candidates.length) {
        binaryMissing = true
        initialized = true
        statusText = "devdock binary not found"
        return
      }
      bin = _candidates[_probeIndex]
    }
    _scanStdout = ""
    _scanStderr = ""
    _scanInFlight = true
    refreshing = true
    scanProcess.command = [bin, "scan"]
    scanProcess.running = true
  }

  function _handleProbeFailure() {
    if (resolvedBinary !== "") return
    _probeIndex += 1
    if (_probeIndex < _candidates.length) {
      Qt.callLater(function() { root.refresh() })
    } else {
      binaryMissing = true
      initialized = true
      statusText = "devdock binary not found"
    }
  }

  function runAction(args, label, shouldRefresh) {
    if (resolvedBinary === "" || actionProcess.running) return
    _actionStdout = ""
    _actionStderr = ""
    _actionLabel = String(label || "")
    _actionNeedsRefresh = shouldRefresh === true
    var cmd = [resolvedBinary]
    for (var i = 0; i < args.length; i++) cmd.push(String(args[i]))
    actionProcess.command = cmd
    actionProcess.running = true
  }

  function _markManualStop(key) {
    var next = ({})
    var now = Date.now()
    for (var k in _manualStops) {
      if (now - _manualStops[k] < 12000) next[k] = _manualStops[k]
    }
    next[String(key)] = now
    _manualStops = next
  }

  function _wasManualStop(key) {
    var ts = _manualStops ? _manualStops[String(key)] : 0
    return ts > 0 && (Date.now() - ts) < 12000
  }

  function _runCrashWatchdog(nextData) {
    var nextCtrs = ({})
    var cItems = (nextData.containers && Array.isArray(nextData.containers.items)) ? nextData.containers.items : []
    for (var i = 0; i < cItems.length; i++) {
      var c = cItems[i]
      if (c && String(c.state || "").toLowerCase() === "running") {
        nextCtrs[String(c.id)] = String(c.name || c.id)
      }
    }

    var nextPorts = ({})
    var pItems = Array.isArray(nextData.ports) ? nextData.ports : []
    for (var j = 0; j < pItems.length; j++) {
      var p = pItems[j]
      if (p && p.category !== "system") {
        nextPorts[String(p.port)] = Model.portTitle(p) + " (:" + p.port + ")"
      }
    }

    if (_watchdogPrimed && crashNotifications && resolvedBinary !== "") {
      var alerts = []
      for (var cid in _prevRunningContainers) {
        if (!nextCtrs[cid] && !_wasManualStop("ctr:" + cid)) {
          alerts.push("Container " + _prevRunningContainers[cid] + " exited")
        }
      }
      for (var pnum in _prevDevPorts) {
        if (!nextPorts[pnum] && !_wasManualStop("port:" + pnum)) {
          alerts.push("Server " + _prevDevPorts[pnum] + " stopped")
        }
      }
      if (alerts.length > 0 && !notifyProcess.running) {
        notifyProcess.command = [resolvedBinary, "notify", "DevDock Watchdog", alerts.slice(0, 3).join(" · ")]
        notifyProcess.running = true
      }
    }

    _prevRunningContainers = nextCtrs
    _prevDevPorts = nextPorts
    _watchdogPrimed = true
  }

  function stopPort(pid, port) {
    _markManualStop("port:" + port)
    runAction(["stop", String(pid), String(port)], "Stopping :" + port, true)
  }

  function killPort(pid, port) {
    _markManualStop("port:" + port)
    runAction(["kill", String(pid), String(port)], "Force killing :" + port, true)
  }

  function stopNetPid(pid, comm) {
    runAction(["net-stop", String(pid)], "Stopping " + (comm || ("pid " + pid)), true)
  }

  function probeFor(port) {
    var key = String(port || "")
    return probeCache && probeCache[key] ? probeCache[key] : null
  }

  function probePort(port) {
    var p = String(port || "")
    if (resolvedBinary === "" || p === "" || probeProcess.running) return
    _probeStdout = ""
    probeProcess.command = [resolvedBinary, "probe", p]
    probeProcess.running = true
  }

  function copySetupCommand() {
    if (setupCopyProcess.running) return
    setupCopyProcess.command = ["wl-copy", "--", setupCommand]
    setupCopyProcess.running = true
  }

  function focusPid(pid) {
    runAction(["focus", String(pid)], "Focusing window", false)
  }

  function openUrl(url) {
    runAction(["open", String(url)], "Opening " + url, false)
  }

  function copyText(text, label) {
    runAction(["copy", String(text)], label ? ("Copied " + label) : "Copied to clipboard", false)
  }

  function containerAction(verb, id, name) {
    var cid = String(id || "")
    var cname = String(name || cid)
    if (verb === "logs") {
      runAction(["container", "logs", cid], "Opening logs for " + cname, false)
      return
    }
    if (verb === "exec") {
      runAction(["container", "exec", cid], "Opening shell in " + cname, false)
      return
    }
    if (resolvedBinary === "" || containerActionProcess.running) return
    if (verb === "stop" || verb === "restart") _markManualStop("ctr:" + cid)
    var verbIng = verb === "start" ? "starting" : (verb === "stop" ? "stopping" : "restarting")
    _setPending(cid, verbIng)
    _ctrActionId = cid
    _ctrActionLabel = (verb === "start" ? "Started " : (verb === "stop" ? "Stopped " : "Restarted ")) + cname
    _ctrActionStdout = ""
    _ctrActionStderr = ""
    containerActionProcess.command = [resolvedBinary, "container", String(verb), cid]
    containerActionProcess.running = true
  }

  function composeStackAction(verb, project) {
    var proj = String(project || "")
    if (proj === "" || resolvedBinary === "") return
    if (verb === "stop") {
      var items = (containers && Array.isArray(containers.items)) ? containers.items : []
      for (var i = 0; i < items.length; i++) {
        if (items[i] && String(items[i].composeProject || "") === proj) {
          _markManualStop("ctr:" + items[i].id)
        }
      }
    }
    runAction(["stack", String(verb), proj], (verb === "start" ? "Starting stack " : "Stopping stack ") + proj, true)
  }

  function openInlineLogs(id, name) {
    logContainerId = String(id || "")
    logContainerName = String(name || id || "")
    logError = ""
    logText = ""
    fetchInlineLogs()
  }

  function closeInlineLogs() {
    logContainerId = ""
    logContainerName = ""
    logText = ""
    logError = ""
    logLoading = false
  }

  function fetchInlineLogs() {
    if (resolvedBinary === "" || logContainerId === "" || logTailProcess.running) return
    _logStdout = ""
    _logStderr = ""
    logLoading = true
    logTailProcess.command = [resolvedBinary, "container-tail", logContainerId, "120"]
    logTailProcess.running = true
  }

  function switchKubeContext(name) {
    runAction(["k8s-switch", String(name)], "Switched K8s context to " + name, true)
  }

  function openServiceLogs(unit, isUser) {
    var args = ["service-logs", String(unit)]
    if (isUser === true) args.push("--user")
    runAction(args, "Opening logs for " + unit, false)
  }

  function rdnsFor(ip) {
    var key = String(ip || "")
    return rdnsCache && rdnsCache[key] ? String(rdnsCache[key]) : ""
  }

  function lookupRdns(ip) {
    var target = String(ip || "").trim()
    if (resolvedBinary === "" || target === "" || rdnsProcess.running) return
    if (rdnsCache && rdnsCache[target]) return
    _rdnsIp = target
    _rdnsStdout = ""
    rdnsProcess.command = [resolvedBinary, "rdns", target]
    rdnsProcess.running = true
  }

  Timer {
    id: pollTimer
    interval: (root.panelOpen ? Math.min(root.refreshIntervalSec, 2) : root.refreshIntervalSec) * 1000
    repeat: true
    running: !root.binaryMissing
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Timer {
    id: logPollTimer
    interval: 1500
    repeat: true
    running: root.panelOpen && root.logContainerId !== "" && root.logAutoRefresh && !root.binaryMissing
    onTriggered: root.fetchInlineLogs()
  }

  Timer {
    id: settleTimer
    interval: 550
    repeat: false
    onTriggered: root.refresh()
  }

  Timer {
    id: toastTimer
    interval: 2800
    repeat: false
    onTriggered: {
      root.toastText = ""
      root.toastIsError = false
    }
  }

  Process {
    id: scanProcess
    running: false
    command: []
    stdout: StdioCollector { id: scanStdout; waitForEnd: true; onStreamFinished: root._scanStdout = text }
    stderr: StdioCollector { id: scanStderr; waitForEnd: true; onStreamFinished: root._scanStderr = text }

    onExited: function(exitCode) {
      root._scanInFlight = false
      root.refreshing = false
      var out = String(scanStdout.text || root._scanStdout || "")
      if (exitCode === 0) {
        var parsed = Model.parseSnapshot(out)
        if (parsed.ok) {
          if (root.resolvedBinary === "" && root._probeIndex < root._candidates.length) {
            root.resolvedBinary = root._candidates[root._probeIndex]
          }
          root.binaryMissing = false
          root.initialized = true
          // Compute live RX/TX throughput from /proc/net/dev counter deltas
          var tr = parsed.data.traffic
          if (tr && tr.timestampMs > 0) {
            if (root._prevNetTs > 0 && tr.timestampMs > root._prevNetTs) {
              var dt = (tr.timestampMs - root._prevNetTs) / 1000.0
              if (dt >= 0.25) {
                var dRx = Math.max(0, tr.totalRxBytes - root._prevRxBytes)
                var dTx = Math.max(0, tr.totalTxBytes - root._prevTxBytes)
                root.rxRateBps = dRx / dt
                root.txRateBps = dTx / dt
              }
            }
            root._prevNetTs = tr.timestampMs
            root._prevRxBytes = tr.totalRxBytes
            root._prevTxBytes = tr.totalTxBytes
          }
          root._runCrashWatchdog(parsed.data)
          root.snapshot = parsed.data
          root.statusText = Model.barTooltip(parsed.data.summary, parsed.data.host, false)
          return
        }
      }
      root._handleProbeFailure()
    }

    onRunningChanged: {
      if (!running && root._scanInFlight) {
        root._scanInFlight = false
        root.refreshing = false
        root._handleProbeFailure()
      }
    }
  }

  Process {
    id: containerActionProcess
    running: false
    command: []
    stdout: StdioCollector { id: ctrStdout; waitForEnd: true; onStreamFinished: root._ctrActionStdout = text }
    stderr: StdioCollector { id: ctrStderr; waitForEnd: true; onStreamFinished: root._ctrActionStderr = text }

    onExited: function(exitCode) {
      var cid = root._ctrActionId
      var out = String(ctrStdout.text || root._ctrActionStdout || "").trim()
      var err = String(ctrStderr.text || root._ctrActionStderr || "").trim()
      root._setPending(cid, "")
      if (exitCode === 0) {
        root.showToast(root._ctrActionLabel || out || "Done", false)
      } else {
        root.showToast(err !== "" ? err : (out !== "" ? out : "Container action failed"), true)
      }
      root.refresh()
      settleTimer.restart()
      if (root.logContainerId !== "" && root.logContainerId === cid) {
        root.fetchInlineLogs()
      }
    }
  }

  Process {
    id: logTailProcess
    running: false
    command: []
    stdout: StdioCollector { id: logStdout; waitForEnd: true; onStreamFinished: root._logStdout = text }
    stderr: StdioCollector { id: logStderr; waitForEnd: true; onStreamFinished: root._logStderr = text }

    onExited: function(exitCode) {
      root.logLoading = false
      var out = String(logStdout.text || root._logStdout || "")
      var err = String(logStderr.text || root._logStderr || "").trim()
      if (exitCode === 0) {
        root.logError = ""
        root.logText = out.trim() !== "" ? out : "(no log output yet)"
      } else {
        root.logError = err !== "" ? err : "Failed to read container logs"
      }
    }
  }

  Process {
    id: probeProcess
    running: false
    command: []
    stdout: StdioCollector { id: probeStdout; waitForEnd: true; onStreamFinished: root._probeStdout = text }

    onExited: function(exitCode) {
      var out = String(probeStdout.text || root._probeStdout || "").trim()
      if (exitCode === 0 && out !== "") {
        try {
          var res = JSON.parse(out)
          if (res && res.port) {
            var next = ({})
            for (var k in root.probeCache) next[k] = root.probeCache[k]
            next[String(res.port)] = res
            root.probeCache = next
            root.showToast(":" + res.port + " → " + res.status + " (" + Number(res.ms || 0).toFixed(1) + " ms)", res.ok !== true)
          }
        } catch (e) {}
      }
    }
  }

  Process {
    id: notifyProcess
    running: false
    command: []
  }

  Process {
    id: setupCopyProcess
    running: false
    command: []
    onExited: function(exitCode) {
      if (exitCode === 0) root.showToast("Copied install command to clipboard", false)
    }
  }

  Process {
    id: rdnsProcess
    running: false
    command: []
    stdout: StdioCollector { id: rdnsStdout; waitForEnd: true; onStreamFinished: root._rdnsStdout = text }

    onExited: function(exitCode) {
      var ip = root._rdnsIp
      var out = String(rdnsStdout.text || root._rdnsStdout || "").trim()
      if (ip !== "" && exitCode === 0 && out !== "") {
        var next = ({})
        for (var k in root.rdnsCache) next[k] = root.rdnsCache[k]
        next[ip] = out
        root.rdnsCache = next
        root.showToast(ip + " → " + out, false)
      }
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: StdioCollector { id: actionStdout; waitForEnd: true; onStreamFinished: root._actionStdout = text }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true; onStreamFinished: root._actionStderr = text }

    onExited: function(exitCode) {
      var out = String(actionStdout.text || root._actionStdout || "").trim()
      var err = String(actionStderr.text || root._actionStderr || "").trim()
      if (exitCode === 0) {
        root.showToast(out !== "" ? out : root._actionLabel, false)
      } else {
        root.showToast(err !== "" ? err : (out !== "" ? out : "Action failed"), true)
      }
      if (root._actionNeedsRefresh) {
        root.refresh()
        settleTimer.restart()
      }
    }
  }
}
