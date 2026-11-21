import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "io.github.pradeepjung45.devdock"
  ipcTarget: "io.github.pradeepjung45.devdock"
  manageIpc: false

  readonly property Item panelFlick: panel.loadedContent ? panel.loadedContent.panelFlick : null
  readonly property Item searchField: panel.loadedContent ? panel.loadedContent.searchField : null

  property string activeTab: "ports" // "ports" | "containers" | "netsec" | "infra" | "arch"
  property string searchQuery: ""
  property bool showSystemPorts: root.setting("showSystemPorts", false) === true
  property bool showSecurityChecks: true
  property string expandedTrafficKey: ""
  property string expandedArchLayer: "workloads" // "hw" | "kernel" | "init" | "session" | "fabrics" | "workloads" | ""
  property string armedKillKey: ""
  property bool showPalettePicker: false
  property string colorSchemeOverride: ""

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color accent: Commons.Color.accent
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // Live Omarchy theme-synced + user-selectable semantic palette
  readonly property string activeColorScheme: colorSchemeOverride !== ""
    ? colorSchemeOverride
    : String(root.setting("colorScheme", "Auto") || "Auto")
  readonly property var _pal: Model.resolvePalette(
    activeColorScheme,
    (devdock.host && devdock.host.palette) ? devdock.host.palette : ({})
  )
  readonly property color okColor: (_pal.green && _pal.green !== "") ? _pal.green : root.accent
  readonly property color warnColor: (_pal.amber && _pal.amber !== "") ? _pal.amber : root.accent
  readonly property color infoColor: (_pal.blue && _pal.blue !== "") ? _pal.blue : root.accent
  readonly property color purpleColor: (_pal.purple && _pal.purple !== "") ? _pal.purple : root.accent
  readonly property color cyanColor: (_pal.cyan && _pal.cyan !== "") ? _pal.cyan : root.accent
  readonly property color dangerColor: (_pal.red && _pal.red !== "") ? _pal.red : root.urgent

  readonly property bool barIsUrgent: Model.barUrgent(devdock.summary)
  readonly property bool barIsActive: Model.barActive(devdock.summary)
  readonly property string barBadgeText: Model.barLabel(devdock.summary, devdock.binaryMissing)
  readonly property color barAccentColor: barIsUrgent
    ? root.urgent
    : (barIsActive ? root.accent : root.barForeground)
  readonly property var hostScreen: button.QsWindow.window ? button.QsWindow.window.screen : null
  readonly property bool isFocusedMonitor: !hostScreen || !Hyprland.focusedMonitor
    || String(hostScreen.name) === String(Hyprland.focusedMonitor.name)

  readonly property var webPorts: Model.filterPorts(devdock.ports, "web", searchQuery)
  readonly property var dataPorts: Model.filterPorts(devdock.ports, "data", searchQuery)
  readonly property var systemPorts: Model.filterPorts(devdock.ports, "system", searchQuery)
  readonly property var filteredTunnels: Model.filterTunnels(devdock.tunnels, searchQuery)
  readonly property var filteredContainers: Model.filterContainers(devdock.containers.items, searchQuery)
  readonly property var composeStacksList: Model.composeStacks(devdock.containers.items)
  readonly property var filteredTrafficGroups: Model.filterTrafficGroups(devdock.traffic.groups, searchQuery)
  readonly property var filteredSecurityChecks: Model.filterSecurityChecks(devdock.security.checks, searchQuery)
  readonly property var filteredContexts: Model.filterContexts(devdock.kube.contexts, searchQuery)
  readonly property var filteredDaemons: Model.filterDaemons(devdock.services.daemons, searchQuery)

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: {
    if (opened) {
      armedKillKey = ""
      if (panelFlick) panelFlick.contentY = 0
      devdock.refresh()
      Qt.callLater(function() { if (panel.loadedContent) panel.loadedContent.forceActiveFocus() })
    } else if (searchQuery !== "") {
      searchQuery = ""
      if (searchField) searchField.text = ""
    }
  }

  function armOrKillPort(pid, port) {
    var key = String(pid) + ":" + String(port)
    if (armedKillKey === key) {
      armedKillKey = ""
      killArmTimer.stop()
      devdock.killPort(pid, port)
    } else {
      armedKillKey = key
      killArmTimer.restart()
      devdock.stopPort(pid, port)
    }
  }

  function focusPortWindow(pid) {
    devdock.focusPid(pid)
    root.close()
  }

  function persistSettings(values) {
    var entry = { id: root.moduleName }
    if (root.settings) {
      for (var existing in root.settings) {
        if (existing !== "id") entry[existing] = root.settings[existing]
      }
    }
    for (var key in values) entry[key] = values[key]
    root.settings = entry
    if (root.bar && root.bar.shell && typeof root.bar.shell.updateEntryInline === "function") {
      root.bar.shell.updateEntryInline(root.moduleName, entry)
    }
  }

  function selectColorScheme(name) {
    var scheme = String(name || "Auto")
    root.colorSchemeOverride = scheme
    persistSettings({ colorScheme: scheme })
  }

  Timer {
    id: killArmTimer
    interval: 4500
    repeat: false
    onTriggered: root.armedKillKey = ""
  }

  Service {
    id: devdock
    settings: root.settings
    panelOpen: root.opened
  }

  ShellIpc {
    enabled: root.isFocusedMonitor
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function openTab(name: string): string {
      var t = String(name || "").toLowerCase()
      if (t === "ports" || t === "containers" || t === "netsec" || t === "infra" || t === "arch") {
        root.activeTab = t
        root.open()
        return t
      }
      return "invalid"
    }
    function refresh(): string { devdock.refresh(); return "ok" }
    function status(): string { return devdock.statusText }
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    labelVisible: false
    hasVisualContent: true
    tooltipText: Model.barTooltip(devdock.summary, devdock.host, devdock.binaryMissing)
    fixedWidth: vertical ? -1 : Math.max(Style.bar.iconSlot, pillRow.implicitWidth + Style.space(12))
    fixedHeight: vertical ? Style.bar.iconSlot : -1

    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) devdock.refresh()
      else root.toggle()
    }

    Row {
      id: pillRow
      anchors.centerIn: parent
      spacing: Style.space(5)
      scale: button.pressScale

      DevDockIcon {
        iconSize: Math.round(Style.bar.iconSize)
        strokeColor: root.barForeground
        accentColor: root.okColor
        urgentColor: root.dangerColor
        active: root.barIsActive
        urgent: root.barIsUrgent
        anchors.verticalCenter: parent.verticalCenter
      }

      Text {
        textFormat: Text.PlainText
        visible: !button.vertical && root.barBadgeText !== ""
        text: root.barBadgeText
        color: root.barIsUrgent ? root.urgent : root.barForeground
        font.family: button.fontFamily
        font.pixelSize: Style.font.bodySmall
        font.bold: root.barIsUrgent
        anchors.verticalCenter: parent.verticalCenter
        renderType: Text.NativeRendering
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(496))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(640))

    content: PanelKeyCatcher {
      id: keyCatcher
      property alias panelFlick: panelFlick
      property alias searchField: searchField
      implicitHeight: mainColumn.implicitHeight
      anchors.fill: parent

      onCloseRequested: {
        if (root.showPalettePicker) {
          root.showPalettePicker = false
        } else if (devdock.logContainerId !== "") {
          devdock.closeInlineLogs()
        } else if (root.searchQuery !== "") {
          root.searchQuery = ""
          searchField.text = ""
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (searchField.activeFocus) return
        if (t === "r" || t === "R") devdock.refresh()
        else if (t === "t" || t === "T") root.showPalettePicker = !root.showPalettePicker
        else if (t === "/") searchField.forceActiveFocus()
        else if (t === "1") root.activeTab = "ports"
        else if (t === "2") root.activeTab = "containers"
        else if (t === "3") root.activeTab = "netsec"
        else if (t === "4") root.activeTab = "infra"
        else if (t === "5") root.activeTab = "arch"
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: mainColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: mainColumn
          width: panelFlick.width
          spacing: Style.space(10)

          // ── Header + Host Vitals HUD ────────────────────────────────────
          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            DevDockIcon {
              iconSize: Style.space(22)
              strokeColor: root.foreground
              accentColor: root.okColor
              urgentColor: root.dangerColor
              active: root.barIsActive
              urgent: root.barIsUrgent
              Layout.alignment: Qt.AlignVCenter
            }

            ColumnLayout {
              Layout.fillWidth: true
              spacing: Style.space(1)

              RowLayout {
                Layout.fillWidth: true
                spacing: Style.space(6)

                Text {
                  textFormat: Text.PlainText
                  text: "DevDock"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.title
                  font.bold: true
                }

                PillBadge {
                  visible: devdock.host.hostname !== ""
                  label: devdock.host.hostname
                  badgeColor: root.purpleColor
                }

                Item { Layout.fillWidth: true }
              }

              Text {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                visible: !devdock.binaryMissing
                text: "Load " + Number(devdock.host.load1m || 0).toFixed(2)
                  + " · RAM " + Number(devdock.host.memUsedGb || 0).toFixed(1) + "/" + Number(devdock.host.memTotalGb || 0).toFixed(0) + "G (" + Number(devdock.host.memPct || 0) + "%)"
                  + " · Disk " + Number(devdock.host.diskPct || 0) + "%"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideRight
              }
            }

            PanelActionButton {
              iconText: "󰏘"
              tooltipText: "Color palette: " + root.activeColorScheme + " (t)"
              foreground: root.showPalettePicker ? root.purpleColor : root.foreground
              hoverColor: root.purpleColor
              fontFamily: root.fontFamily
              onClicked: root.showPalettePicker = !root.showPalettePicker
            }

            PanelActionButton {
              iconText: "󰑐"
              tooltipText: "Refresh (r)"
              foreground: root.foreground
              fontFamily: root.fontFamily
              enabled: !devdock.refreshing
              onClicked: devdock.binaryMissing ? devdock.retryProbe() : devdock.refresh()
            }
          }

          // ── Color Palette Picker Drawer ─────────────────────────────────
          BorderSurface {
            visible: root.showPalettePicker
            width: parent.width
            implicitHeight: palCol.implicitHeight + Style.space(14)
            radius: Style.cornerRadius
            color: Util.alpha(root.purpleColor, 0.08)
            borderSpec: Border.controlSpec("selected", Util.alpha(root.purpleColor, 0.55), root.purpleColor)

            Column {
              id: palCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.margins: Style.space(8)
              spacing: Style.space(6)

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                Text {
                  textFormat: Text.PlainText
                  text: "󰏘 COLOR PALETTE"
                  color: root.purpleColor
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Item { Layout.fillWidth: true }

                Text {
                  textFormat: Text.PlainText
                  text: Model.schemeMeta(root.activeColorScheme).label + " · " + Model.schemeMeta(root.activeColorScheme).desc
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }

              Flow {
                width: parent.width
                spacing: Style.space(5)

                Repeater {
                  model: Model.COLOR_SCHEMES
                  BorderSurface {
                    id: swatchBtn
                    required property var modelData
                    readonly property bool selected: root.activeColorScheme === modelData.id
                    readonly property var previewPal: modelData.id === "Auto"
                      ? Model.resolvePalette("Auto", (devdock.host && devdock.host.palette) ? devdock.host.palette : ({}))
                      : modelData
                    implicitWidth: swatchRow.implicitWidth + Style.space(12)
                    implicitHeight: swatchRow.implicitHeight + Style.space(8)
                    radius: Style.cornerRadius
                    color: swatchBtn.selected
                      ? Util.alpha(root.purpleColor, 0.22)
                      : (swatchMouse.containsMouse ? Style.hoverFillFor(root.foreground, root.accent) : Util.alpha(Commons.Color.background, 0.45))
                    borderSpec: swatchBtn.selected
                      ? Border.controlSpec("selected", root.purpleColor, root.purpleColor)
                      : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.purpleColor)

                    Row {
                      id: swatchRow
                      anchors.centerIn: parent
                      spacing: Style.space(4)

                      Row {
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.space(2)

                        Rectangle {
                          width: Style.space(6); height: Style.space(6); radius: Style.space(3)
                          color: swatchBtn.previewPal.green !== "" ? swatchBtn.previewPal.green : root.accent
                        }
                        Rectangle {
                          width: Style.space(6); height: Style.space(6); radius: Style.space(3)
                          color: swatchBtn.previewPal.cyan !== "" ? swatchBtn.previewPal.cyan : root.foreground
                        }
                        Rectangle {
                          width: Style.space(6); height: Style.space(6); radius: Style.space(3)
                          color: swatchBtn.previewPal.purple !== "" ? swatchBtn.previewPal.purple : root.dim
                        }
                        Rectangle {
                          width: Style.space(6); height: Style.space(6); radius: Style.space(3)
                          color: swatchBtn.previewPal.amber !== "" ? swatchBtn.previewPal.amber : root.urgent
                        }
                      }

                      Text {
                        textFormat: Text.PlainText
                        text: swatchBtn.modelData.label
                        color: swatchBtn.selected ? root.foreground : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: swatchBtn.selected
                      }
                    }

                    MouseArea {
                      id: swatchMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.selectColorScheme(swatchBtn.modelData.id)
                    }
                  }
                }
              }
            }
          }

          // Clickable LAN / Tailscale IP + AWS quick pills
          Flow {
            visible: !devdock.binaryMissing && (devdock.host.lanIp !== "" || devdock.host.tailscaleIp !== "" || devdock.kube.awsProfile !== "")
            width: parent.width
            spacing: Style.space(6)

            CopyChip {
              visible: devdock.host.lanIp !== ""
              label: "LAN " + devdock.host.lanIp
              chipColor: root.cyanColor
              onClicked: devdock.copyText(devdock.host.lanIp, devdock.host.lanIp)
            }

            CopyChip {
              visible: devdock.host.tailscaleIp !== ""
              label: "TS " + devdock.host.tailscaleIp
              chipColor: root.okColor
              onClicked: devdock.copyText(devdock.host.tailscaleIp, devdock.host.tailscaleIp)
            }

            CopyChip {
              visible: devdock.kube.awsProfile !== ""
              label: "AWS " + devdock.kube.awsProfile
              chipColor: root.warnColor
              onClicked: devdock.copyText(devdock.kube.awsProfile, "AWS_PROFILE")
            }
          }

          // ── Persistent PROD K8s Safety Banner ───────────────────────────
          BorderSurface {
            visible: !devdock.binaryMissing && devdock.kube.currentIsProd === true
            width: parent.width
            implicitHeight: prodRow.implicitHeight + Style.space(12)
            radius: Style.cornerRadius
            color: Util.alpha(root.urgent, 0.16)
            borderSpec: Border.controlSpec("focus", root.urgent, root.urgent)

            RowLayout {
              id: prodRow
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                text: "󰀪"
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.heading
              }

              ColumnLayout {
                Layout.fillWidth: true
                spacing: Style.space(1)

                Text {
                  textFormat: Text.PlainText
                  Layout.fillWidth: true
                  text: "PRODUCTION K8S CONTEXT ACTIVE"
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Text {
                  textFormat: Text.PlainText
                  Layout.fillWidth: true
                  text: devdock.kube.currentContext + "  (ns: " + devdock.kube.currentNamespace + ")"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  elide: Text.ElideRight
                }
              }

              ActionPill {
                label: "Switch"
                tintColor: root.urgent
                onClicked: root.activeTab = "infra"
              }
            }
          }

          // ── Binary Missing Setup Card ───────────────────────────────────
          BorderSurface {
            visible: devdock.binaryMissing
            width: parent.width
            implicitHeight: missingCol.implicitHeight + Style.space(20)
            radius: Style.cornerRadius
            color: Style.hoverFillFor(root.foreground, root.accent)
            borderSpec: Border.controlSpec("normal", root.foreground, root.accent)

            Column {
              id: missingCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.margins: Style.space(12)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "DevDock Rust backend needs local build"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: (devdock.binaryStatusDetail !== "" ? (devdock.binaryStatusDetail + "\n\n") : "Build the zero-dependency Rust backend locally from this plugin's audited source:\n\n") + "  " + devdock.setupCommand
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              Row {
                spacing: Style.space(6)

                ActionPill {
                  label: "Copy command"
                  tintColor: root.accent
                  onClicked: devdock.copySetupCommand()
                }

                ActionPill {
                  label: "Retry detection"
                  tintColor: root.foreground
                  onClicked: devdock.retryProbe()
                }
              }
            }
          }

          // ── Search + Tabs (only when backend is ready) ──────────────────
          TextField {
            id: searchField
            visible: !devdock.binaryMissing
            width: parent.width
            foreground: root.foreground
            placeholderText: "Filter port, project, branch, container, service… (/)"
            onTextChanged: root.searchQuery = text
            Keys.onEscapePressed: {
              if (text !== "") {
                text = ""
                keyCatcher.forceActiveFocus()
              } else {
                root.close()
              }
            }
          }

          RowLayout {
            visible: !devdock.binaryMissing
            width: parent.width
            spacing: Style.space(4)

            TabButtonPill {
              Layout.fillWidth: true
              label: "Ports"
              badge: String(Number(devdock.summary.devPorts || 0) + Number(devdock.summary.tunnels || 0))
              active: root.activeTab === "ports"
              tabColor: root.infoColor
              urgentBadge: false
              onClicked: root.activeTab = "ports"
            }

            TabButtonPill {
              Layout.fillWidth: true
              label: "Docker"
              badge: devdock.containers.available
                ? (devdock.containers.runningCount + "/" + devdock.containers.items.length)
                : "-"
              active: root.activeTab === "containers"
              tabColor: root.cyanColor
              urgentBadge: false
              onClicked: root.activeTab = "containers"
            }

            TabButtonPill {
              Layout.fillWidth: true
              label: "Net"
              badge: devdock.security.criticalCount > 0
                ? ("!" + devdock.security.criticalCount)
                : String(devdock.traffic.internetConns || 0)
              active: root.activeTab === "netsec"
              tabColor: root.okColor
              urgentBadge: devdock.security.criticalCount > 0
              onClicked: root.activeTab = "netsec"
            }

            TabButtonPill {
              Layout.fillWidth: true
              label: "Infra"
              badge: devdock.kube.currentIsProd
                ? "PROD"
                : (devdock.services.failedCount > 0
                  ? ("!" + devdock.services.failedCount)
                  : String(devdock.services.daemons.length))
              active: root.activeTab === "infra"
              tabColor: root.warnColor
              urgentBadge: devdock.kube.currentIsProd === true || devdock.services.failedCount > 0
              onClicked: root.activeTab = "infra"
            }

            TabButtonPill {
              Layout.fillWidth: true
              label: "Arch"
              badge: "OS"
              active: root.activeTab === "arch"
              tabColor: root.purpleColor
              urgentBadge: false
              onClicked: root.activeTab = "arch"
            }
          }

          PanelSeparator {
            visible: !devdock.binaryMissing
            foreground: root.foreground
          }

          // ════════════════════════════════════════════════════════════════
          // TAB 1: PORTS & TUNNELS
          // ════════════════════════════════════════════════════════════════
          Column {
            visible: !devdock.binaryMissing && root.activeTab === "ports"
            width: parent.width
            spacing: Style.space(10)

            // Active Tunnels (SSH & kubectl port-forward)
            Column {
              visible: root.filteredTunnels.length > 0
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "ACTIVE TUNNELS (" + root.filteredTunnels.length + ")"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Repeater {
                model: root.filteredTunnels
                TunnelRow {
                  required property var modelData
                  width: parent.width
                  tunnel: modelData
                }
              }
            }

            // Web & Dev Servers
            Column {
              visible: root.webPorts.length > 0
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "DEV SERVERS (" + root.webPorts.length + ")"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Repeater {
                model: root.webPorts
                PortRow {
                  required property var modelData
                  width: parent.width
                  item: modelData
                }
              }
            }

            // Databases, Brokers & Local AI
            Column {
              visible: root.dataPorts.length > 0
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "DATA, BROKERS & AI (" + root.dataPorts.length + ")"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Repeater {
                model: root.dataPorts
                PortRow {
                  required property var modelData
                  width: parent.width
                  item: modelData
                }
              }
            }

            // Clean empty state when no dev servers/tunnels match
            Text {
              textFormat: Text.PlainText
              visible: root.webPorts.length === 0 && root.dataPorts.length === 0 && root.filteredTunnels.length === 0
              width: parent.width
              text: root.searchQuery !== ""
                ? ("No dev ports match '" + root.searchQuery + "'")
                : "No local dev servers or tunnels listening right now.\nStart Next.js, Vite, FastAPI, Spring, Kafka, or an SSH tunnel and it appears here live."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              horizontalAlignment: Text.AlignHCenter
              wrapMode: Text.WordWrap
              topPadding: Style.space(10)
              bottomPadding: Style.space(6)
            }

            // Collapsible Background & System Ports Drawer
            Column {
              visible: root.systemPorts.length > 0
              width: parent.width
              spacing: Style.space(6)

              CursorSurface {
                width: parent.width
                implicitHeight: sysToggleRow.implicitHeight + Style.space(10)
                foreground: root.foreground

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.showSystemPorts = !root.showSystemPorts
                }

                RowLayout {
                  id: sysToggleRow
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.leftMargin: Style.space(8)
                  anchors.rightMargin: Style.space(8)

                  Text {
                    textFormat: Text.PlainText
                    text: (root.showSystemPorts ? "▾ " : "▸ ") + "Background, IDE & System (" + root.systemPorts.length + ")"
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }

                  Item { Layout.fillWidth: true }
                }
              }

              Column {
                visible: root.showSystemPorts || root.searchQuery !== ""
                width: parent.width
                spacing: Style.space(5)

                Repeater {
                  model: (root.showSystemPorts || root.searchQuery !== "") ? root.systemPorts : []
                  PortRow {
                    required property var modelData
                    width: parent.width
                    item: modelData
                  }
                }
              }
            }
          }

          // ════════════════════════════════════════════════════════════════
          // TAB 2: CONTAINERS (DOCKER / PODMAN)
          // ════════════════════════════════════════════════════════════════
          Column {
            visible: !devdock.binaryMissing && root.activeTab === "containers"
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              visible: devdock.containers.available
              text: (devdock.containers.engine || "CONTAINERS").toUpperCase()
                + " · " + devdock.containers.runningCount + " RUNNING / " + devdock.containers.items.length + " TOTAL"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            // Docker Compose Stack 1-Click Group Controls
            Column {
              visible: devdock.containers.available && root.composeStacksList.length > 0 && root.searchQuery === ""
              width: parent.width
              spacing: Style.space(4)

              Repeater {
                model: root.activeTab === "containers" ? root.composeStacksList : []
                BorderSurface {
                  required property var modelData
                  width: parent.width
                  implicitHeight: stackRow.implicitHeight + Style.space(10)
                  radius: Style.cornerRadius
                  color: Util.alpha(root.purpleColor, 0.10)
                  borderSpec: Border.controlSpec("normal", root.purpleColor, root.purpleColor)

                  RowLayout {
                    id: stackRow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.leftMargin: Style.space(8)
                    anchors.rightMargin: Style.space(6)
                    spacing: Style.space(6)

                    Text {
                      textFormat: Text.PlainText
                      text: "󰡨 " + modelData.project
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                      Layout.fillWidth: true
                      elide: Text.ElideRight
                    }

                    PillBadge {
                      label: modelData.running + "/" + modelData.total + " up"
                      badgeColor: modelData.running === modelData.total
                        ? root.okColor
                        : (modelData.running > 0 ? root.warnColor : root.dim)
                    }

                    ActionPill {
                      visible: modelData.startIds && modelData.startIds.length > 0
                      label: "Start Stack"
                      tintColor: root.okColor
                      onClicked: devdock.composeStackAction("start", modelData.project, modelData.startIds)
                    }

                    ActionPill {
                      visible: modelData.stopIds && modelData.stopIds.length > 0
                      label: "Stop Stack"
                      tintColor: root.dangerColor
                      onClicked: devdock.composeStackAction("stop", modelData.project, modelData.stopIds)
                    }
                  }
                }
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: !devdock.containers.available
              width: parent.width
              text: "Docker / Podman daemon is not running or socket is unavailable."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              horizontalAlignment: Text.AlignHCenter
              wrapMode: Text.WordWrap
              topPadding: Style.space(12)
            }

            Text {
              textFormat: Text.PlainText
              visible: devdock.containers.available && root.filteredContainers.length === 0
              width: parent.width
              text: root.searchQuery !== ""
                ? ("No containers match '" + root.searchQuery + "'")
                : "No containers found."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              horizontalAlignment: Text.AlignHCenter
              topPadding: Style.space(10)
            }

            Repeater {
              model: root.activeTab === "containers" ? root.filteredContainers : []
              ContainerRow {
                required property var modelData
                width: parent.width
                ctr: modelData
              }
            }

            // Instant Inline Container Log Drawer (direct Unix-socket tail, ~2ms)
            BorderSurface {
              id: inlineLogCard
              visible: devdock.logContainerId !== ""
              width: parent.width
              implicitHeight: logDrawerCol.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.foreground, root.accent)
              borderSpec: Border.controlSpec("selected", root.foreground, root.accent)

              Column {
                id: logDrawerCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(8)
                spacing: Style.space(6)

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    text: "󰈙 " + devdock.logContainerName
                    color: root.cyanColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                  }

                  ActionPill {
                    label: devdock.logAutoRefresh ? "Live ●" : "Paused"
                    tintColor: devdock.logAutoRefresh ? root.okColor : root.warnColor
                    onClicked: devdock.logAutoRefresh = !devdock.logAutoRefresh
                  }

                  PanelActionButton {
                    iconText: "󰑐"
                    tooltipText: "Refresh logs"
                    foreground: root.foreground
                    hoverColor: root.accent
                    fontFamily: root.fontFamily
                    onClicked: devdock.fetchInlineLogs()
                  }

                  PanelActionButton {
                    iconText: "󰆏"
                    tooltipText: "Copy logs"
                    foreground: root.foreground
                    hoverColor: root.accent
                    fontFamily: root.fontFamily
                    onClicked: devdock.copyContainerLogs(devdock.logContainerId, devdock.logContainerName)
                  }

                  PanelActionButton {
                    iconText: "󰆍"
                    tooltipText: "Pop out live logs in terminal"
                    foreground: root.foreground
                    hoverColor: root.accent
                    fontFamily: root.fontFamily
                    onClicked: {
                      devdock.containerAction("logs", devdock.logContainerId, devdock.logContainerName)
                      root.close()
                    }
                  }

                  PanelActionButton {
                    iconText: "󰅖"
                    tooltipText: "Close log viewer (Esc)"
                    foreground: root.foreground
                    hoverColor: root.urgent
                    fontFamily: root.fontFamily
                    onClicked: devdock.closeInlineLogs()
                  }
                }

                BorderSurface {
                  width: parent.width
                  height: Style.space(185)
                  radius: Style.cornerRadius
                  color: Util.alpha(Commons.Color.background, 0.55)
                  borderSpec: Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.accent)

                  Flickable {
                    id: logFlick
                    anchors.fill: parent
                    anchors.margins: Style.space(6)
                    contentWidth: width
                    contentHeight: logBody.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    flickableDirection: Flickable.VerticalFlick
                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                    function scrollToBottom() {
                      Qt.callLater(function() {
                        if (logFlick.contentHeight > logFlick.height) {
                          logFlick.contentY = logFlick.contentHeight - logFlick.height
                        }
                      })
                    }

                    Text {
                      id: logBody
                      textFormat: Text.PlainText
                      width: logFlick.width
                      text: devdock.logError !== ""
                        ? ("Error: " + devdock.logError)
                        : (devdock.logText !== "" ? devdock.logText : "Loading logs…")
                      color: devdock.logError !== "" ? root.urgent : root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Math.max(10, Style.font.caption - 1)
                      wrapMode: Text.WrapAnywhere
                      onTextChanged: logFlick.scrollToBottom()
                    }
                  }
                }
              }
            }
          }

          // ════════════════════════════════════════════════════════════════
          // TAB 3: LIVE INTERNET TRAFFIC & OS SECURITY RADAR
          // ════════════════════════════════════════════════════════════════
          Column {
            visible: !devdock.binaryMissing && root.activeTab === "netsec"
            width: parent.width
            spacing: Style.space(10)

            // Live Bandwidth & Connection Summary Card
            BorderSurface {
              width: parent.width
              implicitHeight: netHudCol.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.foreground, root.accent)
              borderSpec: Border.controlSpec("normal", Qt.darker(root.foreground, 2.0), root.accent)

              Column {
                id: netHudCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(8)
                spacing: Style.space(6)

                RowLayout {
                  width: parent.width
                  spacing: Style.space(8)

                  Text {
                    textFormat: Text.PlainText
                    text: "↓ " + Model.formatRate(devdock.rxRateBps)
                    color: root.cyanColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: "↑ " + Model.formatRate(devdock.txRateBps)
                    color: root.purpleColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                  }

                  Item { Layout.fillWidth: true }

                  Text {
                    textFormat: Text.PlainText
                    text: (devdock.traffic.internetConns || 0) + " net · "
                      + (devdock.traffic.lanConns || 0) + " LAN · "
                      + (devdock.traffic.inboundConns || 0) + " in"
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                Flow {
                  visible: devdock.traffic.ifaces && devdock.traffic.ifaces.length > 0
                  width: parent.width
                  spacing: Style.space(5)

                  Repeater {
                    model: root.activeTab === "netsec" ? devdock.traffic.ifaces : []
                    PillBadge {
                      required property var modelData
                      visible: modelData.rxBytes > 0 || modelData.txBytes > 0 || modelData.kind === "wifi" || modelData.kind === "vpn"
                      label: modelData.name + " ↓" + Model.formatBytes(modelData.rxBytes) + " ↑" + Model.formatBytes(modelData.txBytes)
                      badgeColor: modelData.kind === "wifi" || modelData.kind === "eth"
                        ? root.okColor
                        : (modelData.kind === "vpn"
                          ? root.purpleColor
                          : (modelData.kind === "docker" ? root.infoColor : root.dim))
                    }
                  }
                }
              }
            }

            // Critical Runtime Traffic Alert Banner (deleted / /tmp binary calling internet)
            BorderSurface {
              visible: devdock.traffic.criticalAlerts && devdock.traffic.criticalAlerts.length > 0
              width: parent.width
              implicitHeight: critCol.implicitHeight + Style.space(12)
              radius: Style.cornerRadius
              color: Util.alpha(root.urgent, 0.16)
              borderSpec: Border.controlSpec("focus", root.urgent, root.urgent)

              Column {
                id: critCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(8)
                spacing: Style.space(4)

                Text {
                  textFormat: Text.PlainText
                  text: "󰀪 CRITICAL RUNTIME TRAFFIC ALERT"
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Repeater {
                  model: devdock.traffic.criticalAlerts || []
                  Text {
                    required property var modelData
                    textFormat: Text.PlainText
                    width: parent.width
                    text: String(modelData || "")
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }
              }
            }

            // OS Hardening & Security Posture Section
            Column {
              width: parent.width
              spacing: Style.space(6)

              RowLayout {
                width: parent.width
                spacing: Style.space(6)

                CursorSurface {
                  Layout.fillWidth: true
                  implicitHeight: secHdrRow.implicitHeight + Style.space(8)
                  foreground: root.foreground

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.showSecurityChecks = !root.showSecurityChecks
                  }

                  RowLayout {
                    id: secHdrRow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.leftMargin: Style.space(6)
                    anchors.rightMargin: Style.space(6)
                    spacing: Style.space(6)

                    Text {
                      textFormat: Text.PlainText
                      text: (root.showSecurityChecks ? "▾ " : "▸ ") + "OS SECURITY POSTURE"
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }

                    PillBadge {
                      label: devdock.security.failCount > 0
                        ? (devdock.security.failCount + " FAIL")
                        : (devdock.security.warnCount > 0
                          ? (devdock.security.passCount + "/" + devdock.security.checks.length + " · " + devdock.security.warnCount + " WARN")
                          : (devdock.security.passCount + "/" + devdock.security.checks.length + " PASS"))
                      badgeColor: devdock.security.failCount > 0
                        ? root.dangerColor
                        : (devdock.security.warnCount > 0 ? root.warnColor : root.okColor)
                    }

                    Item { Layout.fillWidth: true }
                  }
                }
              }

              Column {
                visible: root.showSecurityChecks || root.searchQuery !== ""
                width: parent.width
                spacing: Style.space(4)

                Repeater {
                  model: (root.activeTab === "netsec" && (root.showSecurityChecks || root.searchQuery !== "")) ? root.filteredSecurityChecks : []
                  SecurityCheckRow {
                    required property var modelData
                    width: parent.width
                    check: modelData
                  }
                }
              }
            }

            PanelSeparator { foreground: root.foreground }

            // Live Process-Attributed Internet & LAN Connections
            Column {
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "LIVE CONNECTIONS BY PROCESS (" + root.filteredTrafficGroups.length + ")"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Text {
                textFormat: Text.PlainText
                visible: root.filteredTrafficGroups.length === 0
                width: parent.width
                text: root.searchQuery !== ""
                  ? ("No active connections match '" + root.searchQuery + "'")
                  : "No active external TCP connections right now."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                horizontalAlignment: Text.AlignHCenter
                topPadding: Style.space(8)
              }

              Repeater {
                model: root.activeTab === "netsec" ? root.filteredTrafficGroups : []
                TrafficGroupRow {
                  required property var modelData
                  width: parent.width
                  group: modelData
                }
              }
            }
          }

          // ════════════════════════════════════════════════════════════════
          // TAB 4: INFRASTRUCTURE (KUBERNETES + SYSTEMD SERVICES)
          // ════════════════════════════════════════════════════════════════
          Column {
            visible: !devdock.binaryMissing && root.activeTab === "infra"
            width: parent.width
            spacing: Style.space(10)

            // Failed Systemd Units (pinned to top when > 0)
            Column {
              visible: devdock.services.failedUnits.length > 0
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "FAILED UNITS (" + devdock.services.failedUnits.length + ")"
                foreground: root.urgent
                fontFamily: root.fontFamily
              }

              Repeater {
                model: root.activeTab === "infra" ? devdock.services.failedUnits : []
                FailedUnitRow {
                  required property var modelData
                  width: parent.width
                  unitItem: modelData
                }
              }
            }

            // Kubernetes Contexts
            Column {
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: devdock.kube.available
                  ? ("KUBECONFIG CONTEXTS (" + root.filteredContexts.length + ")")
                  : "KUBERNETES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Text {
                textFormat: Text.PlainText
                visible: !devdock.kube.available
                width: parent.width
                text: "No ~/.kube/config contexts found. When present, DevDock displays your active context and guards production clusters in red on the bar."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              Repeater {
                model: (root.activeTab === "infra" && devdock.kube.available) ? root.filteredContexts : []
                KubeContextRow {
                  required property var modelData
                  width: parent.width
                  ctx: modelData
                  isCurrent: String(modelData.name || "") === String(devdock.kube.currentContext || "")
                }
              }
            }

            PanelSeparator { foreground: root.foreground }

            // DevOps Systemd Daemons
            Column {
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "DEVOPS DAEMONS (" + root.filteredDaemons.length + ")"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Text {
                textFormat: Text.PlainText
                visible: root.filteredDaemons.length === 0
                width: parent.width
                text: "No tracked DevOps systemd daemons installed."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                horizontalAlignment: Text.AlignHCenter
                topPadding: Style.space(6)
              }

              Repeater {
                model: root.activeTab === "infra" ? root.filteredDaemons : []
                DaemonRow {
                  required property var modelData
                  width: parent.width
                  daemon: modelData
                }
              }
            }
          }

          // ════════════════════════════════════════════════════════════════
          // TAB 5: INTERACTIVE ARCH LINUX & OMARCHY ARCHITECTURE MAP
          // ════════════════════════════════════════════════════════════════
          Column {
            visible: !devdock.binaryMissing && root.activeTab === "arch"
            width: parent.width
            spacing: Style.space(4)

            // Architecture Overview Banner
            BorderSurface {
              width: parent.width
              implicitHeight: archBannerCol.implicitHeight + Style.space(12)
              radius: Style.cornerRadius
              color: Util.alpha(root.purpleColor, 0.12)
              borderSpec: Border.controlSpec("selected", root.purpleColor, root.cyanColor)

              Column {
                id: archBannerCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(8)
                spacing: Style.space(3)

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    text: "ARCH LINUX · LIVE OS STACK"
                    color: root.cyanColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }

                  Item { Layout.fillWidth: true }

                  Text {
                    textFormat: Text.PlainText
                    text: "up " + Model.formatUptime(devdock.arch.uptimeSec)
                    color: root.okColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  text: (devdock.arch.cpuModel || "CPU") + " (" + devdock.arch.cpuCores + "c) · "
                    + devdock.arch.pacmanPkgCount + " pkgs · "
                    + devdock.arch.modulesCount + " mods · "
                    + devdock.arch.processCount + " procs"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }
            }

            // Layer 1: Silicon & Storage Stack
            ArchLayerCard {
              width: parent.width
              layerId: "hw"
              layerNum: "1"
              layerColor: root.infoColor
              title: "SILICON & STORAGE"
              summary: (devdock.arch.gpuDriver || "gpu") + " · " + (devdock.arch.storageChain || "block")
              badge: devdock.arch.cpuGovernor || ""
              details: [
                { k: "CPU", v: (devdock.arch.cpuModel || "") + " (" + devdock.arch.cpuCores + " threads, " + devdock.arch.cpuGovernor + ")" },
                { k: "GPU", v: "DRM " + (devdock.arch.gpuDriver || "kms") + (devdock.arch.gpuPci !== "" ? (" [PCI " + devdock.arch.gpuPci + "]") : "") },
                { k: "Storage", v: devdock.arch.storageChain || "-" },
                { k: "Subvols", v: (devdock.arch.btrfsSubvols && devdock.arch.btrfsSubvols.length > 0) ? devdock.arch.btrfsSubvols.join("  ") : "standard root" },
                { k: "Swap", v: devdock.arch.swapSummary || "none" }
              ]
            }

            ArchConnector { width: parent.width }

            // Layer 2: Linux Kernel
            ArchLayerCard {
              width: parent.width
              layerId: "kernel"
              layerNum: "2"
              layerColor: root.purpleColor
              title: "LINUX KERNEL"
              summary: (devdock.arch.kernelRelease || "linux") + " · " + (devdock.arch.kernelPreempt || "SMP")
              badge: devdock.arch.tainted ? "TAINTED" : (devdock.arch.modulesCount + " mods")
              urgentBadge: devdock.arch.tainted === true
              details: [
                { k: "Release", v: (devdock.arch.kernelRelease || "") + " (" + (devdock.arch.kernelPreempt || "SMP") + ")" },
                { k: "Modules", v: devdock.arch.modulesCount + " loaded · " + (devdock.arch.tainted ? "Tainted" : "Clean (untainted)") },
                { k: "Kernels", v: (devdock.arch.installedKernels && devdock.arch.installedKernels.length > 0) ? devdock.arch.installedKernels.join(", ") : "-" },
                { k: "LSMs", v: devdock.arch.activeLsms || "-" }
              ]
            }

            ArchConnector { width: parent.width }

            // Layer 3: Init & Cgroup v2
            ArchLayerCard {
              width: parent.width
              layerId: "init"
              layerNum: "3"
              layerColor: root.okColor
              title: "INIT & CGROUP V2"
              summary: (devdock.arch.initComm || "systemd") + " (PID 1) · " + devdock.arch.processCount + " live tasks"
              badge: devdock.services.failedCount > 0 ? ("!" + devdock.services.failedCount + " fail") : "healthy"
              urgentBadge: devdock.services.failedCount > 0
              details: [
                { k: "PID 1", v: (devdock.arch.initComm || "systemd") + " · " + (devdock.arch.cgroupMode || "cgroup v2") },
                { k: "Controllers", v: devdock.arch.cgroupControllers || "-" },
                { k: "Tasks", v: devdock.arch.processCount + " active processes in /proc" },
                { k: "Daemons", v: devdock.services.daemons.length + " tracked · " + devdock.services.failedCount + " failed units" }
              ]
            }

            ArchConnector { width: parent.width }

            // Layer 4: Display, Wayland & Audio Session
            ArchLayerCard {
              width: parent.width
              layerId: "session"
              layerNum: "4"
              layerColor: root.cyanColor
              title: "WAYLAND & OMARCHY"
              summary: (devdock.arch.compositor || "Hyprland") + " (" + Model.formatMem(devdock.arch.compositorMemMb) + ") · " + (devdock.arch.audioEngine || "PipeWire")
              badge: (devdock.arch.displays ? devdock.arch.displays.length : 0) + " disp"
              details: {
                var rows = [
                  { k: "Compositor", v: (devdock.arch.compositor || "Hyprland") + " (" + Model.formatMem(devdock.arch.compositorMemMb) + ") on " + (devdock.arch.waylandDisplay || "wayland") },
                  { k: "Shell", v: "omarchy-shell / Quickshell (" + Model.formatMem(devdock.arch.shellMemMb) + ")" },
                  { k: "Audio", v: devdock.arch.audioEngine || "PipeWire" }
                ]
                var ds = devdock.arch.displays || []
                for (var i = 0; i < ds.length; i++) {
                  rows.push({
                    k: "Display " + (i + 1),
                    v: ds[i].name + "  " + ds[i].mode + (ds[i].focused ? "  [focused]" : "")
                  })
                }
                return rows
              }
            }

            ArchConnector { width: parent.width }

            // Layer 5: Network & Container Fabrics
            ArchLayerCard {
              width: parent.width
              layerId: "fabrics"
              layerNum: "5"
              layerColor: root.warnColor
              title: "NETWORK & CONTAINER FABRICS"
              summary: "NIC → UFW → " + (devdock.containers.available ? (devdock.containers.engine + " bridges") : "host stack")
              badge: (devdock.traffic.ifaces ? devdock.traffic.ifaces.length : 0) + " ifaces"
              details: {
                var rows = [
                  { k: "Flow", v: "Host NIC ↔ UFW ↔ Docker Bridges ↔ Containers & Ports" },
                  { k: "Traffic", v: "↓ " + Model.formatRate(devdock.rxRateBps) + " · ↑ " + Model.formatRate(devdock.txRateBps) + " (" + (devdock.traffic.internetConns || 0) + " internet)" }
                ]
                var ifs = devdock.traffic.ifaces || []
                for (var i = 0; i < Math.min(ifs.length, 5); i++) {
                  rows.push({
                    k: ifs[i].name,
                    v: ifs[i].kind + " · ↓" + Model.formatBytes(ifs[i].rxBytes) + " ↑" + Model.formatBytes(ifs[i].txBytes)
                  })
                }
                return rows
              }
            }

            ArchConnector { width: parent.width }

            // Layer 6: Arch Pacman Ecosystem & Top RAM Workloads
            BorderSurface {
              id: workloadsCard
              readonly property bool isOpen: root.expandedArchLayer === "workloads"
              width: parent.width
              implicitHeight: wlCol.implicitHeight + Style.space(12)
              radius: Style.cornerRadius
              color: isOpen ? Util.alpha(root.purpleColor, 0.11) : "transparent"
              borderSpec: isOpen
                ? Border.controlSpec("selected", root.purpleColor, root.purpleColor)
                : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.purpleColor)

              Column {
                id: wlCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(8)
                spacing: Style.space(6)

                Item {
                  width: parent.width
                  implicitHeight: wlHdr.implicitHeight

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.expandedArchLayer = workloadsCard.isOpen ? "" : "workloads"
                  }

                  RowLayout {
                    id: wlHdr
                    anchors.left: parent.left
                    anchors.right: parent.right
                    spacing: Style.space(6)

                    PillBadge { label: "6"; badgeColor: root.purpleColor }

                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(1)

                      Text {
                        textFormat: Text.PlainText
                        text: (workloadsCard.isOpen ? "▾ " : "▸ ") + "ARCH PACMAN & TOP WORKLOADS"
                        color: root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        text: devdock.arch.pacmanPkgCount + " installed pkgs"
                          + (devdock.arch.lastPacmanSync !== "" ? (" · synced " + devdock.arch.lastPacmanSync) : "")
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Math.max(10, Style.font.caption - 1)
                        elide: Text.ElideRight
                      }
                    }

                    PillBadge {
                      label: "RAM " + Number(devdock.host.memPct || 0) + "%"
                      badgeColor: Number(devdock.host.memPct || 0) >= 85
                        ? root.dangerColor
                        : (Number(devdock.host.memPct || 0) >= 65 ? root.warnColor : root.okColor)
                    }
                  }
                }

                Column {
                  visible: workloadsCard.isOpen
                  width: parent.width
                  spacing: Style.space(5)

                  Repeater {
                    model: (root.activeTab === "arch" && workloadsCard.isOpen) ? (devdock.arch.topProcs || []) : []
                    Column {
                      required property var modelData
                      readonly property real pct: devdock.host.memTotalGb > 0
                        ? Math.min(1.0, (modelData.memMb / 1024.0) / devdock.host.memTotalGb)
                        : 0.1
                      readonly property color barColor: pct > 0.18
                        ? root.dangerColor
                        : (pct > 0.10 ? root.warnColor : (pct > 0.04 ? root.cyanColor : root.okColor))
                      width: parent.width
                      spacing: Style.space(2)

                      RowLayout {
                        width: parent.width
                        spacing: Style.space(6)

                        Text {
                          textFormat: Text.PlainText
                          text: modelData.comm + " (pid " + modelData.pid + ")"
                          color: root.foreground
                          font.family: root.fontFamily
                          font.pixelSize: Math.max(10, Style.font.caption - 1)
                          Layout.fillWidth: true
                          elide: Text.ElideRight
                        }

                        Text {
                          textFormat: Text.PlainText
                          text: Model.formatMem(modelData.memMb)
                          color: parent.parent.barColor
                          font.family: root.fontFamily
                          font.pixelSize: Math.max(10, Style.font.caption - 1)
                          font.bold: true
                        }
                      }

                      Rectangle {
                        width: parent.width
                        height: Style.space(4)
                        radius: Style.space(2)
                        color: Util.alpha(root.foreground, 0.12)

                        Rectangle {
                          width: Math.max(Style.space(8), parent.width * parent.parent.pct)
                          height: parent.height
                          radius: parent.radius
                          color: parent.parent.barColor
                        }
                      }
                    }
                  }
                }
              }
            }
          }

          // ── Action Toast Strip ──────────────────────────────────────────
          BorderSurface {
            visible: devdock.toastText !== ""
            width: parent.width
            implicitHeight: toastLabel.implicitHeight + Style.space(10)
            radius: Style.cornerRadius
            color: devdock.toastIsError
              ? Util.alpha(root.urgent, 0.14)
              : Style.selectedFillFor(root.foreground, root.accent)
            borderSpec: Border.controlSpec(
              "normal",
              devdock.toastIsError ? root.urgent : root.foreground,
              root.accent
            )

            Text {
              id: toastLabel
              textFormat: Text.PlainText
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              text: devdock.toastText
              color: devdock.toastIsError ? root.urgent : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              elide: Text.ElideRight
            }
          }
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // REUSABLE SUB-COMPONENTS
  // ═══════════════════════════════════════════════════════════════════════

  component PillBadge: BorderSurface {
    id: pill
    property string label: ""
    property color badgeColor: root.dim
    implicitWidth: pillText.implicitWidth + Style.space(8)
    implicitHeight: pillText.implicitHeight + Style.space(3)
    radius: Style.cornerRadius
    color: Util.alpha(pill.badgeColor, 0.13)
    borderSpec: Border.controlSpec("normal", Util.alpha(pill.badgeColor, 0.55), pill.badgeColor)

    Text {
      id: pillText
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: pill.label
      color: pill.badgeColor
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  component CopyChip: BorderSurface {
    id: chip
    property string label: ""
    property color chipColor: root.dim
    signal clicked()
    implicitWidth: chipText.implicitWidth + Style.space(10)
    implicitHeight: chipText.implicitHeight + Style.space(5)
    radius: Style.cornerRadius
    color: chipMouse.containsMouse ? Util.alpha(chip.chipColor, 0.20) : Util.alpha(chip.chipColor, 0.09)
    borderSpec: Border.controlSpec(chipMouse.containsMouse ? "hover-cursor" : "normal", Util.alpha(chip.chipColor, 0.50), chip.chipColor)

    Behavior on color { ColorAnimation { duration: Style.duration(80) } }

    Text {
      id: chipText
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: chip.label
      color: chip.chipColor
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }

    MouseArea {
      id: chipMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: chip.clicked()
    }
  }

  component ActionPill: BorderSurface {
    id: apill
    property string label: ""
    property color tintColor: root.accent
    signal clicked()
    implicitWidth: apillText.implicitWidth + Style.space(12)
    implicitHeight: apillText.implicitHeight + Style.space(6)
    radius: Style.cornerRadius
    color: apillMouse.containsMouse ? Util.alpha(tintColor, 0.24) : Util.alpha(tintColor, 0.11)
    borderSpec: Border.controlSpec("normal", Util.alpha(tintColor, 0.65), tintColor)

    Behavior on color { ColorAnimation { duration: Style.duration(80) } }

    Text {
      id: apillText
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: apill.label
      color: apill.tintColor
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }

    MouseArea {
      id: apillMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: apill.clicked()
    }
  }

  component TabButtonPill: BorderSurface {
    id: tabBtn
    property string label: ""
    property string badge: ""
    property bool active: false
    property bool urgentBadge: false
    property color tabColor: root.accent
    signal clicked()

    implicitHeight: tabRow.implicitHeight + Style.space(10)
    radius: Style.cornerRadius
    color: tabBtn.active
      ? Util.alpha(tabBtn.urgentBadge ? root.dangerColor : tabBtn.tabColor, 0.16)
      : (tabMouse.containsMouse ? Style.hoverFillFor(root.foreground, tabBtn.tabColor) : "transparent")
    borderSpec: tabBtn.active
      ? Border.controlSpec("selected", tabBtn.urgentBadge ? root.dangerColor : tabBtn.tabColor, tabBtn.tabColor)
      : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), tabBtn.tabColor)

    Behavior on color { ColorAnimation { duration: Style.duration(80) } }

    Row {
      id: tabRow
      anchors.centerIn: parent
      spacing: Style.space(4)

      Text {
        textFormat: Text.PlainText
        text: tabBtn.label
        color: tabBtn.active ? root.foreground : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: tabBtn.active
      }

      Text {
        textFormat: Text.PlainText
        visible: tabBtn.badge !== ""
        text: tabBtn.badge
        color: tabBtn.urgentBadge ? root.dangerColor : (tabBtn.active ? tabBtn.tabColor : root.dim)
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: tabBtn.urgentBadge || tabBtn.active
      }
    }

    MouseArea {
      id: tabMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: tabBtn.clicked()
    }
  }

  component PortRow: BorderSurface {
    id: prow
    property var item: null
    readonly property string rowKey: item ? (String(item.pid) + ":" + String(item.port)) : ""
    readonly property bool isArmed: root.armedKillKey === rowKey && rowKey !== ""
    readonly property bool isOwned: item && item.owned === true

    implicitHeight: prowLayout.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: prowMouse.containsMouse ? Style.hoverFillFor(root.foreground, root.accent) : "transparent"
    borderSpec: prowMouse.containsMouse
      ? Border.controlSpec("hover-cursor", root.foreground, root.accent)
      : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.accent)

    Behavior on color { ColorAnimation { duration: Style.duration(70) } }

    MouseArea {
      id: prowMouse
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.NoButton
    }

    RowLayout {
      id: prowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(6)
      spacing: Style.space(8)

      // Port pill (category-coded: blue for web servers, purple for data/brokers/AI, dim for system)
      BorderSurface {
        readonly property color portTint: prow.item && prow.item.category === "web"
          ? root.infoColor
          : (prow.item && prow.item.category === "data" ? root.purpleColor : root.dim)
        implicitWidth: Math.max(Style.space(52), portNumText.implicitWidth + Style.space(10))
        implicitHeight: portNumText.implicitHeight + Style.space(6)
        radius: Style.cornerRadius
        color: Util.alpha(portTint, 0.14)
        borderSpec: Border.controlSpec("normal", Util.alpha(portTint, 0.45), portTint)
        Layout.alignment: Qt.AlignVCenter

        Text {
          id: portNumText
          textFormat: Text.PlainText
          anchors.centerIn: parent
          text: ":" + (prow.item ? prow.item.port : "")
          color: parent.portTint
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          font.bold: true
        }
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(2)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(5)

          Text {
            textFormat: Text.PlainText
            Layout.fillWidth: true
            text: Model.portTitle(prow.item)
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            font.bold: true
            elide: Text.ElideRight
          }

          PillBadge {
            visible: prow.item && String(prow.item.gitBranch || "") !== ""
            label: "󰘬 " + (prow.item ? String(prow.item.gitBranch || "") : "")
            badgeColor: root.purpleColor
          }

          PillBadge {
            visible: prow.item && prow.item.exposedLan === true
            label: "LAN"
            badgeColor: root.dangerColor
          }

          PillBadge {
            readonly property var probeRes: prow.item ? devdock.probeFor(prow.item.port) : null
            visible: probeRes !== null
            label: probeRes ? (probeRes.status + " · " + Number(probeRes.ms || 0).toFixed(1) + "ms") : ""
            badgeColor: probeRes && probeRes.ok ? root.okColor : root.dangerColor
          }
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: Model.portSubtitle(prow.item)
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Row {
        spacing: Style.space(2)
        Layout.alignment: Qt.AlignVCenter

        PanelActionButton {
          visible: prow.item && prow.item.port > 0
          iconText: "󰓅"
          tooltipText: "Health / latency probe (:" + (prow.item ? prow.item.port : "") + ")"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.probePort(prow.item.port)
        }

        PanelActionButton {
          visible: prow.item && prow.item.isHttp === true
          iconText: "󰏌"
          tooltipText: "Open " + (prow.item ? prow.item.url : "")
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.openUrl(prow.item.url)
        }

        PanelActionButton {
          visible: prow.item && String(prow.item.url || "") !== ""
          iconText: "󰆏"
          tooltipText: "Copy " + (prow.item ? prow.item.url : "")
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.copyText(prow.item.url, prow.item.url)
        }

        PanelActionButton {
          visible: prow.item && prow.item.exposedLan === true && String(prow.item.lanUrl || "") !== ""
          iconText: "󰖟"
          tooltipText: "Copy LAN " + (prow.item ? prow.item.lanUrl : "")
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.copyText(prow.item.lanUrl, prow.item.lanUrl)
        }

        PanelActionButton {
          visible: prow.item && prow.item.pid > 1 && prow.isOwned
          iconText: "󰆍"
          tooltipText: "Jump to terminal window"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: root.focusPortWindow(prow.item.pid)
        }

        PanelActionButton {
          visible: prow.isOwned
          iconText: prow.isArmed ? "󰚌" : "󰓛"
          tooltipText: prow.isArmed ? "Force Kill (SIGKILL)" : "Stop (SIGTERM)"
          foreground: prow.isArmed ? root.urgent : root.foreground
          hoverColor: root.urgent
          fontFamily: root.fontFamily
          onClicked: root.armOrKillPort(prow.item.pid, prow.item.port)
        }
      }
    }
  }

  component TunnelRow: BorderSurface {
    id: trow
    property var tunnel: null
    readonly property string rowKey: tunnel ? (String(tunnel.pid) + ":" + String(tunnel.localPort)) : ""
    readonly property bool isArmed: root.armedKillKey === rowKey && rowKey !== ""

    implicitHeight: trowLayout.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: Util.alpha(root.cyanColor, 0.10)
    borderSpec: Border.controlSpec("normal", Util.alpha(root.cyanColor, 0.60), root.cyanColor)

    RowLayout {
      id: trowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(6)
      spacing: Style.space(8)

      PillBadge {
        label: (trow.tunnel ? String(trow.tunnel.direction || "L") : "L") + " :" + (trow.tunnel ? trow.tunnel.localPort : "")
        badgeColor: root.cyanColor
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: "⇄ " + (trow.tunnel ? String(trow.tunnel.target || "") : "")
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          font.bold: true
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: "via " + (trow.tunnel ? String(trow.tunnel.via || "") : "") + " · pid " + (trow.tunnel ? trow.tunnel.pid : "")
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Row {
        spacing: Style.space(2)
        Layout.alignment: Qt.AlignVCenter

        PanelActionButton {
          iconText: "󰆏"
          tooltipText: "Copy localhost:" + (trow.tunnel ? trow.tunnel.localPort : "")
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.copyText("localhost:" + trow.tunnel.localPort, "localhost:" + trow.tunnel.localPort)
        }

        PanelActionButton {
          visible: trow.tunnel && trow.tunnel.owned === true
          iconText: "󰆍"
          tooltipText: "Jump to tunnel terminal"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: root.focusPortWindow(trow.tunnel.pid)
        }

        PanelActionButton {
          visible: trow.tunnel && trow.tunnel.owned === true
          iconText: trow.isArmed ? "󰚌" : "󰅖"
          tooltipText: trow.isArmed ? "Force close tunnel (SIGKILL)" : "Close tunnel (SIGTERM)"
          foreground: trow.isArmed ? root.urgent : root.foreground
          hoverColor: root.urgent
          fontFamily: root.fontFamily
          onClicked: root.armOrKillPort(trow.tunnel.pid, trow.tunnel.localPort)
        }
      }
    }
  }

  component ContainerRow: BorderSurface {
    id: crow
    property var ctr: null
    readonly property string ctrId: ctr ? String(ctr.id || "") : ""
    readonly property string pending: devdock.pendingFor(ctrId)
    readonly property bool isPending: pending !== ""
    readonly property bool running: ctr && String(ctr.state || "").toLowerCase() === "running"
    readonly property bool showingLogs: ctrId !== "" && devdock.logContainerId === ctrId

    implicitHeight: crowLayout.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: crow.showingLogs
      ? Style.selectedFillFor(root.foreground, root.accent)
      : (crowMouse.containsMouse ? Style.hoverFillFor(root.foreground, root.accent) : "transparent")
    borderSpec: crow.showingLogs
      ? Border.controlSpec("selected", root.foreground, root.accent)
      : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.accent)

    Behavior on color { ColorAnimation { duration: Style.duration(70) } }

    MouseArea {
      id: crowMouse
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.NoButton
    }

    RowLayout {
      id: crowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(6)
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: crow.isPending ? "◐" : (crow.running ? "●" : "○")
        color: crow.isPending ? root.warnColor : (crow.running ? root.okColor : root.dim)
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        Layout.alignment: Qt.AlignVCenter
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(2)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(6)

          Text {
            textFormat: Text.PlainText
            Layout.fillWidth: true
            text: crow.ctr ? String(crow.ctr.name || "") : ""
            color: (crow.running || crow.isPending) ? root.foreground : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            font.bold: crow.running || crow.isPending
            elide: Text.ElideRight
          }

          PillBadge {
            visible: crow.isPending
            label: crow.pending + "…"
            badgeColor: root.warnColor
          }

          PillBadge {
            visible: !crow.isPending && crow.ctr && crow.ctr.ports && crow.ctr.ports.length > 0
            label: crow.ctr && crow.ctr.ports && crow.ctr.ports.length > 0 ? (":" + crow.ctr.ports.join(" :")) : ""
            badgeColor: crow.running ? root.cyanColor : root.dim
          }
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: (crow.ctr ? String(crow.ctr.image || "") : "")
            + " · "
            + (crow.isPending ? (crow.pending + " via unix socket…") : (crow.ctr ? String(crow.ctr.status || "") : ""))
          color: crow.isPending ? root.warnColor : root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Row {
        spacing: Style.space(2)
        Layout.alignment: Qt.AlignVCenter

        PanelActionButton {
          visible: !crow.running && !crow.isPending
          iconText: "󰐊"
          tooltipText: "Start container (fast socket)"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.containerAction("start", crow.ctr.id, crow.ctr.name)
        }

        PanelActionButton {
          visible: crow.running && !crow.isPending
          iconText: "󰞷"
          tooltipText: "Open interactive shell (exec sh)"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: {
            devdock.containerAction("exec", crow.ctr.id, crow.ctr.name)
            root.close()
          }
        }

        PanelActionButton {
          iconText: "󰈙"
          tooltipText: crow.showingLogs ? "Close inline logs" : "Instant inline logs"
          foreground: crow.showingLogs ? root.accent : root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: {
            if (crow.showingLogs) devdock.closeInlineLogs()
            else devdock.openInlineLogs(crow.ctr.id, crow.ctr.name)
          }
        }

        PanelActionButton {
          iconText: "󰆍"
          tooltipText: "Pop out live logs in terminal"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: {
            devdock.containerAction("logs", crow.ctr.id, crow.ctr.name)
            root.close()
          }
        }

        PanelActionButton {
          visible: crow.running && !crow.isPending
          iconText: "󰜉"
          tooltipText: "Restart container"
          foreground: root.foreground
          hoverColor: root.accent
          fontFamily: root.fontFamily
          onClicked: devdock.containerAction("restart", crow.ctr.id, crow.ctr.name)
        }

        PanelActionButton {
          visible: crow.running && !crow.isPending
          iconText: "󰓛"
          tooltipText: "Stop container"
          foreground: root.foreground
          hoverColor: root.urgent
          fontFamily: root.fontFamily
          onClicked: devdock.containerAction("stop", crow.ctr.id, crow.ctr.name)
        }
      }
    }
  }

  component KubeContextRow: BorderSurface {
    id: krow
    property var ctx: null
    property bool isCurrent: false
    readonly property bool isProd: ctx && ctx.isProd === true

    implicitHeight: krowLayout.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: krow.isCurrent
      ? (krow.isProd ? Util.alpha(root.urgent, 0.16) : Style.selectedFillFor(root.foreground, root.accent))
      : (krowMouse.containsMouse ? Style.hoverFillFor(root.foreground, root.accent) : "transparent")
    borderSpec: krow.isCurrent
      ? Border.controlSpec("selected", krow.isProd ? root.urgent : root.foreground, krow.isProd ? root.urgent : root.accent)
      : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.accent)

    Behavior on color { ColorAnimation { duration: Style.duration(70) } }

    MouseArea {
      id: krowMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: krow.isCurrent ? Qt.ArrowCursor : Qt.PointingHandCursor
      onClicked: {
        if (!krow.isCurrent && krow.ctx && !devdock.busy) {
          devdock.switchKubeContext(krow.ctx.name)
        }
      }
    }

    RowLayout {
      id: krowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: krow.isCurrent ? "󰄬" : "○"
        color: krow.isCurrent ? (krow.isProd ? root.dangerColor : root.okColor) : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(6)

          Text {
            textFormat: Text.PlainText
            Layout.fillWidth: true
            text: krow.ctx ? String(krow.ctx.name || "") : ""
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            font.bold: krow.isCurrent
            elide: Text.ElideRight
          }

          PillBadge {
            visible: krow.isProd
            label: "PROD"
            badgeColor: root.urgent
          }
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: "ns: " + (krow.ctx ? String(krow.ctx.namespace || "default") : "default")
            + (krow.ctx && String(krow.ctx.cluster || "") !== "" ? (" · cluster: " + krow.ctx.cluster) : "")
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }
    }
  }

  component FailedUnitRow: BorderSurface {
    id: frow
    property var unitItem: null

    implicitHeight: frowLayout.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: Util.alpha(root.urgent, 0.14)
    borderSpec: Border.controlSpec("normal", root.urgent, root.urgent)

    RowLayout {
      id: frowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(6)
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: "󰀪"
        color: root.urgent
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: frow.unitItem ? String(frow.unitItem.unit || "") : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          font.bold: true
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: (frow.unitItem && frow.unitItem.isUser ? "user unit" : "system unit")
            + " · " + (frow.unitItem ? String(frow.unitItem.subState || "failed") : "failed")
          color: root.urgent
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }

      PanelActionButton {
        iconText: "󰆍"
        tooltipText: "Open journalctl logs"
        foreground: root.urgent
        hoverColor: root.urgent
        fontFamily: root.fontFamily
        onClicked: {
          devdock.openServiceLogs(frow.unitItem.unit, frow.unitItem.isUser === true)
          root.close()
        }
      }
    }
  }

  component DaemonRow: BorderSurface {
    id: drow
    property var daemon: null
    readonly property bool isActive: daemon && String(daemon.activeState || "") === "active"
    readonly property bool isFailed: daemon && String(daemon.activeState || "") === "failed"

    implicitHeight: drowLayout.implicitHeight + Style.space(10)
    radius: Style.cornerRadius
    color: drowMouse.containsMouse ? Style.hoverFillFor(root.foreground, root.accent) : "transparent"
    borderSpec: Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.accent)

    Behavior on color { ColorAnimation { duration: Style.duration(70) } }

    MouseArea {
      id: drowMouse
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.NoButton
    }

    RowLayout {
      id: drowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(6)
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: drow.isFailed ? "󰀪" : (drow.isActive ? "●" : "○")
        color: drow.isFailed ? root.dangerColor : (drow.isActive ? root.okColor : root.dim)
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: drow.daemon ? String(drow.daemon.label || drow.daemon.unit || "") : ""
          color: drow.isActive ? root.foreground : root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: drow.isActive
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: (drow.daemon ? String(drow.daemon.unit || "") : "")
            + " · " + (drow.daemon ? String(drow.daemon.activeState || "") : "")
            + (drow.daemon && drow.daemon.memMb > 0 ? (" · " + Model.formatMem(drow.daemon.memMb)) : "")
          color: drow.isFailed ? root.urgent : root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      PanelActionButton {
        iconText: "󰆍"
        tooltipText: "Open journalctl logs"
        foreground: root.foreground
        hoverColor: root.accent
        fontFamily: root.fontFamily
        onClicked: {
          devdock.openServiceLogs(drow.daemon.unit, drow.daemon.isUser === true)
          root.close()
        }
      }
    }
  }

  component SecurityCheckRow: BorderSurface {
    id: srow
    property var check: null
    readonly property string st: check ? String(check.status || "pass") : "pass"
    readonly property bool isFail: st === "fail"
    readonly property bool isWarn: st === "warn"

    implicitHeight: srowLayout.implicitHeight + Style.space(8)
    radius: Style.cornerRadius
    color: srow.isFail
      ? Util.alpha(root.dangerColor, 0.14)
      : (srow.isWarn ? Util.alpha(root.warnColor, 0.10) : "transparent")
    borderSpec: srow.isFail
      ? Border.controlSpec("normal", root.dangerColor, root.dangerColor)
      : (srow.isWarn
        ? Border.controlSpec("normal", Util.alpha(root.warnColor, 0.55), root.warnColor)
        : Border.controlSpec("normal", Qt.darker(root.foreground, 2.4), root.okColor))

    RowLayout {
      id: srowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(8)
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: srow.isFail ? "󰀪" : (srow.isWarn ? "▲" : "󰄬")
        color: srow.isFail ? root.dangerColor : (srow.isWarn ? root.warnColor : root.okColor)
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: srow.check ? String(srow.check.label || "") : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: srow.isFail || srow.isWarn
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: srow.check ? String(srow.check.detail || "") : ""
          color: srow.isFail ? root.urgent : root.dim
          font.family: root.fontFamily
          font.pixelSize: Math.max(10, Style.font.caption - 1)
          elide: Text.ElideRight
        }
      }
    }
  }

  component TrafficGroupRow: BorderSurface {
    id: tgrow
    property var group: null
    readonly property string gkey: group ? (String(group.pid || 0) + ":" + String(group.comm || "")) : ""
    readonly property bool expanded: root.expandedTrafficKey === gkey && gkey !== ""
    readonly property string maxRisk: group ? String(group.maxRisk || "safe") : "safe"
    readonly property bool isCritical: maxRisk === "critical"
    readonly property bool isCleartext: maxRisk === "cleartext"

    implicitHeight: tgCol.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: tgrow.isCritical
      ? Util.alpha(root.urgent, 0.14)
      : (tgrow.expanded
        ? Style.selectedFillFor(root.foreground, root.accent)
        : (tgMouse.containsMouse ? Style.hoverFillFor(root.foreground, root.accent) : "transparent"))
    borderSpec: tgrow.isCritical
      ? Border.controlSpec("normal", root.urgent, root.urgent)
      : (tgrow.expanded
        ? Border.controlSpec("selected", root.foreground, root.accent)
        : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), root.accent))

    Behavior on color { ColorAnimation { duration: Style.duration(70) } }

    Column {
      id: tgCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(8)
      anchors.rightMargin: Style.space(8)
      spacing: Style.space(6)

      Item {
        width: parent.width
        implicitHeight: tgHdr.implicitHeight

        MouseArea {
          id: tgMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: root.expandedTrafficKey = tgrow.expanded ? "" : tgrow.gkey
        }

        RowLayout {
          id: tgHdr
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: Style.space(6)

          Text {
            textFormat: Text.PlainText
            text: tgrow.expanded ? "▾" : "▸"
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            textFormat: Text.PlainText
            text: tgrow.group ? String(tgrow.group.comm || "system") : ""
            color: tgrow.isCritical ? root.urgent : root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: true
            Layout.fillWidth: true
            elide: Text.ElideRight
          }

          Text {
            textFormat: Text.PlainText
            visible: tgrow.group && tgrow.group.pid > 0
            text: "pid " + (tgrow.group ? tgrow.group.pid : "")
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          PillBadge {
            visible: tgrow.isCritical
            label: "CRITICAL"
            badgeColor: root.dangerColor
          }

          PillBadge {
            visible: !tgrow.isCritical && tgrow.isCleartext
            label: "CLEAR"
            badgeColor: root.warnColor
          }

          PillBadge {
            visible: tgrow.group && tgrow.group.internetCount > 0
            label: (tgrow.group ? tgrow.group.internetCount : 0) + " net"
            badgeColor: root.cyanColor
          }

          PillBadge {
            visible: tgrow.group && tgrow.group.lanCount > 0
            label: (tgrow.group ? tgrow.group.lanCount : 0) + " LAN"
            badgeColor: root.purpleColor
          }

          PillBadge {
            visible: tgrow.group && tgrow.group.inboundCount > 0
            label: (tgrow.group ? tgrow.group.inboundCount : 0) + " in"
            badgeColor: root.warnColor
          }
        }
      }

      // Expanded individual remote IP:port connections
      Column {
        visible: tgrow.expanded
        width: parent.width
        spacing: Style.space(4)

        RowLayout {
          visible: tgrow.group && (String(tgrow.group.exe || "") !== "" || tgrow.group.owned === true)
          width: parent.width
          spacing: Style.space(4)

          Text {
            textFormat: Text.PlainText
            Layout.fillWidth: true
            text: (tgrow.group && String(tgrow.group.exe || "") !== "") ? ("exe: " + tgrow.group.exe) : ""
            color: tgrow.isCritical ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Math.max(10, Style.font.caption - 1)
            elide: Text.ElideMiddle
          }

          PanelActionButton {
            visible: tgrow.group && tgrow.group.owned === true && tgrow.group.pid > 1
            iconText: "󰆍"
            tooltipText: "Jump to process window"
            foreground: root.foreground
            hoverColor: root.accent
            fontFamily: root.fontFamily
            onClicked: root.focusPortWindow(tgrow.group.pid)
          }

          PanelActionButton {
            visible: tgrow.group && tgrow.group.owned === true && tgrow.group.pid > 1
            iconText: "󰓛"
            tooltipText: "Stop owned process (SIGTERM)"
            foreground: root.foreground
            hoverColor: root.urgent
            fontFamily: root.fontFamily
            onClicked: devdock.stopNetPid(tgrow.group.pid, tgrow.group.comm)
          }
        }

        Repeater {
          model: tgrow.expanded && tgrow.group ? (tgrow.group.connections || []) : []
          RowLayout {
            required property var modelData
            readonly property string rdnsName: devdock.rdnsFor(modelData.remoteIp)
            width: parent.width
            spacing: Style.space(5)

            Text {
              textFormat: Text.PlainText
              text: modelData.direction === "in" ? "↙" : "↗"
              color: modelData.direction === "in" ? root.warnColor : root.okColor
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              Layout.fillWidth: true
              text: modelData.remoteIp + ":" + modelData.remotePort
                + (rdnsName !== "" ? (" (" + rdnsName + ")") : "")
              color: modelData.risk === "critical"
                ? root.dangerColor
                : (modelData.risk === "cleartext" ? root.warnColor : root.foreground)
              font.family: root.fontFamily
              font.pixelSize: Math.max(10, Style.font.caption - 1)
              elide: Text.ElideRight
            }

            PillBadge {
              label: String(modelData.service || "TCP")
              badgeColor: modelData.risk === "critical"
                ? root.dangerColor
                : (modelData.risk === "cleartext"
                  ? root.warnColor
                  : (String(modelData.service || "") === "HTTPS" ? root.okColor : root.infoColor))
            }

            PanelActionButton {
              iconText: "󰖟"
              tooltipText: "Reverse DNS lookup (" + modelData.remoteIp + ")"
              foreground: root.foreground
              hoverColor: root.accent
              fontFamily: root.fontFamily
              onClicked: devdock.lookupRdns(modelData.remoteIp)
            }

            PanelActionButton {
              iconText: "󰆏"
              tooltipText: "Copy " + modelData.remoteIp + ":" + modelData.remotePort
              foreground: root.foreground
              hoverColor: root.accent
              fontFamily: root.fontFamily
              onClicked: devdock.copyText(modelData.remoteIp + ":" + modelData.remotePort, modelData.remoteIp)
            }
          }
        }
      }
    }
  }

  component ArchConnector: Item {
    implicitHeight: Style.space(10)
    Text {
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: "↓"
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Math.max(10, Style.font.caption - 1)
    }
  }

  component ArchLayerCard: BorderSurface {
    id: alayer
    property string layerId: ""
    property string layerNum: ""
    property string title: ""
    property string summary: ""
    property string badge: ""
    property bool urgentBadge: false
    property color layerColor: root.accent
    property var details: []
    readonly property bool isOpen: root.expandedArchLayer === layerId && layerId !== ""

    implicitHeight: alCol.implicitHeight + Style.space(12)
    radius: Style.cornerRadius
    color: alayer.isOpen
      ? Util.alpha(alayer.layerColor, 0.11)
      : (alMouse.containsMouse ? Util.alpha(alayer.layerColor, 0.08) : "transparent")
    borderSpec: alayer.isOpen
      ? Border.controlSpec("selected", alayer.layerColor, alayer.layerColor)
      : Border.controlSpec("normal", Qt.darker(root.foreground, 2.2), alayer.layerColor)

    Behavior on color { ColorAnimation { duration: Style.duration(70) } }

    Column {
      id: alCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.margins: Style.space(8)
      spacing: Style.space(6)

      Item {
        width: parent.width
        implicitHeight: alHdr.implicitHeight

        MouseArea {
          id: alMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: root.expandedArchLayer = alayer.isOpen ? "" : alayer.layerId
        }

        RowLayout {
          id: alHdr
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: Style.space(6)

          PillBadge {
            label: alayer.layerNum
            badgeColor: alayer.urgentBadge ? root.dangerColor : alayer.layerColor
          }

          ColumnLayout {
            Layout.fillWidth: true
            spacing: Style.space(1)

            Text {
              textFormat: Text.PlainText
              text: (alayer.isOpen ? "▾ " : "▸ ") + alayer.title
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              Layout.fillWidth: true
              text: alayer.summary
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Math.max(10, Style.font.caption - 1)
              elide: Text.ElideRight
            }
          }

          PillBadge {
            visible: alayer.badge !== ""
            label: alayer.badge
            badgeColor: alayer.urgentBadge ? root.dangerColor : alayer.layerColor
          }
        }
      }

      Column {
        visible: alayer.isOpen
        width: parent.width
        spacing: Style.space(3)

        Repeater {
          model: alayer.isOpen ? alayer.details : []
          RowLayout {
            required property var modelData
            width: parent.width
            spacing: Style.space(8)

            Text {
              textFormat: Text.PlainText
              text: String(modelData.k || "")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Math.max(10, Style.font.caption - 1)
              Layout.preferredWidth: Style.space(76)
            }

            Text {
              textFormat: Text.PlainText
              Layout.fillWidth: true
              text: String(modelData.v || "")
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Math.max(10, Style.font.caption - 1)
              wrapMode: Text.Wrap
            }
          }
        }
      }
    }
  }
}
