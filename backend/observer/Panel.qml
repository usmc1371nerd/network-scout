import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "hackerdad.lan-devices"
  ipcTarget: "hackerdad.lan-devices.panel"

  property var anchorItem: null
  property var hostWidget: null
  property var devices: []
  property var wan: ({})
  property var counts: ({ total: 0, recently_active: 0, new_24h: 0, unrecognized: 0 })
  property string networkName: "Local network"
  property string interfaceName: ""
  property string errorText: ""
  property bool scanning: false
  property string scanJobId: ""
  property int scanProgress: 0
  property string scanStatus: ""
  property string selectedIp: ""
  property string actionIp: ""
  property string actionName: ""
  property string actionResult: ""
  property bool actionBusy: false
  property string actionJobId: ""
  property int actionProgress: 0
  property string editingIp: ""
  property string editingName: ""
  property string searchText: ""
  property string recognitionFilter: "all"
  readonly property var categories: ["Unknown", "Computer", "Phone", "Tablet", "Server", "Router", "Switch", "Printer", "Television", "Smart home / IoT", "Gaming console"]
  readonly property var filteredDevices: devices.filter(function(device) {
    if (recognitionFilter !== "all" && device.recognition !== recognitionFilter) return false
    var query = searchText.trim().toLowerCase()
    if (query === "") return true
    return [device.name, device.ip, device.mac, device.vendor, device.category, device.type]
      .some(function(value) { return String(value || "").toLowerCase().indexOf(query) !== -1 })
  })
  readonly property int deviceCount: devices.length
  readonly property color fg: bar ? bar.foreground : Color.popups.text
  readonly property color muted: Qt.rgba(fg.r, fg.g, fg.b, 0.62)
  readonly property color accent: Color.accent
  readonly property string fontFam: bar ? bar.fontFamily : Style.font.family
  readonly property string scriptPath:
    Qt.resolvedUrl("scanner.py").toString().replace(/^file:\/\//, "")

  function open() {
    root.controller.show()
    if (!scanning) Qt.callLater(root.passiveRefresh)
  }

  function close() { root.controller.hide() }

  function toggle() {
    if (root.opened) close()
    else open()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    return false
  }

  function passiveRefresh() {
    if (root.scanning || scanJobId !== "") return
    scanning = true
    errorText = ""
    scanProcess.command = ["python3", "-B", scriptPath, "passive"]
    scanProcess.running = true
  }

  function discover() {
    if (root.scanning || scanJobId !== "") return
    scanning = true
    scanProgress = 0
    scanStatus = "Starting authorized local discovery…"
    errorText = ""
    activeScanStart.command = ["python3", "-B", scriptPath, "scan-start"]
    activeScanStart.running = true
  }

  function cancelScan() {
    if (!scanJobId) return
    scanCancelProcess.command = ["python3", "-B", scriptPath, "scan-cancel", scanJobId]
    scanCancelProcess.running = true
    scanStatus = "Cancellation requested…"
  }

  function runAction(kind, device) {
    if (actionBusy) return
    actionIp = device.ip
    actionName = kind
    actionResult = ""
    actionJobId = ""
    actionProgress = 0
    actionBusy = true
    if (kind === "identify")
      actionProcess.command = ["python3", "-B", scriptPath, kind, device.ip]
    else
      actionProcess.command = ["python3", "-B", scriptPath, "diagnostic-start", device.deviceId, kind, device.ip]
    actionProcess.running = true
  }

  function cancelDiagnostic() {
    if (!actionJobId) return
    cancelProcess.command = ["python3", "-B", scriptPath, "diagnostic-cancel", actionJobId]
    cancelProcess.running = true
    actionResult = "Cancellation requested…"
  }

  function setRecognition(device, state) {
    if (actionBusy || !device.deviceId) return
    actionIp = device.ip
    actionName = "recognition"
    actionResult = ""
    actionBusy = true
    actionProcess.command = ["python3", "-B", scriptPath, "recognition", device.deviceId, state]
    actionProcess.running = true
  }

  function setMetadata(device, field, value) {
    if (actionBusy || !device.deviceId) return
    actionIp = device.ip
    actionName = "metadata"
    actionResult = ""
    actionBusy = true
    actionProcess.command = ["python3", "-B", scriptPath, "metadata", device.deviceId, field, value]
    actionProcess.running = true
  }

  function checkWan(ip) {
    if (actionBusy) return
    actionIp = ip
    actionName = "check WAN"
    actionResult = ""
    actionBusy = true
    actionProcess.command = ["python3", "-B", scriptPath, "wan"]
    actionProcess.running = true
  }

  function beginRename(device) {
    selectedIp = device.ip
    editingIp = device.ip
    editingName = device.hasCustomName ? device.customName : (device.name === "Unknown device" ? "" : device.name)
  }

  function saveName(ip) {
    var name = editingName.trim()
    if (actionBusy || name === "") return
    actionIp = ip
    actionName = "rename"
    actionResult = ""
    actionBusy = true
    actionProcess.command = ["python3", "-B", scriptPath, "name", ip, name]
    actionProcess.running = true
  }

  function resetName(ip) {
    if (actionBusy) return
    editingIp = ""
    actionIp = ip
    actionName = "reset name"
    actionResult = ""
    actionBusy = true
    actionProcess.command = ["python3", "-B", scriptPath, "unname", ip]
    actionProcess.running = true
  }

  function copyText(value) { Quickshell.execDetached(["wl-copy", value]) }
  function openWeb(ip) { Quickshell.execDetached(["xdg-open", "http://" + ip]) }
  function openDashboard() { Quickshell.execDetached(["python3", "-B", scriptPath, "dashboard"]) }

  Process {
    id: scanProcess
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          root.devices = data.devices || []
          root.wan = data.wan || ({})
          root.counts = data.counts || ({ total: root.devices.length, recently_active: 0, new_24h: 0, unrecognized: 0 })
          root.networkName = data.network || "Local network"
          root.interfaceName = data.interface || ""
          root.errorText = data.error || ""
        } catch (error) {
          root.errorText = "Could not read scan results"
        }
      }
    }
    onExited: function(exitCode) {
      root.scanning = false
      if (exitCode !== 0 && root.errorText === "") root.errorText = "Network scan failed"
    }
  }

  Process {
    id: activeScanStart
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (!data.job) throw new Error(data.error || "Missing scan job")
          root.scanJobId = data.job.id
          root.scanProgress = data.job.progress || 0
          root.scanStatus = "Discovery queued…"
          scanPollTimer.start()
        } catch (error) {
          root.scanning = false
          root.errorText = "Could not start discovery"
        }
      }
    }
    onExited: function(exitCode) {
      if (exitCode !== 0 && root.scanJobId === "") root.scanning = false
    }
  }

  Timer {
    id: scanPollTimer
    interval: 500
    repeat: true
    running: false
    onTriggered: {
      if (!root.scanJobId) return
      scanStatusProcess.command = ["python3", "-B", root.scriptPath, "scan-status", root.scanJobId]
      scanStatusProcess.running = true
    }
  }

  Process {
    id: scanStatusProcess
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (!data.job) throw new Error("Missing scan job")
          root.scanProgress = data.job.progress || 0
          if (data.job.status === "queued") root.scanStatus = "Waiting for the discovery worker…"
          else if (data.job.status === "running") root.scanStatus = "Discovering local devices… " + root.scanProgress + "%"
          else {
            scanPollTimer.stop()
            root.scanning = false
            root.scanStatus = data.job.error || (data.job.result ? data.job.result.summary : data.job.status)
            root.scanJobId = ""
            Qt.callLater(root.passiveRefresh)
          }
        } catch (error) {
          scanPollTimer.stop()
          root.scanning = false
          root.scanJobId = ""
          root.errorText = "Could not read discovery status"
        }
      }
    }
  }

  Process {
    id: scanCancelProcess
    running: false
  }

  Process {
    id: actionProcess
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (data.job && data.job.id) {
            root.actionJobId = data.job.id
            root.actionProgress = data.job.progress || 0
            root.actionResult = "Diagnostic queued…"
            diagnosticTimer.start()
          } else {
            root.actionResult = data.error || data.result || "Finished"
          }
        } catch (error) {
          root.actionResult = "Could not read action result"
        }
      }
    }
    onExited: function(exitCode) {
      if (root.actionJobId === "") root.actionBusy = false
      if (root.actionName === "rename" || root.actionName === "reset name" || root.actionName === "check WAN" || root.actionName === "recognition" || root.actionName === "metadata") {
        if (exitCode === 0) root.editingIp = ""
        Qt.callLater(root.passiveRefresh)
      }
    }
  }

  Timer {
    id: diagnosticTimer
    interval: 500
    repeat: true
    running: false
    onTriggered: {
      if (!root.actionJobId) return
      diagnosticPoll.command = ["python3", "-B", root.scriptPath, "diagnostic-status", root.actionJobId]
      diagnosticPoll.running = true
    }
  }

  Process {
    id: diagnosticPoll
    running: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var data = JSON.parse(text)
          if (!data.job) throw new Error("Missing job")
          root.actionProgress = data.job.progress || 0
          if (data.job.status === "queued") root.actionResult = "Waiting for the diagnostic worker…"
          else if (data.job.status === "running") root.actionResult = "Diagnostic running… " + root.actionProgress + "%"
          else {
            diagnosticTimer.stop()
            root.actionBusy = false
            root.actionResult = data.job.error || (data.job.result ? data.job.result.summary : data.job.status)
            root.actionJobId = ""
            Qt.callLater(root.passiveRefresh)
          }
        } catch (error) {
          diagnosticTimer.stop()
          root.actionBusy = false
          root.actionJobId = ""
          root.actionResult = "Could not read diagnostic status"
        }
      }
    }
  }

  Process {
    id: cancelProcess
    running: false
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(430))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(540))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
    }

    ScrollView {
      anchors.fill: parent
      anchors.bottomMargin: -panel.padding
      clip: true
      ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
      ScrollBar.vertical.policy: panelColumn.implicitHeight > height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff

      Column {
        id: panelColumn
        width: parent.width
        spacing: Style.space(12)

        RowLayout {
          width: parent.width
          spacing: Style.space(10)

          Text {
            text: "󰛳"
            color: root.accent
            font.family: root.fontFam
            font.pixelSize: Style.font.display
          }

          Column {
            Layout.fillWidth: true
            spacing: Style.space(2)

            Text {
              text: "LAN Devices"
              color: root.fg
              font.family: root.fontFam
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              text: root.scanning ? root.scanStatus : root.deviceCount + " observed  •  " + root.counts.recently_active + " recently active  •  " + root.counts.unrecognized + " unrecognized"
              color: root.muted
              font.family: root.fontFam
              font.pixelSize: Style.font.caption
            }
          }

          Rectangle {
            width: Style.space(34)
            height: Style.space(34)
            radius: width / 2
            color: refreshMouse.containsMouse ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.18) : "transparent"

            Text {
              anchors.centerIn: parent
              text: root.scanJobId !== "" ? "󰜺" : "󰑐"
              color: root.scanning ? root.muted : root.accent
              font.family: root.fontFam
              font.pixelSize: 18

            }

            MouseArea {
              id: refreshMouse
              anchors.fill: parent
              hoverEnabled: true
              enabled: !root.scanning
              cursorShape: Qt.PointingHandCursor
              onClicked: root.scanJobId !== "" ? root.cancelScan() : root.discover()
            }
          }
        }

        Rectangle {
          width: parent.width
          height: Style.space(40)
          radius: Style.space(7)
          color: dashboardMouse.containsMouse
            ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.22)
            : Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.12)
          border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.55)

          Text {
            id: dashboardLabel
            anchors.centerIn: parent
            text: "Open Cyber Scout Dashboard  ↗"
            color: root.accent
            font.family: root.fontFam
            font.pixelSize: Style.font.body
            font.bold: true
          }

          MouseArea {
            id: dashboardMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openDashboard()
          }
        }

        Rectangle {
          visible: root.errorText !== ""
          width: parent.width
          height: errorLabel.implicitHeight + Style.space(18)
          radius: Style.space(7)
          color: Qt.rgba(0.85, 0.25, 0.25, 0.14)

          Text {
            id: errorLabel
            anchors.centerIn: parent
            text: root.errorText
            color: root.fg
            font.family: root.fontFam
            font.pixelSize: Style.font.caption
          }
        }

        Text {
          visible: root.scanning && root.devices.length === 0
          width: parent.width
          horizontalAlignment: Text.AlignHCenter
          text: "Discovering devices on your local network…"
          color: root.muted
          font.family: root.fontFam
          font.pixelSize: Style.font.body
          topPadding: Style.space(20)
          bottomPadding: Style.space(20)
        }

        RowLayout {
          width: parent.width
          spacing: Style.space(6)

          TextField {
            Layout.fillWidth: true
            placeholderText: "Search name, IP, MAC, vendor…"
            text: root.searchText
            maximumLength: 128
            selectByMouse: true
            foreground: root.fg
            accent: root.accent
            font.family: root.fontFam
            font.pixelSize: Style.font.caption
            onTextChanged: root.searchText = text
          }

          ActionButton {
            label: root.recognitionFilter === "all" ? "All" : (root.recognitionFilter === "unrecognized" ? "Unknown" : "Known")
            onTriggered: {
              if (root.recognitionFilter === "all") root.recognitionFilter = "unrecognized"
              else if (root.recognitionFilter === "unrecognized") root.recognitionFilter = "recognized"
              else root.recognitionFilter = "all"
            }
          }
        }

        Repeater {
          model: root.filteredDevices

          delegate: Rectangle {
            required property var modelData
            width: panelColumn.width
            height: deviceColumn.implicitHeight + Style.space(18)
            radius: Style.space(8)
            color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.055)
            border.width: modelData.gateway ? 1 : 0
            border.color: Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.45)

            Column {
              id: deviceColumn
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.margins: Style.space(10)
              spacing: Style.space(8)

              Item {
                width: parent.width
                height: deviceHeader.implicitHeight

                RowLayout {
                  id: deviceHeader
                  anchors.fill: parent
                  spacing: Style.space(10)

                  Text {
                  text: modelData.gateway ? "󰑩" : (modelData.self ? "󰍹" : "󰛳")
                  color: modelData.gateway || modelData.self ? root.accent : root.muted
                  font.family: root.fontFam
                  font.pixelSize: 18
                }

                  Column {
                  Layout.fillWidth: true
                  spacing: Style.space(2)

                  Text {
                    width: parent.width
                    elide: Text.ElideRight
                    text: modelData.name + (modelData.self ? "  •  This computer" : "")
                    color: root.fg
                    font.family: root.fontFam
                    font.pixelSize: Style.font.body
                    font.bold: true
                  }

                  Text {
                    width: parent.width
                    elide: Text.ElideRight
                    text: (modelData.category || modelData.type) + "  •  " + modelData.vendor + "  •  " + (modelData.recognition || "unrecognized")
                    color: modelData.recognition === "recognized" ? root.accent : root.muted
                    font.family: root.fontFam
                    font.pixelSize: Style.font.caption
                  }

                  Text {
                    width: parent.width
                    elide: Text.ElideRight
                    text: modelData.mac
                    color: root.muted
                    font.family: root.fontFam
                    font.pixelSize: Style.font.caption
                  }

                }

                  Rectangle {
                    z: 2
                    Layout.preferredWidth: Style.space(58)
                    Layout.minimumWidth: Style.space(58)
                    Layout.preferredHeight: Style.space(24)
                    radius: Style.space(6)
                    color: renameMouse.containsMouse
                      ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.22)
                      : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.08)

                    Text {
                      anchors.centerIn: parent
                      text: modelData.hasCustomName ? "Rename" : "Name"
                      color: root.accent
                      font.family: root.fontFam
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }

                    MouseArea {
                      id: renameMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.beginRename(modelData)
                    }
                  }

                  Text {
                  text: modelData.ip
                  color: root.accent
                  font.family: root.fontFam
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                  Rectangle {
                  width: Style.space(26)
                  height: Style.space(26)
                  radius: width / 2
                  color: headerMouse.containsMouse ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.18) : "transparent"

                  Text {
                    anchors.centerIn: parent
                    text: root.selectedIp === modelData.ip ? "⌃" : "⌄"
                    color: root.accent
                    font.pixelSize: Style.font.body
                  }
                  }
                }

                MouseArea {
                  id: headerMouse
                  z: -1
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.selectedIp = root.selectedIp === modelData.ip ? "" : modelData.ip
                }
              }

              Text {
                visible: modelData.gateway
                width: parent.width
                elide: Text.ElideRight
                text: root.wan.publicIp
                  ? "WAN  " + root.wan.publicIp + "  •  " + root.wan.isp
                  : "WAN details not checked — expand for Check WAN"
                color: root.wan.publicIp ? root.accent : root.muted
                font.family: root.fontFam
                font.pixelSize: Style.font.caption
                font.bold: root.wan.publicIp ? true : false
              }

              Flow {
                visible: root.selectedIp === modelData.ip
                width: parent.width
                spacing: Style.space(6)

                ActionButton { label: "Ping"; enabled: !!modelData.deviceId; onTriggered: root.runAction("ping", modelData) }
                ActionButton { label: "Identify"; onTriggered: root.runAction("identify", modelData) }
                ActionButton { label: "Services"; enabled: !!modelData.deviceId; onTriggered: root.runAction("services", modelData) }
                ActionButton { label: "Safety ports"; enabled: !!modelData.deviceId; onTriggered: root.runAction("exposure", modelData) }
                ActionButton { label: root.wan.publicIp ? "Refresh WAN" : "Check WAN"; visible: modelData.gateway; onTriggered: root.checkWan(modelData.ip) }
                ActionButton { label: "Rename"; onTriggered: root.beginRename(modelData) }
                ActionButton { label: "Reset name"; visible: modelData.hasCustomName; onTriggered: root.resetName(modelData.ip) }
                ActionButton { label: "Recognize"; visible: modelData.recognition !== "recognized"; enabled: !!modelData.deviceId; onTriggered: root.setRecognition(modelData, "recognized") }
                ActionButton { label: "Unrecognize"; visible: modelData.recognition === "recognized"; enabled: !!modelData.deviceId; onTriggered: root.setRecognition(modelData, "unrecognized") }
                ActionButton { label: "Ignore"; visible: modelData.recognition !== "ignored"; enabled: !!modelData.deviceId; onTriggered: root.setRecognition(modelData, "ignored") }
                ActionButton { label: "Open"; onTriggered: root.openWeb(modelData.ip) }
                ActionButton { label: "Copy IP"; onTriggered: root.copyText(modelData.ip) }
                ActionButton { label: "Copy MAC"; enabled: modelData.mac !== "Unavailable"; onTriggered: root.copyText(modelData.mac) }
              }

              RowLayout {
                visible: root.selectedIp === modelData.ip
                width: parent.width
                spacing: Style.space(6)

                Text {
                  text: "Category"
                  color: root.muted
                  font.family: root.fontFam
                  font.pixelSize: Style.font.caption
                }

                ComboBox {
                  Layout.fillWidth: true
                  model: root.categories
                  currentIndex: Math.max(0, root.categories.indexOf(modelData.category || "Unknown"))
                  enabled: !!modelData.deviceId && !root.actionBusy
                  font.family: root.fontFam
                  font.pixelSize: Style.font.caption
                  onActivated: function(index) { root.setMetadata(modelData, "category", root.categories[index]) }
                }
              }

              RowLayout {
                visible: root.selectedIp === modelData.ip
                width: parent.width
                spacing: Style.space(6)

                TextField {
                  id: noteField
                  Layout.fillWidth: true
                  text: modelData.notes || ""
                  placeholderText: "Private note about this device"
                  maximumLength: 2000
                  selectByMouse: true
                  foreground: root.fg
                  accent: root.accent
                  font.family: root.fontFam
                  font.pixelSize: Style.font.caption
                  onAccepted: root.setMetadata(modelData, "notes", text)
                }

                ActionButton {
                  label: "Save note"
                  enabled: !!modelData.deviceId && !root.actionBusy
                  onTriggered: root.setMetadata(modelData, "notes", noteField.text)
                }
              }


              RowLayout {
                visible: root.selectedIp === modelData.ip && root.editingIp === modelData.ip
                width: parent.width
                spacing: Style.space(6)

                TextField {
                  id: nameField
                  Layout.fillWidth: true
                  text: root.editingIp === modelData.ip ? root.editingName : ""
                  placeholderText: "Device name"
                  maximumLength: 64
                  selectByMouse: true
                  foreground: root.fg
                  accent: root.accent
                  font.family: root.fontFam
                  font.pixelSize: Style.font.body
                  onTextChanged: if (root.editingIp === modelData.ip) root.editingName = text
                  onAccepted: root.saveName(modelData.ip)
                  Keys.onEscapePressed: root.editingIp = ""
                  onVisibleChanged: if (visible) Qt.callLater(forceActiveFocus)
                  Component.onCompleted: if (visible) Qt.callLater(forceActiveFocus)
                }

                ActionButton {
                  label: "Save"
                  enabled: root.editingName.trim() !== "" && !root.actionBusy
                  onTriggered: root.saveName(modelData.ip)
                }
                ActionButton { label: "Cancel"; onTriggered: root.editingIp = "" }
              }

              Text {
                visible: root.selectedIp === modelData.ip && root.actionIp === modelData.ip && (root.actionBusy || root.actionResult !== "")
                width: parent.width
                wrapMode: Text.Wrap
                text: root.actionBusy
                  ? (root.actionJobId !== "" ? root.actionResult : root.actionName.charAt(0).toUpperCase() + root.actionName.slice(1) + "…")
                  : root.actionResult
                color: root.actionBusy ? root.muted : root.accent
                font.family: root.fontFam
                font.pixelSize: Style.font.caption
              }

              ActionButton {
                visible: root.selectedIp === modelData.ip && root.actionIp === modelData.ip && root.actionBusy && root.actionJobId !== ""
                label: "Cancel diagnostic"
                enabled: root.actionBusy
                onTriggered: root.cancelDiagnostic()
              }
            }
          }
        }

        Text {
          visible: !root.scanning && root.filteredDevices.length === 0 && root.errorText === ""
          width: parent.width
          horizontalAlignment: Text.AlignHCenter
          text: root.devices.length === 0 ? "No devices found" : "No devices match this filter"
          color: root.muted
          font.family: root.fontFam
          font.pixelSize: Style.font.body
          topPadding: Style.space(20)
          bottomPadding: Style.space(20)
        }

        Text {
          id: footerAction
          width: parent.width
          text: "Open Dashboard ↗   •   Hover is passive   •   Checks are explicit"
          horizontalAlignment: Text.AlignHCenter
          color: footerMouse.containsMouse ? root.accent : root.muted
          font.family: root.fontFam
          font.pixelSize: Style.font.caption
          bottomPadding: Style.space(4)

          MouseArea {
            id: footerMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openDashboard()
          }
        }
      }
    }
  }

  component ActionButton: Rectangle {
    id: actionButton
    property string label: "Action"
    signal triggered()
    implicitWidth: actionLabel.implicitWidth + Style.space(18)
    implicitHeight: actionLabel.implicitHeight + Style.space(10)
    radius: Style.space(6)
    color: actionMouse.containsMouse ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.22) : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.08)
    opacity: enabled ? 1 : 0.4

    Text {
      id: actionLabel
      anchors.centerIn: parent
      text: actionButton.label
      color: root.fg
      font.family: root.fontFam
      font.pixelSize: Style.font.caption
      font.bold: true
    }

    MouseArea {
      id: actionMouse
      anchors.fill: parent
      enabled: actionButton.enabled
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: actionButton.triggered()
    }
  }
}
