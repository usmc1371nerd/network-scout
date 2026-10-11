import QtQuick
import qs.Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "hackerdad.lan-devices"

  readonly property bool panelOpen: panelLoader.item ? panelLoader.item.opened : false

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    target.bar = root.bar
    target.settings = root.settings
    target.anchorItem = button
    target.hostWidget = root
  }

  function open() { if (panelLoader.item) panelLoader.item.open() }
  function close() { if (panelLoader.item) panelLoader.item.close() }
  function togglePanel() { if (panelLoader.item) panelLoader.item.toggle() }
  function refresh() { if (panelLoader.item) panelLoader.item.discover() }
  function cancelClose() {}
  function scheduleClose() {}

  Timer {
    id: hoverTimer
    interval: 300
    onTriggered: root.open()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰛳"
    active: root.panelOpen
    useActiveColor: true
    activeColor: Color.accent
    tooltipText: panelLoader.item && panelLoader.item.deviceCount > 0
      ? panelLoader.item.deviceCount + " LAN devices"
      : "LAN devices"

    onPressed: function(mouseButton) {
      if (mouseButton === Qt.MiddleButton) root.refresh()
      else root.togglePanel()
    }

    HoverHandler {
      onHoveredChanged: {
        if (hovered) {
          root.cancelClose()
          hoverTimer.restart()
        } else {
          hoverTimer.stop()
        }
      }
    }
  }
}
