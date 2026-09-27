import QtQuick
import QtQuick.Dialogs
import Quickshell.Io
import qs.Commons
import qs.Ui
import qs.Ui as Ui

Panel {
  id: root
  moduleName: "adarsh.vpn"
  ipcTarget: "adarsh.vpn"
  manageIpc: false
  readonly property string helperPath: decodeURIComponent(Qt.resolvedUrl("scripts/vpn.py").toString().replace(/^file:\/\//, ""))
  property string connectionUuid: ""
  property var profiles: []
  property var activeProfiles: []
  property bool connected: false
  property bool stateKnown: false
  property bool desired: false
  property string operation: ""
  property string lastError: ""
  property string editorMode: ""
  property string editorUuid: ""
  property string editorName: ""
  property string importPath: ""
  property bool editorExisting: false
  property var splitTunnel: null
  property bool routingPending: false
  property bool importSplit: true
  readonly property bool busy: action.running
  readonly property bool revealInactive: opened || busy || (bar && bar.centerSectionRevealHeld === true && bar.centerHoverRevealSuppressed !== true)
  readonly property bool anyConnected: stateKnown && activeProfiles.length > 0
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property string selectedName: {
    for (var i = 0; i < profiles.length; i++) if (profiles[i].uuid === connectionUuid) return profiles[i].name
    return ""
  }
  readonly property string statusText: busy ? (operation === "import" ? "Saving VPN…" : operation === "rename" ? "Saving name…" : operation === "remove" ? "Removing VPN…" : operation === "set-split" ? "Saving routing…" : operation === "select" ? "Selecting…" : desired ? "Connecting…" : "Disconnecting…") : !profiles.length ? "Add a VPN to get started" : !stateKnown ? "Status unavailable" : routingPending ? "Choose split tunneling before connecting" : connected ? "Connected" : "Disconnected"
  visible: anyConnected || revealInactive
  implicitWidth: visible ? button.implicitWidth : 0
  implicitHeight: visible ? button.implicitHeight : 0

  function applyState(data) {
    if (data.profiles !== undefined) {
      profiles = data.profiles
      activeProfiles = data.active || []
      connectionUuid = data.selected || ""
      connected = data.connected === true
      stateKnown = data.stateKnown === true
      splitTunnel = data.splitTunnel
      routingPending = data.routingPending === true
    }
    if (data.error) lastError = data.error
  }
  function refresh() { if (!poll.running && !busy) poll.running = true }
  function runAction(name, value, label, fullTunnel) {
    if (busy) return
    operation = name
    lastError = ""
    var command = ["python3", helperPath, name]
    if (value !== undefined) command.push(value)
    if (label !== undefined) command.push("--name", label)
    if (fullTunnel === true) command.push("--full-tunnel")
    action.command = command
    action.running = true
  }
  function importVpn() {
    if (busy) return
    editorMode = ""
    close()
    fileDialog.open()
  }
  function beginImport(file) {
    importPath = file
    importSplit = true
    nameInput.text = file.split("/").pop().replace(/\.ovpn$/i, "").replace(/[_-]+/g, " ").slice(0, 64)
    editorMode = "import"
    open()
    Qt.callLater(function() { nameInput.forceActiveFocus(); nameInput.selectAll() })
  }
  function editProfile(profile, mode) {
    if (busy) return
    lastError = ""
    editorUuid = profile.uuid
    editorName = profile.name
    editorExisting = profile.existing === true
    editorMode = mode
    nameInput.text = profile.name
    if (mode === "rename") Qt.callLater(function() { nameInput.forceActiveFocus(); nameInput.selectAll() })
  }
  function saveEditor() {
    if (busy || !nameInput.text.trim()) return
    runAction(editorMode === "import" ? "import" : "rename", editorMode === "import" ? importPath : editorUuid, nameInput.text.trim(), editorMode === "import" && !importSplit)
  }
  function toggleVpn() {
    if (busy || !stateKnown || !connectionUuid || routingPending) return
    desired = !connected
    runAction(desired ? "connect" : "disconnect")
  }
  onOpenedChanged: if (opened) refresh(); else if (!busy) editorMode = ""

  Timer {
    interval: 5000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }
  Process {
    id: poll
    command: ["python3", root.helperPath, "status"]
    stdout: StdioCollector { id: pollOutput; waitForEnd: true }
    onExited: function(code) {
      if (root.busy) return
      try {
        root.applyState(JSON.parse(pollOutput.text))
        if (code !== 0) root.stateKnown = false
      } catch (error) {
        root.stateKnown = false
        root.lastError = "Unable to check VPN status. Run the plugin dependency setup."
      }
    }
  }
  Process {
    id: action
    stdout: StdioCollector { id: actionOutput; waitForEnd: true }
    onExited: function(code) {
      try {
        root.applyState(JSON.parse(actionOutput.text))
        if (code === 0 && ["import", "rename", "remove"].indexOf(root.operation) !== -1) root.editorMode = ""
      } catch (error) { root.lastError = "Unable to run VPN setup. Check the plugin dependencies." }
      Qt.callLater(root.refresh)
    }
  }
  FileDialog {
    id: fileDialog
    title: "Import OpenVPN configuration"
    fileMode: FileDialog.OpenFile
    nameFilters: ["OpenVPN configurations (*.ovpn *.OVPN)", "All files (*)"]
    onAccepted: root.beginImport(decodeURIComponent(selectedFile.toString().replace(/^file:\/\//, "")))
  }
  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function status(): string { return root.statusText }
    function inspect(): string { return JSON.stringify({version: "1.3.0", selected: root.connectionUuid, savedProfiles: root.profiles.length, connected: root.connected, splitTunnel: root.splitTunnel, stateKnown: root.stateKnown, visible: root.visible, revealed: root.revealInactive, editor: root.editorMode, error: root.lastError}) }
  }
  QtObject {
    id: vpnIndicatorHost
    readonly property bool revealInactiveIndicators: root.revealInactive
  }
  BarIndicator {
    id: button
    anchors.fill: parent
    bar: root.bar
    active: root.anyConnected
    indicatorHost: vpnIndicatorHost
    activeText: "󰌾"
    inactiveText: "󰌾"
    activeTooltipText: "VPN connected"
    inactiveTooltipText: "VPN"
    onPressed: function(buttonCode) { if (buttonCode === Qt.LeftButton) root.toggle() }
  }
  KeyboardPanel {
    id: popup
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panelContent
    contentWidth: popup.fittedContentWidth(Style.space(340))
    contentHeight: popup.fittedContentHeight(content.implicitHeight, Style.space(540))
    FocusScope {
      id: panelContent
      anchors.fill: parent
      Keys.onEscapePressed: {
        if (root.editorMode !== "" && !root.busy) root.editorMode = ""
        else root.close()
      }
      Column {
        id: content
        width: parent.width
        spacing: Style.space(14)
        Row {
          width: parent.width
          spacing: Style.space(12)
          Column {
            width: parent.width - powerSwitch.width - parent.spacing
            spacing: Style.space(4)
            Text {
              text: root.editorMode === "import" ? "Add VPN" : root.editorMode === "rename" ? "Rename VPN" : root.editorMode === "remove" ? "Remove VPN" : "VPN"
              color: root.foreground
              font.family: Style.font.family
              font.pixelSize: Style.font.body
              font.bold: true
            }
            Text {
              width: parent.width
              text: root.editorMode === "" ? root.statusText : root.editorMode === "import" ? "Choose a name you’ll recognize" : root.editorName
              textFormat: Text.PlainText
              elide: Text.ElideRight
              color: root.connected && root.editorMode === "" ? Color.accent : Qt.darker(root.foreground, 1.35)
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
            }
          }
          ToggleSwitch {
            id: powerSwitch
            visible: root.editorMode === "" && root.profiles.length > 0
            anchors.verticalCenter: parent.verticalCenter
            checked: root.busy && (root.operation === "connect" || root.operation === "disconnect") ? root.desired : root.connected
            busy: root.busy || !root.stateKnown || root.routingPending
            foreground: root.foreground
            onToggled: root.toggleVpn()
          }
        }
        Rectangle { width: parent.width; height: 1; color: root.foreground; opacity: 0.12 }
        Column {
          visible: root.editorMode === ""
          width: parent.width
          spacing: Style.space(8)
          Text {
            visible: !root.profiles.length
            width: parent.width
            text: "Import your .ovpn file to create a saved connection."
            wrapMode: Text.WordWrap
            color: Qt.darker(root.foreground, 1.25)
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
          Flickable {
            width: parent.width
            height: Math.min(profileRows.implicitHeight, Style.space(220))
            visible: root.profiles.length > 0
            contentWidth: width
            contentHeight: profileRows.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            Column {
              id: profileRows
              width: parent.width
              spacing: Style.space(4)
              Repeater {
                model: root.profiles
                delegate: Rectangle {
                  id: profileRow
                  required property var modelData
                  readonly property bool selected: modelData.uuid === root.connectionUuid
                  readonly property bool online: root.activeProfiles.indexOf(modelData.uuid) !== -1
                  width: profileRows.width
                  height: Style.space(52)
                  radius: Style.cornerRadius
                  color: selected ? Style.selectedFillFor(root.foreground, Color.accent) : "transparent"
                  Rectangle { width: Style.space(2); height: parent.height - Style.space(18); anchors.verticalCenter: parent.verticalCenter; color: Color.accent; visible: profileRow.selected }
                  Item {
                    width: parent.width - rowActions.width - Style.space(18)
                    height: parent.height
                    activeFocusOnTab: true
                    enabled: !root.busy
                    Keys.onReturnPressed: root.runAction("select", profileRow.modelData.uuid)
                    Keys.onSpacePressed: root.runAction("select", profileRow.modelData.uuid)
                    Rectangle { anchors.fill: parent; color: root.foreground; opacity: rowMouse.containsMouse || parent.activeFocus ? 0.06 : 0 }
                    Column {
                      anchors.left: parent.left
                      anchors.leftMargin: Style.space(12)
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(3)
                      Text {
                        width: parent.width
                        text: profileRow.modelData.name
                        textFormat: Text.PlainText
                        elide: Text.ElideRight
                        color: root.foreground
                        font.family: Style.font.family
                        font.pixelSize: Style.font.body
                        font.bold: profileRow.selected
                      }
                      Text {
                        text: profileRow.online ? "Connected" : profileRow.selected ? "Selected" : "Disconnected"
                        color: profileRow.online ? Color.accent : Qt.darker(root.foreground, 1.45)
                        font.family: Style.font.family
                        font.pixelSize: Style.font.bodySmall
                      }
                    }
                    MouseArea { id: rowMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.runAction("select", profileRow.modelData.uuid) }
                  }
                  Row {
                    id: rowActions
                    anchors.right: parent.right
                    anchors.rightMargin: Style.space(6)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(4)
                    PanelActionButton { iconText: "󰏫"; tooltipText: "Rename VPN"; focusable: true; enabled: !root.busy; foreground: root.foreground; onClicked: root.editProfile(profileRow.modelData, "rename") }
                    PanelActionButton { iconText: "󰆴"; tooltipText: "Remove VPN"; focusable: true; enabled: !root.busy; foreground: root.foreground; hoverColor: Color.urgent; onClicked: root.editProfile(profileRow.modelData, "remove") }
                  }
                }
              }
            }
          }
          Ui.Button {
            id: importButton
            width: parent.width
            text: "Add VPN"
            iconText: "+"
            leftAlign: true
            focusable: true
            enabled: !root.busy
            opacity: enabled ? 1 : 0.5
            foreground: Color.accent
            onClicked: root.importVpn()
          }
        }
        Column {
          visible: root.editorMode === "import" || root.editorMode === "rename"
          width: parent.width
          spacing: Style.space(10)
          Ui.TextField {
            id: nameInput
            width: parent.width
            placeholderText: "e.g. Office VPN"
            maximumLength: 64
            enabled: !root.busy
            onAccepted: root.saveEditor()
          }
          Text {
            visible: root.editorMode === "import"
            width: parent.width
            text: "Configuration: " + root.importPath.split("/").pop()
            textFormat: Text.PlainText
            elide: Text.ElideMiddle
            color: Qt.darker(root.foreground, 1.4)
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
          Row {
            width: parent.width
            spacing: Style.space(8)
            Ui.Button { width: (parent.width - parent.spacing) / 2; text: "Cancel"; bordered: true; focusable: true; enabled: !root.busy; onClicked: root.editorMode = "" }
            Ui.Button { width: (parent.width - parent.spacing) / 2; text: root.editorMode === "import" ? "Save VPN" : "Save name"; bordered: true; focusable: true; foreground: Color.accent; enabled: !root.busy && nameInput.text.trim() !== ""; opacity: enabled ? 1 : 0.4; onClicked: root.saveEditor() }
          }
        }
        Column {
          visible: root.editorMode === "remove"
          width: parent.width
          spacing: Style.space(12)
          Text {
            width: parent.width
            text: root.editorExisting ? "Remove this VPN from your saved list?" : "Remove this VPN and its saved configuration? If connected, it will disconnect."
            wrapMode: Text.WordWrap
            color: root.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
          Row {
            width: parent.width
            spacing: Style.space(8)
            Ui.Button { width: (parent.width - parent.spacing) / 2; text: "Cancel"; bordered: true; focusable: true; enabled: !root.busy; onClicked: root.editorMode = "" }
            Ui.Button { width: (parent.width - parent.spacing) / 2; text: "Remove VPN"; bordered: true; focusable: true; enabled: !root.busy; foreground: Color.urgent; onClicked: root.runAction("remove", root.editorUuid) }
          }
        }
        Column {
          visible: (root.editorMode === "" && root.profiles.length > 0) || root.editorMode === "import"
          width: parent.width
          spacing: Style.space(4)
          Rectangle { width: parent.width; height: 1; color: root.foreground; opacity: 0.12 }
          Row {
            width: parent.width
            spacing: Style.space(8)
            Text {
              width: parent.width - splitSwitch.width - parent.spacing
              anchors.verticalCenter: parent.verticalCenter
              text: "Split tunneling"
              color: root.foreground
              font.family: Style.font.family
              font.pixelSize: Style.font.body
            }
            ToggleSwitch {
              id: splitSwitch
              checked: root.editorMode === "import" ? root.importSplit : root.splitTunnel === true
              busy: root.busy || (root.editorMode !== "import" && (root.connected || root.splitTunnel === null))
              opacity: root.connected && root.editorMode !== "import" ? 0.5 : 1
              onToggled: {
                if (root.editorMode === "import") root.importSplit = !root.importSplit
                else root.runAction("set-split", root.connectionUuid, undefined, root.splitTunnel === true)
              }
            }
          }
          Text {
            width: parent.width
            text: root.connected && root.editorMode !== "import" ? "Disconnect to change. Internet stays on your normal connection when enabled." : "Keep internet on your normal connection. Use the VPN for its specific routes."
            wrapMode: Text.WordWrap
            color: Qt.darker(root.foreground, 1.35)
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }
        }
        Text {
          visible: root.activeProfiles.length > 0 && !root.connected && root.editorMode === ""
          width: parent.width
          text: "Another saved VPN is connected."
          wrapMode: Text.WordWrap
          color: Color.accent
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
        }
        Text {
          visible: root.lastError !== ""
          width: parent.width
          text: root.lastError
          textFormat: Text.PlainText
          wrapMode: Text.WrapAnywhere
          color: Color.urgent
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
        }
      }
    }
  }
}
