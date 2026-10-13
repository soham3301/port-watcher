import QtQuick
import Quickshell
import qs.Ui
import qs.Commons
import "Detector.js" as D

BarWidget {
  id: root
  moduleName: "io.github.soham3301.port-watcher"

  property alias engine: eng

  readonly property bool opened: panelLoader.item
    ? panelLoader.item.opened === true
    : false
  readonly property bool popoutSwitchClosing: panelLoader.item
    ? panelLoader.item.popoutSwitchClosing === true
    : false

  function open() {
    if (panelLoader.item) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item) panelLoader.item.close()
  }

  function toggle() {
    if (panelLoader.item) panelLoader.item.toggle()
  }

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    if (!panelLoader.item) return
    panelLoader.item.bar = root.bar
    panelLoader.item.anchorItem = button
    panelLoader.item.hostWidget = root
  }

  // Both click routes (our MouseArea and the WidgetButton) call this.
  // The debounce stops a double toggle from one physical click.
  property double lastToggle: 0
  function toggleOnce() {
    var n = Date.now()
    if (n - lastToggle < 400) return
    lastToggle = n
    toggle()
  }

  implicitWidth: 210
  implicitHeight: root.bar ? root.bar.barSize : 26
  width: implicitWidth
  height: implicitHeight

  onBarChanged: injectPanel()

  // ---- colors
  readonly property color cGreen: "#3cff6b"
  readonly property color cYellow: "#ffd23c"
  readonly property color cRed: "#ff3b3b"
  function dotColor(s) { return s === "r" ? cRed : (s === "y" ? cYellow : cGreen) }
  readonly property color sysText: root.bar ? root.bar.foreground : Color.foreground
  readonly property color textColor: eng.status === "r" ? cRed : (eng.systemText ? sysText : cGreen)

  PortEngine { id: eng }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
    onStatusChanged: {
      if (status === Loader.Error)
        console.warn("[port-watcher] Panel.qml failed to load - see the QML errors printed above this line")
    }
  }

  // Fallback click target (also anchors the popup to the bar). Text is a single
  // space because some bar buttons ignore clicks when their text is empty.
  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: " "
    opacity: 0
    tooltipText: "Port Watcher - click for details"
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.LeftButton) root.toggleOnce()
    }
  }

  // ---- orbiting dots: one per process name.
  // Level 0 (green, slow): up to 5 remote IPs. Level 1 (yellow, faster): over 5 IPs or a
  // suspicious process. Level 2 (red, pulsing, fastest): over 50 IPs or a threat process.
  readonly property var levelSpeed: [28, 46, 72]
  property var phases: ({})
  property var adj: ({})
  property string lastSig: ""
  property int tick: 0

  function perimLen(w, h, r) {
    return 2 * (w - 2 * r) + 2 * (h - 2 * r) + 2 * Math.PI * r
  }

  function perimPoint(s, w, h, r) {
    var sx = w - 2 * r, sy = h - 2 * r, ar = Math.PI * r / 2
    var L = 2 * sx + 2 * sy + 4 * ar
    s = ((s % L) + L) % L
    if (s < sx) return { x: r + s, y: 0 }
    s -= sx
    if (s < ar) { var a = -Math.PI / 2 + s / r; return { x: w - r + r * Math.cos(a), y: r + r * Math.sin(a) } }
    s -= ar
    if (s < sy) return { x: w, y: r + s }
    s -= sy
    if (s < ar) { var b = s / r; return { x: w - r + r * Math.cos(b), y: h - r + r * Math.sin(b) } }
    s -= ar
    if (s < sx) return { x: w - r - s, y: h }
    s -= sx
    if (s < ar) { var c = Math.PI / 2 + s / r; return { x: r + r * Math.cos(c), y: h - r + r * Math.sin(c) } }
    s -= ar
    if (s < sy) return { x: 0, y: h - r - s }
    s -= sy
    var d = Math.PI + s / r
    return { x: r + r * Math.cos(d), y: r + r * Math.sin(d) }
  }

  // Called whenever the set of dots changes: new dots start at their slot of an
  // equal split of the border, and the existing dots ease to equal gaps.
  function syncDots() {
    var ds = eng.dots, keys = [], i
    for (i = 0; i < ds.length; i++) keys.push(ds[i].key)
    var sig = keys.slice().sort().join("|")
    if (sig === lastSig) return
    lastSig = sig
    var L = perimLen(face.width, face.height, face.radius)
    var alive = [], fresh = []
    for (i = 0; i < keys.length; i++) {
      if (phases[keys[i]] !== undefined) alive.push(keys[i])
      else fresh.push(keys[i])
    }
    for (var k in phases) {
      if (keys.indexOf(k) < 0) { delete phases[k]; delete adj[k] }
    }
    alive.sort(function (x, y) { return phases[x] - phases[y] })
    var order = alive.concat(fresh)
    var n = order.length
    if (n === 0) return
    var anchor = alive.length > 0 ? phases[alive[0]] : Math.random() * L
    for (i = 0; i < n; i++) {
      var target = (anchor + i * L / n) % L
      var key = order[i]
      if (phases[key] === undefined) {
        phases[key] = target
        adj[key] = 0
      } else {
        var dd2 = target - phases[key]
        dd2 = ((dd2 + L / 2) % L + L) % L - L / 2
        adj[key] = dd2
      }
    }
  }

  function advance(dt) {
    var ds = eng.dots
    var L = perimLen(face.width, face.height, face.radius)
    for (var i = 0; i < ds.length; i++) {
      var k = ds[i].key
      if (phases[k] === undefined) phases[k] = Math.random() * L
      var a = adj[k] || 0
      var move = levelSpeed[ds[i].level] * dt
      if (a !== 0) {
        var s = Math.abs(a) < 0.3 ? a : a * Math.min(1, dt * 4)
        move += s
        adj[k] = a - s
      }
      phases[k] = ((phases[k] + move) % L + L) % L
    }
    tick++
  }

  Component.onCompleted: syncDots()

  Timer {
    interval: 33
    repeat: true
    running: root.visible
    onTriggered: root.advance(0.033)
  }

  // ---- blinking light: slow = safe, medium = suspicious, fast = threat
  property bool blinkOn: true
  Timer {
    interval: eng.status === "r" ? 80 : (eng.status === "y" ? 250 : 500)
    repeat: true
    running: root.visible
    onTriggered: root.blinkOn = !root.blinkOn
  }

  // ---- terminal typing: type a piece, hold, backspace it, continue
  property string shown: ""
  property var chunks: []
  property int ci: 0
  property string phase: "type"
  property bool curOn: true

  function loadLine() {
    chunks = D.chunkify(eng.nextLine(), 25)
    ci = 0
  }

  function restartTyping() {
    chunks = []
    ci = 0
    shown = ""
    phase = "type"
    typer.interval = 30
  }

  function stepTyping() {
    var s = eng.status
    var sp = s === "r" ? 12 : (s === "y" ? 24 : 42)
    if (chunks.length === 0) loadLine()
    var target = chunks[ci] || ""
    if (phase === "type") {
      if (shown.length < target.length) {
        shown = target.substring(0, shown.length + 1)
        typer.interval = sp
      } else {
        phase = "hold"
        typer.interval = s === "r" ? 650 : 1300
      }
    } else if (phase === "hold") {
      phase = "erase"
      typer.interval = sp
    } else {
      if (shown.length > 0) {
        shown = shown.substring(0, shown.length - 1)
        typer.interval = Math.max(8, sp / 2)
      } else {
        ci++
        if (ci >= chunks.length) loadLine()
        phase = "type"
        typer.interval = 180
      }
    }
  }

  Timer {
    id: typer
    interval: 500
    repeat: true
    running: eng.stateReady && root.visible
    onTriggered: root.stepTyping()
  }

  Timer {
    interval: 500
    repeat: true
    running: root.visible
    onTriggered: root.curOn = !root.curOn
  }

  Connections {
    target: eng
    function onInterrupt() { root.restartTyping() }
    function onDotsChanged() { root.syncDots() }
  }

  // ---- the display
  Item {
    id: disp
    anchors.centerIn: parent
    width: 206
    height: Math.min(parent.height - 4, 30)

    Rectangle {
      id: face
      anchors.fill: parent
      radius: 8
      color: eng.transparentBg ? "transparent" : "#000000"
      border.width: 1
      // "no border" only hides the line; the geometry stays, so the dots keep their track
      border.color: eng.noBorder ? "transparent"
                                 : Qt.rgba(root.dotColor(eng.status).r, root.dotColor(eng.status).g,
                                           root.dotColor(eng.status).b, 0.45)
    }

    Repeater {
      model: eng.dots
      delegate: Item {
        id: dd
        required property var modelData
        readonly property color col: modelData.level >= 2 ? root.cRed
                                   : (modelData.level === 1 ? root.cYellow : root.cGreen)
        readonly property var pt: {
          root.tick
          return root.perimPoint(root.phases[modelData.key] || 0, face.width, face.height, face.radius)
        }
        readonly property real pulse: modelData.level >= 2 ? 1 + 0.5 * Math.sin(root.tick * 0.3) : 1
        width: 3 * pulse
        height: width
        x: pt.x - width / 2
        y: pt.y - height / 2
        Rectangle {
          anchors.centerIn: parent
          width: parent.width * 2.2
          height: width
          radius: width / 2
          color: dd.col
          opacity: 0.2
        }
        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: dd.col
        }
      }
    }

    Item {
      id: textBox
      anchors.left: parent.left
      anchors.leftMargin: 8
      anchors.right: blinker.left
      anchors.rightMargin: 3
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      clip: true

      Text {
        anchors.verticalCenter: parent.verticalCenter
        text: "> " + root.shown + (root.curOn ? "_" : " ")
        color: root.textColor
        font.family: "monospace"
        font.pixelSize: 10
      }
    }

    Rectangle {
      id: blinker
      width: 8
      height: 8
      radius: 4
      anchors.right: parent.right
      anchors.rightMargin: 9
      anchors.verticalCenter: parent.verticalCenter
      color: root.dotColor(eng.status)
      opacity: root.blinkOn ? 1 : 0.15
    }
  }

  // Our own click target, on top of everything. Left click opens or closes the popup.
  MouseArea {
    anchors.fill: parent
    z: 10
    acceptedButtons: Qt.LeftButton
    cursorShape: Qt.PointingHandCursor
    onPressed: root.toggleOnce()
  }
}