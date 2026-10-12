import QtQuick
import Quickshell
import qs.Commons
import qs.Ui
import "Detector.js" as D

Panel {
  id: root
  moduleName: "io.github.soham3301.port-watcher"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null

  function open() {
    root.controller.show()
  }

  function close() {
    root.controller.hide()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    return false
  }

  // ---- shared state; the palette comes from the system theme
  readonly property var eng: hostWidget ? hostWidget.engine : null
  readonly property color fg: root.barForeground
  readonly property color accent: Color.accent
  readonly property color cR: Color.urgent
  readonly property color cY: "#ffd23c"
  function tone(s) { return s === "r" ? cR : (s === "y" ? cY : accent) }
  function dim(c, a) { return Qt.rgba(c.r, c.g, c.b, a) }
  function rgba(c, a) {
    return "rgba(" + Math.round(c.r * 255) + "," + Math.round(c.g * 255) + "," + Math.round(c.b * 255) + "," + a + ")"
  }
  function histInfo() {
    var h = eng ? eng.hist : []
    if (h.length === 0) return ""
    var m = 0
    for (var i = 0; i < h.length; i++) m = Math.max(m, h[i])
    return "now " + h[h.length - 1] + "  peak " + m
  }
  property string tab: "overview"
  property string sel: ""
  readonly property var selProc: {
    var ps = eng ? eng.procs : []
    var k = sel || (eng && eng.threats.length ? eng.threats[0].key : "")
    for (var i = 0; i < ps.length; i++) if (ps[i].key === k) return ps[i]
    return null
  }

  // ---- small reusable pieces
  component PwBtn: Rectangle {
    id: b
    property string label: ""
    property color tone: Color.accent
    property bool active: false
    signal clicked()
    implicitWidth: lbl.implicitWidth + 16
    implicitHeight: 22
    radius: 5
    color: active ? Qt.rgba(tone.r, tone.g, tone.b, 0.25)
                  : (ma.containsMouse ? Qt.rgba(tone.r, tone.g, tone.b, 0.15) : "transparent")
    border.width: 1
    border.color: tone
    Text {
      id: lbl
      anchors.centerIn: parent
      text: b.label
      color: b.tone
      font.family: "monospace"
      font.pixelSize: 11
    }
    MouseArea {
      id: ma
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: b.clicked()
    }
  }

  component PwChip: Rectangle {
    id: c
    property string label: ""
    implicitWidth: ct.implicitWidth + 10
    implicitHeight: 18
    radius: 4
    color: "transparent"
    border.width: 1
    border.color: root.dim(root.accent, 0.5)
    Text {
      id: ct
      anchors.centerIn: parent
      text: c.label
      color: root.accent
      font.family: "monospace"
      font.pixelSize: 10
    }
  }

  // ---- no-threat banter, typed like the bar display
  readonly property var banter: [
    "No threat found as of now",
    "Watching over the network for anything suspicious",
    "Explore the plugin, it might surprise you",
    "All quiet on the wire. Suspiciously quiet?",
    "Your packets are behaving. For now.",
    "Nothing to see here. Probably.",
    "Every socket is being watched. Politely.",
    "Ports: open. Suspicion: also open."
  ]
  property int mi: 0
  property string mtxt: ""
  property string mph: "type"
  property bool mcur: true
  Timer {
    interval: 500
    repeat: true
    running: root.opened && root.tab === "overview"
    onTriggered: root.mcur = !root.mcur
  }
  Timer {
    id: banterT
    interval: 45
    repeat: true
    running: root.opened && root.tab === "overview" && (!root.eng || root.eng.threats.length === 0)
    onTriggered: {
      var t = root.banter[root.mi % root.banter.length]
      if (root.mph === "type") {
        if (root.mtxt.length < t.length) { root.mtxt = t.substring(0, root.mtxt.length + 1); interval = 45 }
        else { root.mph = "hold"; interval = 2200 }
      } else if (root.mph === "hold") {
        root.mph = "erase"; interval = 20
      } else {
        if (root.mtxt.length > 0) root.mtxt = root.mtxt.substring(0, root.mtxt.length - 1)
        else { root.mi++; root.mph = "type"; interval = 300 }
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    // fixed size: the layout below never grows or shrinks
    contentWidth: panel.fittedContentWidth(640)
    contentHeight: panel.fittedContentHeight(520)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      // System theme background (delete this block if the panel already paints one you like better)
      Rectangle {
        id: sysBg
        anchors.fill: parent
        radius: 10
        color: Color.background
      }

      Item {
        id: content
        anchors.fill: parent
        anchors.margins: 12

        // ---- header
        Text {
          y: 0
          text: "> PORT_WATCHER"
          color: root.accent
          font.family: "monospace"
          font.pixelSize: 14
          font.bold: true
        }
        Text {
          y: 0
          anchors.right: parent.right
          text: "\u25CF " + (root.eng ? ({ g: "ALL CLEAR", y: "SUSPICIOUS", r: "THREAT ACTIVE" }[root.eng.status]) : "")
          color: root.eng ? root.tone(root.eng.status) : root.accent
          font.family: "monospace"
          font.pixelSize: 12
          font.bold: true
        }

        // ---- tabs, and toggles that only change the bar display
        Row {
          y: 28
          spacing: 6
          PwBtn { label: "overview"; tone: root.accent; active: root.tab === "overview"; onClicked: root.tab = "overview" }
          PwBtn { label: "network log"; tone: root.accent; active: root.tab === "log"; onClicked: root.tab = "log" }
        }
        Row {
          y: 28
          anchors.right: parent.right
          spacing: 6
          Text {
            anchors.verticalCenter: parent.verticalCenter
            text: "bar display:"
            color: root.dim(root.fg, 0.7)
            font.family: "monospace"
            font.pixelSize: 10
          }
          PwBtn {
            label: (root.eng && root.eng.transparentBg ? "[x] " : "[ ] ") + "transparent bg"
            tone: root.accent
            onClicked: if (root.eng) root.eng.setTransparent(!root.eng.transparentBg)
          }
          PwBtn {
            label: (root.eng && root.eng.systemText ? "[x] " : "[ ] ") + "system text color"
            tone: root.accent
            onClicked: if (root.eng) root.eng.setSystemText(!root.eng.systemText)
          }
        }

        // ================================================= overview page
        Item {
          id: pageOv
          y: 60
          width: parent.width
          height: parent.height - 60
          visible: root.tab === "overview"

          // charts row
          Item {
            id: chartsRow
            width: parent.width
            height: 96

            Canvas {
              id: donut
              width: 96
              height: 96
              property int rev: root.eng ? root.eng.rev : 0
              onRevChanged: requestPaint()
              Component.onCompleted: requestPaint()
              onPaint: {
                var ctx = getContext("2d")
                ctx.clearRect(0, 0, width, height)
                var ps = root.eng ? root.eng.procs : []
                var tot = 0, i
                for (i = 0; i < ps.length; i++) tot += ps[i].conns
                ctx.lineWidth = 12
                ctx.beginPath()
                ctx.arc(48, 48, 38, 0, 2 * Math.PI)
                ctx.strokeStyle = root.rgba(root.accent, 0.12)
                ctx.stroke()
                if (tot === 0) return
                var shades = [root.rgba(root.accent, 1.0), root.rgba(root.accent, 0.7),
                              root.rgba(root.accent, 0.5), root.rgba(root.accent, 0.35)]
                var a = -Math.PI / 2, gi = 0
                for (i = 0; i < ps.length; i++) {
                  var span = ps[i].conns / tot * 2 * Math.PI
                  ctx.beginPath()
                  ctx.arc(48, 48, 38, a, a + Math.max(0.05, span - 0.05))
                  ctx.strokeStyle = ps[i].status === "r" ? root.rgba(root.cR, 1)
                                  : (ps[i].status === "y" ? root.rgba(root.cY, 1) : shades[gi++ % shades.length])
                  ctx.stroke()
                  a += span
                }
              }
              Text {
                anchors.centerIn: parent
                text: root.eng ? root.eng.connCount : 0
                color: root.accent
                font.family: "monospace"
                font.pixelSize: 20
                font.bold: true
              }
            }

            // live connections: oscilloscope trace
            Rectangle {
              id: scope
              x: 108
              width: parent.width - 108
              height: 96
              radius: 8
              color: "transparent"
              border.width: 1
              border.color: root.dim(root.accent, 0.35)

              Text {
                x: 8; y: 5
                text: "live connections (last 60 s)"
                color: root.dim(root.fg, 0.8)
                font.family: "monospace"
                font.pixelSize: 10
              }
              Text {
                anchors.right: parent.right
                anchors.rightMargin: 8
                y: 5
                text: root.eng ? (root.eng.listenCount + " listening | " + root.eng.unconCount
                                  + " unconnected | " + root.eng.uniqueIps + " IPs") : ""
                color: root.dim(root.fg, 0.8)
                font.family: "monospace"
                font.pixelSize: 10
              }
              Canvas {
                id: graph
                x: 8; y: 22
                width: parent.width - 16
                height: parent.height - 30
                property int rev: root.eng ? root.eng.rev : 0
                onRevChanged: requestPaint()
                onWidthChanged: requestPaint()
                onPaint: {
                  var ctx = getContext("2d")
                  var W = width, H = height, i
                  ctx.clearRect(0, 0, W, H)
                  ctx.lineWidth = 1
                  ctx.strokeStyle = root.rgba(root.accent, 0.12)
                  for (i = 1; i < 4; i++) {
                    var gy = Math.round(H * i / 4) + 0.5
                    ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(W, gy); ctx.stroke()
                  }
                  for (i = 1; i < 6; i++) {
                    var gx = Math.round(W * i / 6) + 0.5
                    ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, H); ctx.stroke()
                  }
                  var h = root.eng ? root.eng.hist : []
                  if (h.length < 2) return
                  var mx = 1
                  for (i = 0; i < h.length; i++) mx = Math.max(mx, h[i])
                  mx = mx * 1.2
                  var step = W / 29, xs = [], ys = []
                  for (i = 0; i < h.length; i++) {
                    xs.push((30 - h.length + i) * step)
                    ys.push(H - 3 - h[i] / mx * (H - 8))
                  }
                  var trace = function () {
                    ctx.beginPath()
                    ctx.moveTo(xs[0], ys[0])
                    for (var j = 1; j < xs.length; j++) {
                      ctx.quadraticCurveTo(xs[j - 1], ys[j - 1], (xs[j - 1] + xs[j]) / 2, (ys[j - 1] + ys[j]) / 2)
                    }
                    ctx.lineTo(xs[xs.length - 1], ys[ys.length - 1])
                  }
                  trace()
                  ctx.lineTo(xs[xs.length - 1], H)
                  ctx.lineTo(xs[0], H)
                  ctx.closePath()
                  var gr = ctx.createLinearGradient(0, 0, 0, H)
                  gr.addColorStop(0, root.rgba(root.accent, 0.35))
                  gr.addColorStop(1, root.rgba(root.accent, 0.0))
                  ctx.fillStyle = gr
                  ctx.fill()
                  var ws = [7, 3.5, 1.6], al = [0.07, 0.18, 1.0]
                  for (i = 0; i < 3; i++) {
                    trace()
                    ctx.lineWidth = ws[i]
                    ctx.strokeStyle = root.rgba(root.accent, al[i])
                    ctx.stroke()
                  }
                  var hx = xs[xs.length - 1], hy = ys[ys.length - 1]
                  ctx.beginPath(); ctx.arc(hx, hy, 5, 0, 2 * Math.PI)
                  ctx.fillStyle = root.rgba(root.accent, 0.25); ctx.fill()
                  ctx.beginPath(); ctx.arc(hx, hy, 2.2, 0, 2 * Math.PI)
                  ctx.fillStyle = root.rgba(root.accent, 1); ctx.fill()
                }
              }
              // faint scan beam sweeping across the trace
              Rectangle {
                id: beam
                y: 22
                width: 26
                height: graph.height
                gradient: Gradient {
                  orientation: Gradient.Horizontal
                  GradientStop { position: 0.0; color: "transparent" }
                  GradientStop { position: 1.0; color: root.dim(root.accent, 0.16) }
                }
                NumberAnimation on x {
                  from: 8
                  to: scope.width - 8 - beam.width
                  duration: 4200
                  loops: Animation.Infinite
                  running: root.opened && root.tab === "overview"
                }
              }
              Text {
                anchors.right: parent.right
                anchors.rightMargin: 10
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 4
                text: root.histInfo()
                color: root.accent
                font.family: "monospace"
                font.pixelSize: 10
                font.bold: true
              }
            }
          }

          // dedicated threat / banter area (fixed height)
          Rectangle {
            id: special
            y: 104
            width: parent.width
            height: 96
            radius: 8
            property bool hot: root.eng ? root.eng.threats.length > 0 : false
            property real glow: 1
            color: hot ? root.dim(root.cR, 0.08) : root.dim(root.accent, 0.05)
            border.width: hot ? 2 : 1
            border.color: hot ? root.dim(root.cR, 0.35 + 0.65 * glow) : root.dim(root.accent, 0.5)
            clip: true

            SequentialAnimation on glow {
              running: special.hot && root.opened
              loops: Animation.Infinite
              NumberAnimation { to: 0.2; duration: 450 }
              NumberAnimation { to: 1.0; duration: 450 }
            }

            Text {
              visible: !special.hot
              anchors.left: parent.left
              anchors.leftMargin: 14
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - 28
              text: "> " + root.mtxt + (root.mcur ? "_" : " ")
              color: root.accent
              font.family: "monospace"
              font.pixelSize: 15
              elide: Text.ElideRight
            }

            ListView {
              id: threatList
              visible: special.hot
              anchors.fill: parent
              anchors.margins: 6
              spacing: 6
              clip: true
              boundsBehavior: Flickable.StopAtBounds
              model: root.eng ? root.eng.threats : []
              delegate: Rectangle {
                id: tc
                required property var modelData
                width: threatList.width
                height: 78
                radius: 6
                color: root.dim(root.cR, 0.12)
                border.width: 1
                border.color: root.dim(root.cR, 0.8)
                Text {
                  x: 10; y: 6
                  text: "THREAT - " + tc.modelData.label + (tc.modelData.pid ? "  (PID " + tc.modelData.pid + ")" : "")
                  color: root.cR
                  font.family: "monospace"
                  font.pixelSize: 14
                  font.bold: true
                }
                Text {
                  x: 10; y: 28
                  width: parent.width - 120
                  text: tc.modelData.reason
                  color: root.cR
                  font.family: "monospace"
                  font.pixelSize: 11
                  elide: Text.ElideRight
                }
                Text {
                  x: 10; y: 46
                  width: parent.width - 20
                  text: D.hint(tc.modelData)
                  color: root.dim(root.cR, 0.8)
                  font.family: "monospace"
                  font.pixelSize: 10
                  wrapMode: Text.WordWrap
                  maximumLineCount: 2
                  elide: Text.ElideRight
                }
                PwBtn {
                  anchors.right: parent.right
                  anchors.rightMargin: 8
                  y: 6
                  label: "Mark safe"
                  tone: root.cR
                  onClicked: if (root.eng) root.eng.markSafe(tc.modelData.key)
                }
              }
            }
          }

          // process cards: threat > suspicious > safe, sized by severity
          Flickable {
            id: cardsView
            y: 208
            width: parent.width
            height: 138
            contentWidth: width
            contentHeight: flow.height
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Flow {
              id: flow
              width: cardsView.width
              spacing: 6

              Repeater {
                model: root.eng ? root.eng.procs : []
                delegate: Rectangle {
                  id: card
                  required property var modelData
                  readonly property color c: root.tone(modelData.status)
                  readonly property bool isSel: (root.sel || (root.selProc ? root.selProc.key : "")) === modelData.key
                  width: modelData.status === "r" ? 250 : (modelData.status === "y" ? 190 : 164)
                  height: modelData.status === "r" ? 92 : (modelData.status === "y" ? 70 : 54)
                  radius: 7
                  color: isSel ? root.dim(c, 0.16) : root.dim(c, 0.05)
                  border.width: isSel ? 2 : 1
                  border.color: isSel ? c : root.dim(c, 0.5)

                  Text {
                    x: 8; y: 5
                    width: parent.width - 16
                    text: card.modelData.label + (card.modelData.safe ? " [safe]" : "")
                    color: card.c
                    font.family: "monospace"
                    font.pixelSize: card.modelData.status === "r" ? 15 : 11
                    font.bold: true
                    elide: Text.ElideRight
                  }
                  Text {
                    x: 8
                    y: card.modelData.status === "r" ? 30 : 21
                    width: parent.width - 16
                    text: card.modelData.protos.join("/") + " | " + card.modelData.nPorts + " ports | " + card.modelData.nIps + " IPs"
                    color: root.dim(root.fg, 0.75)
                    font.family: "monospace"
                    font.pixelSize: 9
                    elide: Text.ElideRight
                  }
                  Text {
                    visible: card.modelData.status !== "g"
                    x: 8
                    y: card.modelData.status === "r" ? 48 : 37
                    text: card.modelData.status === "r" ? "THREAT" : "SUSPICIOUS"
                    color: card.c
                    font.family: "monospace"
                    font.pixelSize: card.modelData.status === "r" ? 16 : 10
                    font.bold: true
                  }
                  Rectangle {
                    anchors.left: parent.left
                    anchors.leftMargin: 8
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: 6
                    height: 4
                    radius: 2
                    width: Math.min(parent.width - 16, 10 + card.modelData.nPorts * 16)
                    color: card.c
                    opacity: 0.8
                  }
                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.sel = card.modelData.key
                  }
                }
              }
            }
          }

          // details of the selected process
          Rectangle {
            y: 354
            width: parent.width
            height: 82
            radius: 8
            color: "transparent"
            border.width: 1
            border.color: root.selProc ? root.dim(root.tone(root.selProc.status), 0.6) : root.dim(root.accent, 0.35)

            Text {
              anchors.left: parent.left
              anchors.leftMargin: 10
              anchors.right: btnCol.left
              anchors.rightMargin: 10
              anchors.verticalCenter: parent.verticalCenter
              text: root.selProc ? "> " + D.describe(root.selProc) : "> Select a process card to see its details."
              color: root.selProc && root.selProc.status !== "g" ? root.tone(root.selProc.status) : root.fg
              font.family: "monospace"
              font.pixelSize: 11
              wrapMode: Text.WordWrap
              maximumLineCount: 4
              elide: Text.ElideRight
            }
            Column {
              id: btnCol
              anchors.right: parent.right
              anchors.rightMargin: 8
              anchors.verticalCenter: parent.verticalCenter
              spacing: 6
              visible: root.selProc !== null
              PwBtn {
                label: "Mark safe"
                tone: root.accent
                onClicked: if (root.selProc && root.eng) root.eng.markSafe(root.selProc.key)
              }
              PwBtn {
                label: "Mark threat"
                tone: root.cR
                onClicked: if (root.selProc && root.eng) root.eng.markThreat(root.selProc.key)
              }
            }
          }
        }

        // ================================================= network log page
        Item {
          id: pageLog
          y: 60
          width: parent.width
          height: parent.height - 60
          visible: root.tab === "log"

          // top: new remote IPs, full width
          Rectangle {
            id: ipBox
            width: parent.width
            height: 230
            radius: 8
            color: "transparent"
            border.width: 1
            border.color: root.dim(root.accent, 0.4)

            Text {
              x: 10; y: 8
              text: "NEW REMOTE IPs (" + (root.eng ? root.eng.ipsList.length : 0) + ")"
              color: root.cY
              font.family: "monospace"
              font.pixelSize: 11
              font.bold: true
            }
            Text {
              anchors.right: parent.right
              anchors.rightMargin: 10
              y: 9
              text: "yellow = first seen in the last 10 min"
              color: root.dim(root.fg, 0.7)
              font.family: "monospace"
              font.pixelSize: 9
            }
            ListView {
              x: 10; y: 30
              width: parent.width - 20
              height: parent.height - 40
              clip: true
              boundsBehavior: Flickable.StopAtBounds
              model: root.eng ? root.eng.ipsList : []
              delegate: Item {
                id: ipr
                required property var modelData
                width: ListView.view.width
                height: 18
                Text {
                  x: 0
                  width: 300
                  text: ipr.modelData.ip
                  color: Date.now() - ipr.modelData.t < 600000 ? root.cY : root.fg
                  font.family: "monospace"
                  font.pixelSize: 11
                }
                Text {
                  x: 310
                  width: ipr.width - 310 - 50
                  text: ipr.modelData.p
                  color: root.dim(root.fg, 0.8)
                  font.family: "monospace"
                  font.pixelSize: 10
                  elide: Text.ElideRight
                }
                Text {
                  anchors.right: parent.right
                  text: D.ago(ipr.modelData.t)
                  color: root.dim(root.fg, 0.7)
                  font.family: "monospace"
                  font.pixelSize: 10
                }
              }
            }
          }

          // bottom: port numbers by state, three columns
          Item {
            id: portsBox
            y: 238
            width: parent.width
            height: parent.height - 238

            Repeater {
              model: root.eng ? [
                { title: "LISTENING", items: root.eng.ports.listening },
                { title: "ESTABLISHED", items: root.eng.ports.established },
                { title: "UNCONNECTED", items: root.eng.ports.unconnected }
              ] : []
              delegate: Rectangle {
                id: grp
                required property int index
                required property var modelData
                x: index * (width + 8)
                width: (portsBox.width - 16) / 3
                height: portsBox.height
                radius: 8
                color: "transparent"
                border.width: 1
                border.color: root.dim(root.accent, 0.4)

                Text {
                  x: 10; y: 8
                  text: grp.modelData.title + " (" + grp.modelData.items.length + ")"
                  color: root.accent
                  font.family: "monospace"
                  font.pixelSize: 11
                  font.bold: true
                }
                Flickable {
                  x: 10; y: 30
                  width: parent.width - 20
                  height: parent.height - 40
                  contentWidth: width
                  contentHeight: chips.height
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  Flow {
                    id: chips
                    width: parent.width
                    spacing: 4
                    Repeater {
                      model: grp.modelData.items
                      delegate: PwChip { required property string modelData; label: modelData }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
