import QtQuick

// Bespoke vector Hex Container Radar icon for DevDock.
// Draws a crisp geometric hexagon housing a `>_` terminal chevron and a live
// corner status beacon (idle, active accent, or urgent PROD/alert red).
Item {
  id: root

  property real iconSize: 16
  property color strokeColor: "#FFFFFF"
  property color accentColor: "#38BDF8"
  property color urgentColor: "#F43F5E"
  property bool active: false
  property bool urgent: false

  implicitWidth: iconSize
  implicitHeight: iconSize
  width: iconSize
  height: iconSize

  onStrokeColorChanged: canvas.requestPaint()
  onAccentColorChanged: canvas.requestPaint()
  onUrgentColorChanged: canvas.requestPaint()
  onActiveChanged: canvas.requestPaint()
  onUrgentChanged: canvas.requestPaint()
  onWidthChanged: canvas.requestPaint()
  onHeightChanged: canvas.requestPaint()

  Canvas {
    id: canvas
    anchors.fill: parent
    antialiasing: true
    renderStrategy: Canvas.Cooperative

    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      ctx.clearRect(0, 0, width, height)

      var s = Math.min(width, height)
      if (s <= 0) return
      var cx = width / 2
      var cy = height / 2
      var r = s * 0.43
      var lw = Math.max(1.25, s * 0.095)

      var mainColor = root.urgent
        ? root.urgentColor
        : (root.active ? root.accentColor : root.strokeColor)

      // Outer hexagon (flat-pointed top/bottom container silhouette)
      ctx.save()
      ctx.beginPath()
      for (var i = 0; i < 6; i++) {
        var angle = (Math.PI / 180) * (60 * i - 90)
        var px = cx + r * Math.cos(angle)
        var py = cy + r * Math.sin(angle)
        if (i === 0) ctx.moveTo(px, py)
        else ctx.lineTo(px, py)
      }
      ctx.closePath()
      ctx.strokeStyle = mainColor
      ctx.lineWidth = lw
      ctx.lineJoin = "round"
      ctx.stroke()

      // Subtle inner fill when active or urgent
      if (root.active || root.urgent) {
        ctx.fillStyle = mainColor
        ctx.globalAlpha = root.urgent ? 0.20 : 0.14
        ctx.fill()
      }
      ctx.restore()

      // Inner terminal chevron `>` + prompt underscore `_`
      ctx.save()
      ctx.strokeStyle = root.urgent ? root.urgentColor : root.strokeColor
      ctx.lineWidth = Math.max(1.2, s * 0.095)
      ctx.lineCap = "round"
      ctx.lineJoin = "round"

      // `>`
      ctx.beginPath()
      ctx.moveTo(cx - r * 0.42, cy - r * 0.28)
      ctx.lineTo(cx - r * 0.10, cy)
      ctx.lineTo(cx - r * 0.42, cy + r * 0.28)
      ctx.stroke()

      // `_`
      ctx.beginPath()
      ctx.moveTo(cx + r * 0.06, cy + r * 0.26)
      ctx.lineTo(cx + r * 0.42, cy + r * 0.26)
      ctx.stroke()
      ctx.restore()

      // Live corner beacon dot (top-right vertex highlight when active/urgent)
      if (root.active || root.urgent) {
        ctx.save()
        var dotR = Math.max(1.8, s * 0.145)
        var dx = cx + r * 0.72
        var dy = cy - r * 0.62
        ctx.beginPath()
        ctx.arc(dx, dy, dotR, 0, Math.PI * 2)
        ctx.fillStyle = root.urgent ? root.urgentColor : root.accentColor
        ctx.fill()
        ctx.restore()
      }
    }
  }
}
