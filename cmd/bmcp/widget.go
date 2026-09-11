package main

import (
	"fmt"
	"strings"
)

// The widget the host mounts for a finder call, and a static shell by
// necessity: the host reads this resource while the tool input is still
// streaming, so a drawing inlined here could only be the previous call's. The
// picture arrives instead on the call's own result, which the host forwards as
// ui/notifications/tool-result.
const widgetTemplate = `<div style="font:13px system-ui,-apple-system,sans-serif">
<div id="pic"><p style="color:#6b7280">Drawing the neighbourhood…</p></div>
</div>
<script>
(function () {
  var handshakeId = 1;
  function send(m) { window.parent.postMessage(m, "*"); }
  function size() {
    var r = document.body.getBoundingClientRect();
    send({ jsonrpc: "2.0", method: "ui/notifications/size-changed",
           params: { width: Math.ceil(r.width), height: Math.ceil(r.height) } });
  }
  function settle(html) {
    document.getElementById("pic").innerHTML = html;
    size();
  }
  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.jsonrpc !== "2.0") return;
    // The picture for THIS call, and the only message that carries one. An
    // answer that drew nothing lands here too, so the placeholder never sticks.
    if (d.method === "ui/notifications/tool-result") {
      var svg = d.params && d.params._meta && d.params._meta[%q];
      settle(svg || '<p style="color:#6b7280">No graph for this answer.</p>');
      return;
    }
    // A host forwards the result only to a widget that announced itself, so
    // this notification is what arms the message above.
    if (d.id === handshakeId) {
      send({ jsonrpc: "2.0", method: "ui/notifications/initialized", params: {} });
    }
  });
  new ResizeObserver(size).observe(document.body);

  send({ jsonrpc: "2.0", id: handshakeId, method: "ui/initialize", params: {
    protocolVersion: "2025-11-21",
    appInfo: { name: "bmcp", version: %q },
    appCapabilities: {}
  }});
})();
</script>`

func widgetHTML() string {
	return fmt.Sprintf(widgetTemplate, pictureField, version)
}

// fitWithinPanel makes the drawing responsive without resizing what is in it.
//
// The intrinsic width and height stay: measured in a browser, dropping them
// makes a 926px drawing stretch to 1400 in a wide panel, blowing up 11px labels
// and the raster mark past its source resolution. Keeping them and constraining
// with max-width gives the right behaviour at every width — 400px panel draws
// 400x329, 800px draws 800x658, and anything wider leaves it at 926x762
// untouched. A max-height would only scale the whole drawing, shrinking the
// labels with it, so there is none. Markup it cannot read comes back untouched:
// showing it unscaled beats showing nothing.
func fitWithinPanel(svg string) string {
	start := strings.Index(svg, "<svg")
	if start < 0 {
		return svg
	}
	end := strings.Index(svg[start:], ">")
	if end < 0 {
		return svg
	}
	const fit = `max-width:100%;height:auto;display:block;margin:0 auto`
	return `<svg style="` + fit + `"` + svg[start+len("<svg"):]
}
