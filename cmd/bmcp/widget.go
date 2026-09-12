package main

import (
	"fmt"
	"strings"
)

// The widget the host mounts for a finder call, and a static shell by
// necessity: the host reads this resource while the tool input is still
// streaming, so a drawing inlined here could only be the previous call's.
// It asks for its own call's drawing instead, named by the arguments the host
// hands it — the one thing both ends of this can see.
const widgetTemplate = `<div style="font:13px system-ui,-apple-system,sans-serif">
<div id="pic"><p style="color:#6b7280">Drawing the neighbourhood…</p></div>
</div>
<script>
(function () {
  var nextId = 1, pending = {}, asked = false;
  function send(m) { window.parent.postMessage(m, "*"); }
  function call(method, params) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      pending[id] = { resolve: resolve, reject: reject };
      send({ jsonrpc: "2.0", id: id, method: method, params: params });
    });
  }
  function size() {
    var r = document.body.getBoundingClientRect();
    send({ jsonrpc: "2.0", method: "ui/notifications/size-changed",
           params: { width: Math.ceil(r.width), height: Math.ceil(r.height) } });
  }
  function settle(html) {
    document.getElementById("pic").innerHTML = html;
    size();
  }
  // Keyed the way the server keys it: sorted keys, no HTML escaping, FNV-1a
  // over the UTF-8 bytes.
  function canon(v) {
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    return "{" + Object.keys(v).sort().map(function (k) {
      return JSON.stringify(k) + ":" + canon(v[k]);
    }).join(",") + "}";
  }
  function digest(args) {
    var bytes = new TextEncoder().encode(canon(args || {})), h = 2166136261;
    for (var i = 0; i < bytes.length; i++) {
      h = (h ^ bytes[i]) >>> 0;
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h.toString(16);
  }
  // The arguments name the call, so the drawing asked for here is this call's
  // and no other. The server holds the answer until that call has run.
  function fetchPicture(args) {
    if (asked) return;
    asked = true;
    call("resources/read", { uri: %q + "?call=" + digest(args) }).then(function (res) {
      var svg = res && res.contents && res.contents[0] && res.contents[0].text;
      settle(svg || '<p style="color:#6b7280">No graph for this answer.</p>');
    }).catch(function () {
      settle('<p style="color:#6b7280">Could not reach bmcp for this picture.</p>');
    });
  }
  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.jsonrpc !== "2.0") return;
    if (d.method === "ui/notifications/tool-input") {
      fetchPicture(d.params && d.params.arguments);
      return;
    }
    if (d.id === undefined || !pending[d.id]) return;
    var p = pending[d.id];
    delete pending[d.id];
    if (d.error) p.reject(new Error(d.error.message || "error")); else p.resolve(d.result);
  });
  new ResizeObserver(size).observe(document.body);

  call("ui/initialize", {
    protocolVersion: "2025-11-21",
    appInfo: { name: "bmcp", version: %q },
    appCapabilities: {}
  }).then(function () {
    // A host sends the tool input only to a widget that has announced itself.
    send({ jsonrpc: "2.0", method: "ui/notifications/initialized", params: {} });
  });
})();
</script>`

func widgetHTML() string {
	return fmt.Sprintf(widgetTemplate, pictureURI, version)
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
