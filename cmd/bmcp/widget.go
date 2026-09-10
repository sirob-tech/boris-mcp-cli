package main

import (
	"fmt"
	"strings"
)

// The widget the host mounts for a finder call. It shows the picture the
// resource was served with, then asks the app-only tool for a fresher one:
// hosts are allowed to cache a ui:// resource indefinitely, and without the
// second step a cached widget would show the first picture forever.
const widgetTemplate = `<div style="font:13px system-ui,-apple-system,sans-serif">
<div id="pic">%s</div>
<div id="note" style="margin-top:6px;color:#6b7280;font-size:12px"></div>
</div>
<script>
(function () {
  var nextId = 1, pending = {};
  function send(m) { window.parent.postMessage(m, "*"); }
  // No deadline: a host that prompts before allowing an app-initiated call can
  // take as long as the person does, and a discarded late reply would leave the
  // picture stale with nothing to retry it.
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
  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.jsonrpc !== "2.0" || d.id === undefined || !pending[d.id]) return;
    var p = pending[d.id];
    delete pending[d.id];
    if (d.error) p.reject(new Error(d.error.message || "error")); else p.resolve(d.result);
  });
  new ResizeObserver(size).observe(document.body);

  call("ui/initialize", {
    protocolVersion: "2025-11-21",
    appInfo: { name: "bmcp", version: "%s" },
    appCapabilities: {}
  }).then(function () {
    send({ jsonrpc: "2.0", method: "ui/notifications/initialized", params: {} });
    return call("tools/call", { name: "%s", arguments: {} });
  }).then(function (res) {
    var svg = res && res._meta && res._meta.svg;
    if (svg) { document.getElementById("pic").innerHTML = svg; size(); }
  }).catch(function () {
    // The picture already on screen is the one the resource carried, so a host
    // without app-initiated calls still shows a graph.
    var note = document.getElementById("note");
    if (note && !document.querySelector("#pic svg")) {
      note.textContent = "Could not reach bmcp for the current picture.";
      size();
    }
  });
})();
</script>`

const noPictureYet = `<p style="color:#6b7280">No graph has been drawn yet. ` +
	`Ask for a resource by description and the picture appears here.</p>`

func widgetHTML(svg string) string {
	body := noPictureYet
	if svg != "" {
		body = scaleToWidth(svg)
	}
	return fmt.Sprintf(widgetTemplate, body, version, pictureToolName)
}

// scaleToWidth drops the fixed pixel size so the drawing fits the panel it is
// mounted in, keeping the viewBox to preserve its aspect ratio. Markup it cannot
// read comes back untouched: showing it unscaled beats showing nothing.
func scaleToWidth(svg string) string {
	start := strings.Index(svg, "<svg")
	if start < 0 {
		return svg
	}
	end := strings.Index(svg[start:], ">")
	if end < 0 {
		return svg
	}
	open := svg[start : start+end]
	for _, attr := range []string{" width=", " height="} {
		for {
			at := strings.Index(open, attr)
			if at < 0 {
				break
			}
			rest := open[at+len(attr):]
			if len(rest) == 0 || rest[0] != '"' {
				break
			}
			close := strings.Index(rest[1:], `"`)
			if close < 0 {
				break
			}
			open = open[:at] + rest[close+2:]
		}
	}
	return `<svg style="width:100%;height:auto"` + open[len("<svg"):] + svg[start+end:]
}
