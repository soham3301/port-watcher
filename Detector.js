.pragma library

// Port Watcher - stateless helpers (parsing, labels, text segments).

var EPHEMERAL_MIN = 32768;
var BAD_PORTS = [4444, 1337, 31337, 6667, 9001];
var SHELLS = ["bash", "sh", "zsh", "fish", "dash", "ash", "nc", "ncat", "netcat", "socat"];
var BROWSERS = ["firefox", "firefox-bin", "Web Content", "WebExtensions", "Isolated Web Co",
                "chromium", "chrome", "google-chrome", "brave", "vivaldi-bin", "opera", "msedge",
                "librewolf", "zen"];
var BROWSER_OK_PORTS = [80, 443, 8080, 8443, 853, 5228];

function splitHostPort(s) {
  var i = s.lastIndexOf(":");
  if (i < 0) return { host: s, port: 0 };
  var host = s.substring(0, i).replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  var port = parseInt(s.substring(i + 1), 10);
  if (host.indexOf("::ffff:") === 0) host = host.substring(7);
  return { host: host, port: isNaN(port) ? 0 : port };
}

function isLoopback(h) {
  return h.indexOf("127.") === 0 || h === "::1" || h === "localhost";
}

function isWildcard(h) {
  return h === "*" || h === "0.0.0.0" || h === "::";
}

function badExe(p) {
  return /^\/(tmp|dev\/shm|var\/tmp)\//.test(p) || /\(deleted\)\s*$/.test(p);
}

function fmtRate(b) {
  return (b / 1048576).toFixed(1) + " MB/s";
}

function ago(t) {
  var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

// Parses the output of: ss -H -tupani
function parseSs(text) {
  var out = [], last = null, lines = text.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (!ln) continue;
    if (/^\s/.test(ln)) {
      if (last) {
        var bm = /bytes_sent:(\d+)/.exec(ln);
        if (bm) last.sent = parseInt(bm[1], 10);
      }
      continue;
    }
    var m = /^(\S+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*(.*)$/.exec(ln);
    if (!m) { last = null; continue; }
    var proto = m[1] === "tcp" ? "TCP" : (m[1] === "udp" ? "UDP" : "");
    if (!proto) { last = null; continue; }
    var l = splitHostPort(m[3]);
    var r = splitHostPort(m[4]);
    var pm = /\("([^"]*)",pid=(\d+)/.exec(m[5] || "");
    var st = m[2];
    last = {
      proto: proto,
      kind: st === "ESTAB" ? "est" : (st === "LISTEN" ? "listen" : (st === "UNCONN" ? "uncon" : "other")),
      lhost: l.host, lport: l.port,
      rip: r.host, rport: r.port,
      comm: pm ? pm[1] : "",
      pid: pm ? pm[2] : "",
      sent: undefined
    };
    out.push(last);
  }
  return out;
}

// Process key: the process name, or protocol + ports when the owner is hidden.
function keyFor(r) {
  if (r.comm) return r.comm;
  var lp = r.lport >= EPHEMERAL_MIN ? "*" : String(r.lport);
  return "unknown " + r.proto + " " + lp + " to " + r.rport;
}

function labelFor(key) {
  return key.replace(" * to ", " ports to ");
}

function pidText(p) {
  if (!p.pids.length) return "PID hidden";
  return "PID " + p.pids[0] + (p.pids.length > 1 ? "+" : "");
}

// Segments of one typed line: [TCP - PID - name - ports - ip]
function procSegs(p) {
  var lp = p.lports.length > 1 ? "multiple ports" : "port " + p.lports[0];
  var rp = p.rports.length > 1 ? "multiple" : String(p.rports[0]);
  var ip = p.ipList.length > 1 ? "multiple ip" : p.ipList[0];
  return [p.protos.join("/"), pidText(p), p.unknown ? "unknown" : p.key, lp + " to " + rp, ip];
}

function threatSegs(t, p) {
  return p ? procSegs(p) : [t.label, t.reason];
}

function describe(p) {
  var who = p.unknown ? "This unknown process (" + p.label + ")" : "Process \"" + p.key + "\"";
  var pid = p.pids.length ? "PID " + p.pids[0] : "PID hidden";
  var lp = p.lports.length > 1 ? p.lports.length + " local ports" : "port " + p.lports[0];
  var rp = p.rports.length > 1 ? p.rports.length + " remote ports" : "port " + p.rports[0];
  var ip = p.ipList.length > 1 ? p.ipList.length + " remote IPs" : p.ipList[0];
  var s = who + " (" + pid + ") is connected from " + lp + " to " + rp + " on " + ip +
          " over " + p.protos.join("/") + ". ";
  if (p.unknown || !p.pids.length)
    s += "Use root privileges to check its details (sudo ss -tupnp), then mark it safe if it is a system process.";
  else
    s += "Inspect it with: sudo ls -l /proc/" + p.pids[0] + "/exe . If it is a system process, mark it safe.";
  return s;
}

function hint(t) {
  return t.pid ? "Inspect: sudo ls -l /proc/" + t.pid + "/exe  then mark safe if it is a system process"
               : "Use root privileges (sudo ss -tupnp) to inspect, then mark safe if it is a system process";
}

// Splits segments into pieces that fit the small display.
function chunkify(segs, limit) {
  var out = [], cur = "";
  for (var i = 0; i < segs.length; i++) {
    var s = String(segs[i]);
    while (s.length > limit) {
      if (cur) { out.push(cur); cur = ""; }
      var cut = s.lastIndexOf(" ", limit);
      if (cut < 6) cut = limit;
      out.push(s.substring(0, cut));
      s = s.substring(cut).replace(/^\s+/, "");
    }
    var t = cur ? cur + " - " + s : s;
    if (t.length > limit && cur) { out.push(cur); cur = s; } else { cur = t; }
  }
  if (cur) out.push(cur);
  return out;
}
