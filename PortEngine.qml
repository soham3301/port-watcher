import QtQuick
import Quickshell
import Quickshell.Io
import "Detector.js" as D

// Port Watcher engine: polls `ss`, applies the detection rules, keeps state on disk.
// Loaded once as the plugin service; all monitor widgets share this engine.
// Runs only fixed commands (ss, ls, mkdir). No shell, no sudo, no network access.
Item {
  id: eng

  // ---- published state (replaced as whole objects so bindings update)
  property string status: "g"          // g = safe, y = suspicious, r = threat
  property var procs: []
  property var threats: []
  property var ipsList: []
  property var ports: ({ listening: [], established: [], unconnected: [] })
  property var dots: []
  property var hist: []
  property int connCount: 0
  property int listenCount: 0
  property int unconCount: 0
  property int uniqueIps: 0
  property int newThisSession: 0
  property int rev: 0
  property bool transparentBg: false
  property bool systemText: false
  property bool stateReady: false
  signal interrupt()

  readonly property string stateDir: (Quickshell.env("XDG_STATE_HOME")
      || (Quickshell.env("HOME") + "/.local/state")) + "/io.github.soham3301.port-watcher"
  readonly property string statePath: stateDir + "/state.json"

  // ---- internal (mutated in place, not bound to the UI)
  property var st: ({
    first: true, scans: 0, known: {}, safe: {}, ips: {}, listeners: {}, flagged: {},
    yellowUntil: {}, exe: {}, newIpTimes: {}, fanAt: {}, lps: {}, sentPrev: {},
    prevPresent: {}, app: {}, beaconed: {}, recentEv: {}, events: [], sess: {},
    per: {}, ri: 0, alt: 0, ti: 0, dirty: false, ipsDirty: true,
    rports: {}, prevHigh: {}, portWarnAt: {}, notices: [], ni: 0, m10: 0, m50: 0, connHist: [], surgeAt: 0
  })

  // ---------------------------------------------------------------- persistence
  Process {
    id: mk
    command: ["mkdir", "-p", eng.stateDir]
    onExited: function () { fv.path = eng.statePath }
  }

  FileView {
    id: fv
    path: ""
    printErrors: false
    onLoaded: eng.loadState(fv.text())
    onLoadFailed: eng.loadState("")
  }

  Component.onCompleted: mk.running = true

  function loadState(txt) {
    var ok = false;
    try {
      var o = JSON.parse(txt);
      if (o && o.v === 1) {
        st.known = o.known || {};
        st.safe = o.safe || {};
        st.ips = o.ips || {};
        st.listeners = o.listeners || {};
        transparentBg = o.transparent === true;
        systemText = o.systemText === true;
        st.rports = o.rports || {};
        ok = true;
      }
    } catch (e) {}
    st.first = !ok;
    stateReady = true;
  }

  function save() {
    if (!st.dirty || !stateReady) return;
    st.dirty = false;
    fv.setText(JSON.stringify({
      v: 1, known: st.known, safe: st.safe, ips: st.ips, listeners: st.listeners,
      rports: st.rports, transparent: transparentBg, systemText: systemText
    }));
  }

  Timer { interval: 4000; repeat: true; running: eng.stateReady; onTriggered: eng.save() }

  function setTransparent(v) { transparentBg = v; st.dirty = true; rev++; }
  function setSystemText(v) { systemText = v; st.dirty = true; rev++; }

  // ---------------------------------------------------------------- polling
  Process {
    id: ssProc
    command: ["ss", "-H", "-tupani"]
    stdout: StdioCollector { onStreamFinished: eng.onScan(D.parseSs(text)) }
  }

  Timer {
    interval: 2000
    repeat: true
    running: eng.stateReady
    triggeredOnStart: true
    onTriggered: if (!ssProc.running) ssProc.running = true
  }

  Process {
    id: exeProc
    stdout: StdioCollector { onStreamFinished: eng.onExe(text) }
  }

  function lookupExe(pids) {
    if (exeProc.running || pids.length === 0) return;
    var args = ["ls", "-l", "--"];
    for (var i = 0; i < pids.length; i++) {
      if (!/^\d+$/.test(pids[i])) continue;
      st.exe[pids[i]] = "";
      args.push("/proc/" + pids[i] + "/exe");
    }
    if (args.length === 3) return;
    exeProc.command = args;
    exeProc.running = true;
  }

  function onExe(text) {
    var lines = text.split("\n");
    for (var i = 0; i < lines.length; i++) {
      var m = /\/proc\/(\d+)\/exe -> (.+)$/.exec(lines[i]);
      if (m) st.exe[m[1]] = m[2];
    }
  }

  // ---------------------------------------------------------------- rules
  function pushEvent(segs, now) {
    var text = segs.join(" - ");
    if (st.recentEv[text] && now - st.recentEv[text] < 20000) return;
    st.recentEv[text] = now;
    st.notices.push({ segs: segs, until: now + 10000 });
    if (st.notices.length > 8) st.notices.shift();
    interrupt();
  }

  function markYellow(key, segs, now) {
    if (st.safe[key]) return;
    st.yellowUntil[key] = now + 10000;
    pushEvent(segs, now);
  }

  function flag(key, reason, r, now) {
    if (st.safe[key] || st.flagged[key]) return;
    st.flagged[key] = {
      key: key, label: D.labelFor(key), reason: reason,
      pid: r && r.pid ? r.pid : "", since: now
    };
  }

  function onScan(recs) {
    var now = Date.now();
    var base = st.first;          // very first run: learn the baseline silently
    var warm = st.scans > 0;      // session-only memories need one scan to fill
    var per = {}, est = [], lis = [], con = [];
    var newIps = {}, presentNow = {}, connNow = {}, lookups = [], highNow = {};
    var learnPorts = base || Object.keys(st.rports).length === 0;
    var i, k, r;

    for (i = 0; i < recs.length; i++) {
      r = recs[i];
      if (r.kind === "listen") { if (r.proto === "TCP") lis.push(r); continue; }
      if (r.kind === "uncon") { con.push(r); continue; }
      if (r.kind !== "est" || D.isLoopback(r.rip)) continue;
      est.push(r);

      var key = D.keyFor(r);
      var p = per[key];
      if (!p) {
        p = per[key] = { key: key, label: D.labelFor(key), unknown: !r.comm, pids: {},
                         protos: {}, lports: {}, rports: {}, ips: {}, conns: 0 };
      }
      p.conns++;
      p.protos[r.proto] = 1;
      p.lports[r.lport] = 1;
      p.rports[r.rport] = 1;
      p.ips[r.rip] = 1;
      if (r.pid) p.pids[r.pid] = 1;
      st.sess[r.rip] = 1;

      // RED: new process name
      if (!st.known[key] && !st.safe[key]) {
        if (base) st.known[key] = 1;
        else flag(key, "New process name opened a connection", r, now);
      }
      // RED: shell or netcat style process with a live connection (reverse shell)
      if (D.SHELLS.indexOf(r.comm) >= 0)
        flag(key, "Shell or netcat process holds a live connection", r, now);
      // RED: classic backdoor ports
      if (D.BAD_PORTS.indexOf(r.rport) >= 0)
        flag(key, "Connection to backdoor-style port " + r.rport, r, now);
      // RED: binary in a temp path or deleted from disk
      if (r.pid) {
        var ex = st.exe[r.pid];
        if (ex === undefined) { if (lookups.indexOf(r.pid) < 0) lookups.push(r.pid); }
        else if (ex && D.badExe(ex))
          flag(key, "Binary runs from a temp path or was deleted: " + ex, r, now);
      }

      // YELLOW: new remote IP (persisted list)
      if (!st.ips[r.rip]) {
        st.ips[r.rip] = { t: now, p: key };
        st.dirty = true;
        st.ipsDirty = true;
        if (!base) {
          newThisSession++;
          var ni = newIps[key] || (newIps[key] = { n: 0, port: r.rport });
          ni.n++;
          var arr = st.newIpTimes[key] || (st.newIpTimes[key] = []);
          arr.push(now);
        }
      }
      // YELLOW: new non-ephemeral local port for a known process
      if (r.lport < D.EPHEMERAL_MIN) {
        var lp = st.lps[key] || (st.lps[key] = {});
        if (!lp[r.lport]) {
          lp[r.lport] = 1;
          if (!base && warm && st.known[key])
            markYellow(key, ["New local port opened", key, "port " + r.lport], now);
        }
      }
      // YELLOW: browser using a non-standard remote port
      if (D.BROWSERS.indexOf(r.comm) >= 0 && D.BROWSER_OK_PORTS.indexOf(r.rport) < 0)
        markYellow(key, ["Browser on odd port", key, "port " + r.rport], now);
      // NOTICE: first connection ever to this remote port
      if (r.rport > 0 && !st.rports[r.rport]) {
        st.rports[r.rport] = 1;
        st.dirty = true;
        if (!learnPorts) pushEvent(["First connection to port " + r.rport, key], now);
      }
      // bookkeeping for the browser high-port notice
      if (D.BROWSERS.indexOf(r.comm) >= 0 && r.lport >= D.EPHEMERAL_MIN) {
        var hp = highNow[key] || (highNow[key] = {});
        hp[r.lport] = 1;
      }
      // YELLOW: upload spike to a recently first-seen IP
      if (r.sent !== undefined) {
        var ck = r.proto + "|" + r.lport + "|" + r.rip + "|" + r.rport;
        connNow[ck] = 1;
        var pv = st.sentPrev[ck];
        if (pv && now > pv.t) {
          var rate = (r.sent - pv.b) * 1000 / (now - pv.t);
          var ipr = st.ips[r.rip];
          if (rate > 1500000 && ipr && now - ipr.t < 600000)
            markYellow(key, ["Upload spike detected", key, D.fmtRate(rate)], now);
        }
        st.sentPrev[ck] = { b: r.sent, t: now };
      }
      presentNow[key + "|" + r.rip + "|" + r.rport] = key;
    }

    // YELLOW: new IPs per process and fan-out
    for (k in newIps) {
      if (st.flagged[k]) continue;
      markYellow(k, ["New remote IP detected", newIps[k].n + " over " + newIps[k].port], now);
    }
    for (k in st.newIpTimes) {
      var ts = st.newIpTimes[k].filter(function (t) { return now - t < 60000; });
      st.newIpTimes[k] = ts;
      if (ts.length >= 10 && (!st.fanAt[k] || now - st.fanAt[k] > 60000)) {
        st.fanAt[k] = now;
        markYellow(k, ["Fan-out detected", k, ts.length + " new IPs in 60s"], now);
      }
    }

    // NOTICE: a browser opened 5 or more new high ports since the last scan
    for (k in highNow) {
      var fresh = 0, prevH = st.prevHigh[k] || {};
      for (var hpPort in highNow[k]) if (!prevH[hpPort]) fresh++;
      if (warm && fresh >= 5 && (!st.portWarnAt[k] || now - st.portWarnAt[k] > 15000)) {
        st.portWarnAt[k] = now;
        pushEvent([fresh + " new ports opened by " + k], now);
      }
    }
    st.prevHigh = highNow;

    // NOTICE: new remote IP volume (every 10, and again past 50, 100, ...)
    if (!base) {
      if (Math.floor(newThisSession / 10) > st.m10) {
        st.m10 = Math.floor(newThisSession / 10);
        pushEvent([newThisSession + " new remote IPs logged", "check network log for details"], now);
      }
      if (newThisSession > 50 * (st.m50 + 1)) {
        st.m50++;
        pushEvent(["Over " + (50 * st.m50) + " new remote IPs this session", "check network log, unusual volume"], now);
      }
    }

    // NOTICE: sudden jump in the number of established connections
    var chh = st.connHist;
    if (warm && chh.length >= 3) {
      var avg = 0;
      for (var q = 0; q < chh.length; q++) avg += chh[q];
      avg /= chh.length;
      if (est.length >= avg + 10 && est.length >= avg * 1.5 && now - st.surgeAt > 30000) {
        st.surgeAt = now;
        pushEvent(["Connection surge", "from about " + Math.round(avg) + " to " + est.length], now);
      }
    }
    chh.push(est.length);
    if (chh.length > 8) chh.shift();

    // YELLOW: beaconing (same destination reconnecting at regular intervals)
    for (var bk in presentNow) {
      if (st.prevPresent[bk] || !warm) continue;
      var ap = st.app[bk] || (st.app[bk] = []);
      ap.push(now);
      if (ap.length > 6) ap.shift();
      if (ap.length >= 5 && !st.beaconed[bk]) {
        var gaps = [], sum = 0;
        for (var g = 1; g < ap.length; g++) { gaps.push(ap[g] - ap[g - 1]); sum += ap[g] - ap[g - 1]; }
        var mean = sum / gaps.length, varr = 0;
        for (g = 0; g < gaps.length; g++) varr += (gaps[g] - mean) * (gaps[g] - mean);
        var sd = Math.sqrt(varr / gaps.length);
        if (mean >= 6000 && mean <= 900000 && sd / mean < 0.15) {
          st.beaconed[bk] = 1;
          var bp = bk.split("|");
          markYellow(presentNow[bk], ["Beaconing detected", bp[0], bp[1]], now);
        }
      }
    }
    for (var ak in st.app) {
      var al = st.app[ak];
      if (now - al[al.length - 1] > 1200000) { delete st.app[ak]; delete st.beaconed[ak]; }
    }
    st.prevPresent = presentNow;

    // YELLOW: new listeners, noting wildcard binds (reachable from the network)
    for (i = 0; i < lis.length; i++) {
      r = lis[i];
      var lk = "tcp:" + r.lport;
      if (st.listeners[lk]) continue;
      st.listeners[lk] = 1;
      st.dirty = true;
      if (base) continue;
      var lkey = r.comm || ("unknown TCP " + r.lport);
      markYellow(lkey, ["New listener detected", "port " + r.lport, r.comm || "unknown",
                        D.isWildcard(r.lhost) ? "exposed" : "local only"], now);
    }

    for (var sk in st.sentPrev) if (!connNow[sk]) delete st.sentPrev[sk];
    for (var ek in st.recentEv) if (now - st.recentEv[ek] > 60000) delete st.recentEv[ek];

    // ports panel data
    var pl = {}, pe = {}, pu = {};
    for (i = 0; i < lis.length; i++) pl["tcp:" + lis[i].lport + " " + (lis[i].comm || "?")] = 1;
    for (i = 0; i < est.length; i++) pe[(est[i].comm || "?") + " " + est[i].lport + ">" + est[i].rport] = 1;
    for (i = 0; i < con.length; i++) pu["udp:" + con[i].lport + " " + (con[i].comm || "?")] = 1;
    ports = {
      listening: Object.keys(pl).slice(0, 100),
      established: Object.keys(pe).slice(0, 100),
      unconnected: Object.keys(pu).slice(0, 100)
    };

    st.per = per;
    connCount = est.length;
    listenCount = Object.keys(pl).length;
    unconCount = Object.keys(pu).length;
    uniqueIps = Object.keys(st.sess).length;
    var h = hist.slice();
    h.push(est.length);
    if (h.length > 30) h.shift();
    hist = h;
    st.first = false;
    st.scans++;
    if (lookups.length > 0) lookupExe(lookups.slice(0, 40));
    publish();
  }

  function publish() {
    var now = Date.now();
    var ord = { r: 0, y: 1, g: 2 };
    var pl = [], k;
    for (k in st.per) {
      var p = st.per[k];
      var lps = Object.keys(p.lports), ipl = Object.keys(p.ips);
      pl.push({
        key: k, label: p.label, unknown: p.unknown, pids: Object.keys(p.pids),
        protos: Object.keys(p.protos), lports: lps, rports: Object.keys(p.rports), ipList: ipl,
        nPorts: lps.length, nIps: ipl.length, conns: p.conns, safe: !!st.safe[k],
        status: st.flagged[k] ? "r" : ((st.yellowUntil[k] || 0) > now ? "y" : "g")
      });
    }
    pl.sort(function (a, b) { return ord[a.status] - ord[b.status] || b.conns - a.conns; });
    procs = pl;

    var th = [];
    for (k in st.flagged) th.push(st.flagged[k]);
    th.sort(function (a, b) { return b.since - a.since; });
    threats = th;

    var d = [];
    for (var i = 0; i < pl.length && i < 10; i++)
      d.push({ key: pl[i].key, status: pl[i].status, speed: 30 + 25 * pl[i].nPorts });
    dots = d;

    if (st.ipsDirty) {
      capIps();
      var ks = Object.keys(st.ips);
      ks.sort(function (a, b) { return st.ips[b].t - st.ips[a].t; });
      ipsList = ks.slice(0, 300).map(function (ip) { return { ip: ip, p: st.ips[ip].p, t: st.ips[ip].t }; });
      st.ipsDirty = false;
    }

    var anyY = false;
    for (var yk in st.yellowUntil) { if (st.yellowUntil[yk] > now) { anyY = true; break; } }
    st.notices = st.notices.filter(function (n) { return n.until > now; });
    if (st.notices.length > 0) anyY = true;
    var ns = th.length > 0 ? "r" : (anyY ? "y" : "g");
    var changed = ns !== status && (ns === "r" || status === "r");
    status = ns;
    rev++;
    if (changed) interrupt();
  }

  // Keeps at most 5000 remembered remote IPs: every new IP is logged, the oldest are dropped.
  function capIps() {
    var keys = Object.keys(st.ips);
    if (keys.length <= 5000) return;
    keys.sort(function (a, b) { return st.ips[a].t - st.ips[b].t; });
    var drop = keys.length - 5000;
    for (var i = 0; i < drop; i++) delete st.ips[keys[i]];
    st.dirty = true;
  }

  // ---------------------------------------------------------------- actions
  function findProc(key) {
    for (var i = 0; i < procs.length; i++) if (procs[i].key === key) return procs[i];
    return null;
  }

  function markSafe(key) {
    delete st.flagged[key];
    delete st.yellowUntil[key];
    st.safe[key] = 1;
    st.known[key] = 1;
    st.dirty = true;
    save();
    publish();
    interrupt();
  }

  function markThreat(key) {
    var p = findProc(key);
    delete st.safe[key];
    st.flagged[key] = {
      key: key, label: D.labelFor(key), reason: "Marked as a threat by you",
      pid: p && p.pids.length ? p.pids[0] : "", since: Date.now()
    };
    st.dirty = true;
    save();
    publish();
    interrupt();
  }

  // ---------------------------------------------------------------- bar text scheduler
  // Priority: threats (locked) > new events > rotation of process and summary lines.
  function rotationLines() {
    var a = [], i;
    for (i = 0; i < procs.length; i++) {
      var p = procs[i];
      var s = D.procSegs(p);
      a.push(s);
      if (p.status === "y") a.push(s);
      if (p.unknown) a.push(["Unknown process", s[3], "detected"]);
    }
    var b = [
      ["Listening ports", listenCount + " detected"],
      ["Established ports", connCount + " detected"],
      ["Unconnected ports", unconCount + " detected"],
      ["New remote IPs", newThisSession + " this session"],
      ["Active connections", String(connCount)],
      ["Unique remote IPs", uniqueIps + " seen"]
    ];
    var out = [];
    for (i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i]) out.push(a[i]);
      if (b[i]) out.push(b[i]);
    }
    return out;
  }

  function nextLine() {
    if (threats.length > 0) {
      var t = threats[st.ti % threats.length];
      st.alt = st.alt ? 0 : 1;
      if (st.alt) return ["INSPECT THE THREAT", t.pid ? "PID " + t.pid : "PID hidden"];
      st.ti++;
      return D.threatSegs(t, findProc(t.key));
    }
    var nowT = Date.now();
    var act = st.notices.filter(function (n) { return n.until > nowT; });
    if (act.length > 0) return act[st.ni++ % act.length].segs;
    var L = rotationLines();
    if (L.length === 0) return ["Watching the network", "nothing established"];
    return L[st.ri++ % L.length];
  }
}
