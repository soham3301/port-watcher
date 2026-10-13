# Port Watcher

A tiny security monitor for the [Omarchy](https://omarchy.org) 4 (Quattro) bar. A 210px terminal-style display shows your established network connections, and clicking it opens a popup with the details.

It exists to make two situations easier to notice: a backdoor on your machine, and a malicious program talking to a remote server.

> Port Watcher is an awareness tool, not a detector you can rely on against a skilled attacker. A quiet widget does not mean a clean machine. See [Limits](#limits).

## What you see

**Bar display (210px, left section by default)**

- A rounded border with small glowing dots travelling around it: one dot per process name. A dot is green and slow for up to 5 remote IPs, yellow and one step faster for more than 5, and red, pulsing and faster still for more than 50. A suspicious (yellow) or threat (red) process always gets a yellow or red dot. The dots are spaced evenly around the border.
- A terminal-style line (`> text_`) that types, backspaces and types again: process lines, counts of listening, established and unconnected ports, new remote IPs, unknown processes and warnings.
- A blinking light on the right: green (slow) = safe, yellow (faster) = suspicious, red (rapid) = threat.
- During a threat the display is locked: red text alternating `INSPECT THE THREAT - PID n` with the threat details, until you neutralize it.

**Popup (click the display, fixed size, uses your Omarchy theme)**

- **Overview:** a donut chart of connections per process, a live oscilloscope-style trace of your connection count over the last minute, a dedicated threat area, and process cards.
- **Threat area:** shows scrollable red threat cards when something is wrong, and a few witty typed lines when everything is quiet.
- **Process cards:** threats are drawn larger than suspicious ones, which are larger than safe ones. Select a card to see its details, with **Mark safe** and **Mark threat** buttons.
- **Network log:** new remote IPs on top (newest first, last 300 shown), port numbers by state (listening, established, unconnected) below.
- **Bar display toggles:** a transparent background (default is black), system text color (default is green) and no border (hides the border line while the dots keep flowing). These change only the bar display, not the popup.

The popup takes its colors from the Omarchy theme (accent, background and urgent colors). Suspicious items stay yellow, because themes don't define a yellow.

## How alerts work

Everything is keyed on the **process name**, the most stable value. PIDs change, local ports are random, and remote IPs keep moving. When the owner of a socket is hidden, the key is the protocol plus ports, for example `unknown UDP 68 to 67`.

### Red (threat)

Red turns the light red, locks the display on the threat, and stays until you click **Mark safe**.

| Rule                                                                                   | Why it matters                                                |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| A new process name opens a connection                                                  | Something you have never run before is talking to the network |
| A shell or netcat-type process (bash, sh, nc, ncat, socat ...) holds a live connection | Classic reverse shell                                         |
| A connection to a backdoor-style port (4444, 1337, 31337, 6667, 9001)                  | Common backdoor and IRC bot ports                             |
| The binary runs from `/tmp`, `/dev/shm`, `/var/tmp`, or was deleted from disk          | Typical of dropped malware                                    |
| You click **Mark threat**                                                              | Your own call                                                 |

### Yellow (suspicious)

Yellow is not a card you have to deal with. It turns the light yellow and types a warning in the mini display for 10 seconds, then returns to green by itself.

**Warnings tied to a process** (the process card also turns yellow for 10 seconds):

- A known process connects to a new remote IP
- A known process uses a new local port below 32768
- A new TCP listener appears (marked `exposed` when bound to all interfaces)
- One process reaches 10 or more new IPs within a minute (fan-out)
- The same destination reconnects at regular intervals (beaconing)
- Upload spike (over 1.5 MB/s) to an IP first seen in the last 10 minutes
- A browser connects to a non-standard remote port

**Warnings not tied to a process** (display only, nothing to mark):

- A browser opens 5 or more new high ports (32768 and up) between two scans: `5 new ports opened by chromium`
- Every 10 new remote IPs logged: `10 new remote IPs logged - check network log for details`
- More than 50 new remote IPs this session (and again past 100, 150 ...)
- Connection surge: established connections jump to at least 10 more than, and 1.5 times, the recent average
- First connection ever to a remote port you have not used before

Marking a process safe silences the red and yellow rules tied to it. The general warnings above still appear.

On the very first run the plugin learns what is already running as a silent baseline, so you do not start with a wall of red.

## Requirements

- Omarchy 4 (Quattro) with the Quickshell-based shell
- `ss` (from iproute2) and `ls` (from coreutils), both part of a standard Omarchy install
- No other dependencies. The plugin never uses sudo and never writes to your Omarchy configuration; it only writes its own state file (see below).

## Install

```sh
omarchy plugin add https://github.com/soham3301/port-watcher.git --enable
```

The manifest declares the left bar section as the default. To put it somewhere else:

```sh
omarchy plugin enable io.github.soham3301.port-watcher --section center
```

`--section` can be `left`, `center` or `right`. Leave out `--enable` to add the plugin disabled so you can read the source first, then enable it later with the command above.

For a manual install, copy this folder to `~/.config/omarchy/plugins/io.github.soham3301.port-watcher/`, then run:

```sh
omarchy-shell shell rescanPlugins
omarchy plugin enable io.github.soham3301.port-watcher
```

## Update

```sh
omarchy plugin update io.github.soham3301.port-watcher
```

## Remove

```sh
omarchy plugin remove io.github.soham3301.port-watcher
```

Removing the plugin deletes its folder but not the data it saved. To wipe that too:

```sh
rm -rf ~/.local/state/io.github.soham3301.port-watcher
```

If an entry for the plugin is still listed in `~/.config/omarchy/shell.json`, delete it by hand.

## What it runs and stores

- Runs `ss -H -tupani` every 2 seconds, and `ls -l -- /proc/<pid>/exe` for newly seen PIDs (PIDs are checked to be digits only). It also runs `mkdir -p` once to create its state folder. All commands use fixed argument lists: no shell, no sudo, no network access of its own.
- Stores its state in `$XDG_STATE_HOME/io.github.soham3301.port-watcher/state.json` (default `~/.local/state/io.github.soham3301.port-watcher/state.json`):
    - the safe list and known process names
    - seen remote IPs, capped at 5000 (once full, each new IP is logged and the oldest are dropped; an IP that was dropped counts as new if it appears again)
    - known listening ports and known remote ports
    - the three bar display toggles
- Delete that file to reset everything.
- Like every Omarchy plugin, it runs unsandboxed inside `omarchy-shell`. Read the source before enabling it.

## Limits

- Without root, PID and process name are only visible for your own processes. Root-owned sockets appear as `unknown` with `PID hidden`. The plugin never uses sudo; the details text tells you to inspect them yourself with root privileges.
- The binary-path rule only works for processes you own.
- Connections are sampled every 2 seconds, so a connection that opens and closes between two samples is never seen.
- Unconnected UDP traffic (most DNS tunnelling and QUIC) has no remote address in `ss` and is not visible. Rootkits can hide sockets from `ss`.
- Loopback connections (127.0.0.1, ::1) are ignored.
- Malware that talks to normal services (cloud APIs, chat platforms) looks like normal traffic.
- Some red rules can fire on harmless software: a package update can leave a running program "deleted from disk", AppImages run from a temp path, and some apps use the listed ports. Read the reason on the threat card, and mark it safe if it is expected.

For real protection, run it next to tools built for it, such as OpenSnitch or auditd.

Files:

- `manifest.json`: plugin manifest
- `BarWidget.qml`: the 210px bar display
- `Panel.qml`: the popup
- `PortEngine.qml`: polling, detection rules, saved state
- `Detector.js`: parsing and text helpers

## License

MIT, see [LICENSE](LICENSE).
