# Phase 4 — live ingest, lab, and demo

Three ways to run, in increasing realism:
- **A. Single laptop, simulator** — no VMs. Best for testing and as the demo fallback.
- **B. Single laptop, SSH to self** — exercises real sshd + rsyslog on one machine.
- **C. Two laptops** — the full deliverable (Laptop B = network, Laptop A = analytics).

All three feed the **same** listener on Laptop A, so what you test in A/B is what runs in C.

---

## Laptop A — the analytics node (always required)

From WSL, with containers up and Phases 1-3 loaded:

```bash
cd /mnt/c/Users/abhil/Desktop/DBMS && source .venv/bin/activate
docker compose up -d

# 1. start the live syslog listener (parses sshd -> scores on arrival)
python ingest/listener.py            # listens on 0.0.0.0:5514

# 2. in another terminal: the dashboard, with Live mode ticked
streamlit run dashboard/app.py       # http://localhost:8501
```

The listener seeds the 5 lab hosts from `lab/lab_topology.json` (sensitivities,
IP->host map) on startup. Leave both running during the demo.

---

## A. Single-laptop test with the simulator (recommended first)

With the listener running, in a third terminal:

```bash
python demo/simulate_attack.py --speed 0.3
```

Expected (seen in the listener output):
```
[OK ] alice@ws-01 ...                      -> quiet
[FAIL] bob@ws-01 ... (x4)
[OK ] bob@ws-01 ...   *** ALERT score 60   (failed_then_success + new_host)
[OK ] bob@jump-01 ...                       (35, no alert)
[OK ] bob@fileserver-01 ... *** ALERT 75    (sensitive + rapid_movement)
```

Then reconstruct the fileserver alert (or click **Reconstruct** on the dashboard):

```bash
python graph/reconstruct.py <that-alert-id>
# -> foothold -> ws-01 -> jump-01 -> fileserver-01   (Neo4j nodes at rest: 0)
```

This validates the entire Laptop-A pipeline without any VMs.

---

## B. Single-laptop test with real SSH (optional, more realistic)

Install sshd + rsyslog on the WSL Ubuntu itself and forward to the listener:

```bash
sudo apt-get install -y openssh-server rsyslog
# NOTE: 'auth' as well as 'authpriv' -- sshd's own Failed/Accepted password
# lines use SyslogFacility AUTH; only PAM's lines are authpriv.
echo 'auth,authpriv.*  @@127.0.0.1:5514' | sudo tee /etc/rsyslog.d/90-forward.conf
sudo service rsyslog restart && sudo service ssh restart
sudo useradd -m bob && sudo chpasswd <<< 'bob:Passw0rd!'
```

Then `ssh bob@localhost` (wrong password a few times, then right) and watch the
listener. Note: with one host the *hostname* is always the same, so this tests
the parse/score path, not multi-host movement. For movement, use A or C.

To confirm the plumbing itself, start the listener with `-v` so it echoes every
forwarded line before parsing:

```bash
python ingest/listener.py -v
logger -p authpriv.info TEST_FORWARDING_123     # in another terminal
```

`logger` lines are not sshd events, so without `-v` the listener drops them
silently and the test looks like a failure when forwarding is in fact fine.

Best one-shot smoke test — a fake sshd line on the facility sshd really uses.
It exercises forward -> parse -> store without touching ssh at all, and should
print `[FAIL] selftest@...` in the listener:

```bash
logger -p auth.info -t "sshd[99999]" "Failed password for selftest from 10.10.10.11 port 22 ssh2"
```

Swap `auth.info` for `authpriv.info` to tell the two facilities apart: if only
the authpriv one arrives, `90-forward.conf` is still selecting `authpriv.*`.
Check the TCP session is up with `ss -tnp | grep 5514` — an `ESTAB` pair means
rsyslog is connected and the problem is downstream of the network.

---

## C. Two laptops — the full lab (deliverable)

### Laptop A
- Find its IP on the shared network: `ip addr` (WSL) or `ipconfig` (Windows).
- Make sure port **5514/tcp** is reachable from Laptop B (allow it through the
  Windows firewall; in WSL2 you may need `netsh interface portproxy` to forward
  5514 from the Windows host to WSL, or run the listener where Laptop B can reach it).
- Run the listener and dashboard as above.

### Laptop B — 5 Alpine VMs in VirtualBox
1. Create one Alpine VM (1 vCPU, 256 MB, 2 GB disk). Install Alpine, add the
   two network adapters:
   - **Internal Network** (`intnet`) — VM↔VM traffic, static IPs 10.10.10.10-14.
   - **Host-only / Bridged** — so the VM can reach Laptop A.
2. Copy `lab/alpine-setup.sh` into the VM and run it as root, once per role:
   ```sh
   ./alpine-setup.sh ws-01 <LAPTOP_A_IP>
   ```
   Do this for `foothold`, `ws-01`, `ws-02`, `jump-01`, `fileserver-01`
   (clone the VM and just re-run with a different host-id + fix the IP).
3. Set each VM's internal-network IP to match `lab/lab_topology.json`
   (10.10.10.10 … 10.10.10.14), or edit the JSON to match your IPs and restart
   the listener.
4. Verify forwarding: run the listener with `-v` on Laptop A, then on a VM run
   `logger -p authpriv.info test`; the line should appear as `[raw ] ...` in the
   listener output. (Without `-v` only sshd auth lines are printed.)

### Run the demo
Follow `attack/demo_runbook.md` — type the SSH logins by hand on Laptop B and
watch alerts + the path appear on Laptop A's dashboard.

---

## Evaluation (report numbers) — still to do

Not built yet: the precision/recall-vs-threshold sweep, alerts-per-day table,
the SQL-recursive-CTE vs Neo4j comparison, and the index study. These produce
report content, not demo content (plan §7, cut-list items 2 & 4). Ask to build
`eval/metrics.py` when you want them.

---

## Troubleshooting
- `docker` missing in WSL after reboot → start Docker Desktop, then `docker compose up -d`.
- Listener dies when a WSL terminal closes → run it in a terminal you keep open
  (or `nohup ... &` from a `wsl` shell you leave running).
- No events arriving in C → firewall on 5514, or WSL2 port-forwarding; test with
  `logger` first (step 4 above).
- Listener prints only `[raw ]` PAM lines (`<85>`/`<86>`, "session opened",
  "PAM N more authentication failures") and never a `[FAIL]`/`[OK ]` → the
  rsyslog selector is `authpriv.*` only. sshd's own `Failed password` /
  `Accepted password` lines are facility **auth** (`<38>`), so they are written
  to `auth.log` (selector `auth,authpriv.*`) but never forwarded. Use
  `auth,authpriv.*` in `90-forward.conf`.
- Listener silent although `/var/log/auth.log` has the logins and `ss -tnp |
  grep 5514` shows an `ESTAB` pair → the forwarded line format. rsyslog 8.x on
  Ubuntu 22.04+ forwards RFC3339 timestamps (`2026-10-31T20:18:42.904904+00:00`)
  while Alpine sends traditional RFC3164 (`Oct 31 20:18:42`); the listener now
  accepts both. Run with `-v` to see exactly what is arriving.
