# Manual demo runbook

Perform the attack by hand — no cracking tools. SSH records the same log
lines whether you type the password or a script does, and typing is clearer
for the audience. You know every password because you set them in setup.

Accounts (from `lab/alpine-setup.sh`): `alice` / `bob`, password `Passw0rd!`.

Keep two windows visible: a terminal on the lab (Laptop B, or the simulator
on Laptop A) and the dashboard with **Live mode** ticked.

| # | Do this | Say this | Dashboard |
|---|---------|----------|-----------|
| 1 | `ssh alice@ws-01` (correct pw), then `exit` | "Alice's normal login — the system stays quiet." | score ~5, no alert |
| 2 | `ssh bob@ws-01` — type a **wrong** password 3-4 times, then the right one | "Someone's fumbling at the door, then gets in." | **alert**, reason `failed_then_success` |
| 3 | from ws-01: `ssh bob@jump-01` | "Now moving to a machine Bob has never used." | score rises (`new_host`) |
| 4 | from jump-01: `ssh bob@fileserver-01` | "And onto the file server — a sensitive host." | **alert crosses threshold** |
| 5 | On the dashboard, open the fileserver alert → **Reconstruct path** | "No single login looks wrong — the *shape* of the chain gives it away." | path `foothold → ws-01 → jump-01 → fileserver-01`, Neo4j nodes at rest = 0 |

> If the VM network misbehaves, switch to the replay/simulator on Laptop A:
> `python demo/simulate_attack.py --speed 0.3` reproduces the exact same
> alerts and path. Decide in the first 5 seconds; do not debug on stage.

**Honesty note for the viva:** you type known passwords, so you are
*demonstrating* the log signature of an attack, not performing a real
break-in. The detector reads the log either way.
