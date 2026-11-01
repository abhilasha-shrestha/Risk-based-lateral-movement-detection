#!/bin/sh
# ---------------------------------------------------------------------------
# Laptop B — per-VM setup (Alpine Linux). Run as root on EACH lab VM.
#
# Usage:   ./alpine-setup.sh <this-host-id> <laptop-A-ip>
#   e.g.   ./alpine-setup.sh ws-01 10.10.10.1
#
# <this-host-id> must match a host_id in lab/lab_topology.json
# (foothold | ws-01 | ws-02 | jump-01 | fileserver-01) because the
# listener maps the syslog hostname to the destination host.
# <laptop-A-ip> is the address of the analytics laptop running the listener.
# ---------------------------------------------------------------------------
set -e
HOSTID="$1"
LAPTOP_A="$2"
if [ -z "$HOSTID" ] || [ -z "$LAPTOP_A" ]; then
  echo "usage: $0 <this-host-id> <laptop-A-ip>"; exit 1
fi

echo "[1/6] set hostname to $HOSTID"
hostname "$HOSTID"
echo "$HOSTID" > /etc/hostname

echo "[2/6] install openssh + rsyslog"
apk update >/dev/null
apk add openssh rsyslog >/dev/null

echo "[3/6] enable + start sshd"
rc-update add sshd default
# allow password auth so the demo can type logins by hand
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# optional for the demo only: allow root login by password
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
rc-service sshd restart

echo "[4/6] create demo users (alice, bob) with known passwords"
for u in alice bob; do
  id "$u" >/dev/null 2>&1 || adduser -D "$u"
  echo "$u:Passw0rd!" | chpasswd
done

echo "[5/6] forward auth.log to Laptop A ($LAPTOP_A:5514) over TCP"
cat > /etc/rsyslog.d/90-forward.conf <<EOF
# Send sshd auth events to the analytics listener.
# Both facilities: sshd's own "Failed/Accepted password" lines go to AUTH
# (SyslogFacility AUTH is the OpenSSH default); PAM's go to AUTHPRIV.
# Selecting authpriv alone forwards the PAM noise and drops every scored event.
auth,authpriv.*  @@${LAPTOP_A}:5514
EOF
rc-update add rsyslog default
rc-service rsyslog restart

echo "[6/6] done. host=$HOSTID forwarding to $LAPTOP_A:5514"
echo "Test from another VM:  ssh alice@$HOSTID"
