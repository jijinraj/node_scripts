#!/usr/bin/env bash
# SpartaRocket Node Bootstrap (Stage-1, generic)
# - NO node-specific addresses hardcoded
# - Reads env vars from Stage-0
# - Continues even if a step fails (logs error + moves on)

set -u
set -o pipefail

LOG=/var/log/spartarocket-bootstrap.log
mkdir -p /var/log
exec > >(tee -a "$LOG") 2>&1

ts(){ date -Is; }
ok(){ echo "[OK  $(ts)] $*"; }
err(){ echo "[ERR $(ts)] $*"; }

require_env() {
  local k="$1"
  if [[ -z "${!k:-}" ]]; then
    echo "FATAL: Missing env var: $k"
    exit 1
  fi
}

step() {
  local name="$1"; shift
  echo
  echo "===== STEP: $name ====="
  set +e
  "$@"
  local rc=$?
  set -e 2>/dev/null || true
  if [[ $rc -eq 0 ]]; then ok "$name"; else err "$name failed (exit $rc) — continuing"; fi
  return 0
}

echo "=== SpartaRocket Stage-1 BEGIN: $(ts) ==="

# ----------------------------
# REQUIRED env vars (from Stage-0)
# ----------------------------
for k in \
  ADMIN_USER ADMIN_PUBKEY \
  NODE_LABEL PUBLIC_ENDPOINT_DNS TZ \
  WG_PUBLIC_PORT WG0_ADDR CLIENT_SUBNET_CIDR \
  MGMT_SUBNET_CIDR WG_MGMT_ADDR WG_MGMT_PORT \
  AGENT_HOST_BIND_IP AGENT_PORT
do
  require_env "$k"
done

# Optional toggles
HARDEN_SSH="${HARDEN_SSH:-1}"
ADMIN_SUDO_NOPASSWD="${ADMIN_SUDO_NOPASSWD:-1}"
ROOT_PUBKEY="${ROOT_PUBKEY:-}"

export DEBIAN_FRONTEND=noninteractive

echo "Node: ${NODE_LABEL}"
echo "Endpoint: ${PUBLIC_ENDPOINT_DNS}:${WG_PUBLIC_PORT}"

# ----------------------------
# Base packages (avoid iptables-persistent on your image)
# ----------------------------
step "apt-get update (retry)" bash -lc '
for i in 1 2 3; do
  apt-get update && exit 0
  echo "apt-get update failed (try $i/3), sleeping..."
  sleep 3
done
exit 0
'

step "apt-get upgrade" bash -lc 'apt-get -y upgrade || true'

step "install base packages" bash -lc '
apt-get -y install \
  ca-certificates curl git vim jq \
  ufw fail2ban unattended-upgrades \
  wireguard \
  gnupg lsb-release \
  python3 \
  || true
'

# ----------------------------
# Time
# ----------------------------
step "set timezone" timedatectl set-timezone "$TZ"
step "enable NTP" timedatectl set-ntp true

# ----------------------------
# Admin user + sudo
# IMPORTANT: if user has no password, sudo would normally ask for one.
# We optionally enable NOPASSWD for bootstrap convenience.
# ----------------------------
step "create admin user" bash -lc "
if ! id -u '$ADMIN_USER' >/dev/null 2>&1; then
  adduser --disabled-password --gecos '' '$ADMIN_USER' || true
fi
usermod -aG sudo '$ADMIN_USER' || true
"

step "optional sudo NOPASSWD" bash -lc "
if [[ '$ADMIN_SUDO_NOPASSWD' == '1' ]]; then
  cat > /etc/sudoers.d/90-spartarocket-$ADMIN_USER <<EOF
$ADMIN_USER ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 440 /etc/sudoers.d/90-spartarocket-$ADMIN_USER
  visudo -cf /etc/sudoers.d/90-spartarocket-$ADMIN_USER >/dev/null 2>&1 || true
fi
"

# ----------------------------
# SSH keys
# ----------------------------
KEY_OK=0
step "install SSH key for admin user" bash -lc "
if [[ '$ADMIN_PUBKEY' != ssh-* ]]; then
  echo 'ADMIN_PUBKEY must start with ssh-'
  exit 1
fi
install -d -m 700 /home/$ADMIN_USER/.ssh
echo '$ADMIN_PUBKEY' > /home/$ADMIN_USER/.ssh/authorized_keys
chmod 600 /home/$ADMIN_USER/.ssh/authorized_keys
chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh

# verify key line exists
grep -q \"$(echo "$ADMIN_PUBKEY" | awk "{print \\$2}")\" /home/$ADMIN_USER/.ssh/authorized_keys
"
if [[ $? -eq 0 ]]; then KEY_OK=1; fi

step "optional root SSH pubkey" bash -lc "
if [[ -n '$ROOT_PUBKEY' ]]; then
  install -d -m 700 /root/.ssh
  echo '$ROOT_PUBKEY' > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi
exit 0
"

# ----------------------------
# SSH hardening (only after key installed)
# ----------------------------
step "SSH hardening (key-only)" bash -lc "
mkdir -p /etc/ssh/sshd_config.d
if [[ '$HARDEN_SSH' == '1' && $KEY_OK -eq 1 ]]; then
  cat > /etc/ssh/sshd_config.d/99-spartarocket.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
X11Forwarding no
PermitRootLogin no
EOF
  systemctl restart ssh || systemctl restart sshd || true
else
  echo 'Skipping SSH hardening (either HARDEN_SSH=0 or key not confirmed).'
fi
exit 0
"

# ----------------------------
# Firewall
# ----------------------------
step "UFW baseline rules" bash -lc "
ufw default deny incoming || true
ufw default allow outgoing || true

ufw allow 22/tcp || true
ufw allow 443/tcp || true
ufw allow '${WG_PUBLIC_PORT}/udp' || true
ufw allow '${WG_MGMT_PORT}/udp' || true

ufw allow from '${MGMT_SUBNET_CIDR}' to any port '${AGENT_PORT}' proto tcp || true
ufw deny '${AGENT_PORT}/tcp' || true

ufw --force enable || true
ufw status verbose || true
exit 0
"

step "enable fail2ban" systemctl enable --now fail2ban

# unattended upgrades non-interactive
step "enable unattended-upgrades" bash -lc '
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl restart unattended-upgrades 2>/dev/null || true
exit 0
'

# ----------------------------
# Forwarding
# ----------------------------
step "enable IP forwarding (sysctl)" bash -lc '
cat > /etc/sysctl.d/99-spartarocket.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.src_valid_mark=1
EOF
sysctl --system || true
exit 0
'

# ----------------------------
# Mgmt hub WG on host (wg-mgmt0)
# ----------------------------
step "create mgmt hub keys" bash -lc '
umask 077
install -d -m 700 /etc/wireguard || true
if [[ ! -f /etc/wireguard/mgmt_hub.key ]]; then
  wg genkey | tee /etc/wireguard/mgmt_hub.key | wg pubkey | tee /etc/wireguard/mgmt_hub.pub >/dev/null || true
fi
exit 0
'

step "write wg-mgmt0.conf" bash -lc "
if [[ -f /etc/wireguard/mgmt_hub.key ]]; then
  cat > /etc/wireguard/wg-mgmt0.conf <<EOF
[Interface]
Address = ${WG_MGMT_ADDR}
ListenPort = ${WG_MGMT_PORT}
PrivateKey = \$(cat /etc/wireguard/mgmt_hub.key)
SaveConfig = false
EOF
fi
exit 0
"

step "start wg-mgmt0" bash -lc '
systemctl enable --now wg-quick@wg-mgmt0 || true
wg show wg-mgmt0 || true
ip a show wg-mgmt0 || true
exit 0
'

# ----------------------------
# Docker install (official repo)
# ----------------------------
step "install docker (official repo)" bash -lc '
if command -v docker >/dev/null 2>&1; then exit 0; fi
install -m 0755 -d /etc/apt/keyrings || true
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || true
chmod a+r /etc/apt/keyrings/docker.gpg || true
UBUNTU_CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list || true
apt-get update || true
apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || true
systemctl enable --now docker || true
exit 0
'

step "add admin to docker group" usermod -aG docker "$ADMIN_USER"

# ----------------------------
# Generate server-side secret env file (AGENT_TOKEN)
# ----------------------------
step "create /etc/spartarocket/<node>.env" bash -lc "
umask 077
install -d -m 700 /etc/spartarocket || true
ENVFILE=/etc/spartarocket/${NODE_LABEL}.env
if [[ ! -f \$ENVFILE ]]; then
  AGENT_TOKEN=\$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)
  cat > \$ENVFILE <<EOF
NODE_LABEL=${NODE_LABEL}
PUBLIC_ENDPOINT_DNS=${PUBLIC_ENDPOINT_DNS}
WG_PUBLIC_PORT=${WG_PUBLIC_PORT}
CLIENT_SUBNET_CIDR=${CLIENT_SUBNET_CIDR}
MGMT_SUBNET_CIDR=${MGMT_SUBNET_CIDR}
AGENT_BIND_IP=${AGENT_HOST_BIND_IP}
AGENT_PORT=${AGENT_PORT}
AGENT_TOKEN=\$AGENT_TOKEN
EOF
  chmod 600 \$ENVFILE || true
fi
exit 0
"

# ----------------------------
# Deploy WG + Agent via Docker
# Agent binds to mgmt IP and controls wg via docker socket (docker exec into wg container)
# ----------------------------
step "deploy docker wg + agent" bash -lc "
command -v docker >/dev/null 2>&1 || exit 0

ENVFILE=/etc/spartarocket/${NODE_LABEL}.env
BASE=/opt/spartarocket/${NODE_LABEL}
mkdir -p \"\$BASE/wg/wg_confs\" \"\$BASE/agent\" || true
chmod 700 \"\$BASE\" \"\$BASE/wg\" \"\$BASE/agent\" 2>/dev/null || true

# server keypair
umask 077
if [[ ! -f \"\$BASE/wg/server.key\" ]]; then
  wg genkey | tee \"\$BASE/wg/server.key\" | wg pubkey | tee \"\$BASE/wg/server.pub\" >/dev/null || true
fi

WG_PRIV=\$(cat \"\$BASE/wg/server.key\")

# WG server config (inside container)
cat > \"\$BASE/wg/wg_confs/wg0.conf\" <<EOF
[Interface]
Address = ${WG0_ADDR}
ListenPort = ${WG_PUBLIC_PORT}
PrivateKey = \${WG_PRIV}

PostUp   = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT
EOF

# Agent app (written on host, runs in agent container)
cat > \"\$BASE/agent/app.py\" <<'PY'
import os, subprocess, tempfile
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

APP = FastAPI(title="SpartaRocket vpn-agent")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
WG_CONTAINER = os.environ.get("WG_CONTAINER", "")
WG_IFACE = os.environ.get("WG_IFACE", "wg0")

def sh(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("cmd failed: " + " ".join(cmd) + " -> " + p.stderr.strip())
    return p.stdout.strip()

def auth(x_token):
    if not AGENT_TOKEN:
        raise HTTPException(status_code=500, detail="AGENT_TOKEN not set")
    if x_token != AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

def wg_exec(args):
    if not WG_CONTAINER:
        raise HTTPException(status_code=500, detail="WG_CONTAINER not set")
    return sh(["docker", "exec", WG_CONTAINER, "wg"] + args)

class AddPeerReq(BaseModel):
    public_key: str
    allowed_ip: str
    preshared_key: str | None = None
    persistent_keepalive: int | None = 25

@APP.get("/health")
def health():
    out = wg_exec(["show", WG_IFACE])
    return {"ok": True, "iface": WG_IFACE, "wg_show": out[:2000]}

@APP.post("/peers/add")
def add_peer(req: AddPeerReq, x_token: str | None = Header(default=None)):
    auth(x_token)
    cmd = ["set", WG_IFACE, "peer", req.public_key, "allowed-ips", req.allowed_ip]
    if req.persistent_keepalive is not None:
        cmd += ["persistent-keepalive", str(req.persistent_keepalive)]
    if req.preshared_key:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(req.preshared_key.strip() + "\n")
            psk_path = f.name
        sh(["docker", "cp", psk_path, f"{WG_CONTAINER}:/tmp/psk"])
        cmd += ["preshared-key", "/tmp/psk"]
    wg_exec(cmd)
    return {"ok": True}

class RemovePeerReq(BaseModel):
    public_key: str

@APP.post("/peers/remove")
def remove_peer(req: RemovePeerReq, x_token: str | None = Header(default=None)):
    auth(x_token)
    wg_exec(["set", WG_IFACE, "peer", req.public_key, "remove"])
    return {"ok": True}
PY

# Compose (NO hardcoded addresses; reads from ENVFILE)
cat > \"\$BASE/docker-compose.yml\" <<EOF
services:
  wg:
    image: lscr.io/linuxserver/wireguard:latest
    container_name: sr-wg-\${NODE_LABEL}
    cap_add: [NET_ADMIN, SYS_MODULE]
    environment:
      - PUID=0
      - PGID=0
      - TZ=\${TZ:-UTC}
    volumes:
      - ./wg:/config
      - /lib/modules:/lib/modules:ro
    ports:
      - \"\${WG_PUBLIC_PORT}:\${WG_PUBLIC_PORT}/udp\"
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv4.ip_forward=1
    restart: unless-stopped

  agent:
    image: python:3.12-alpine
    container_name: sr-agent-\${NODE_LABEL}
    network_mode: \"host\"
    depends_on: [wg]
    environment:
      - AGENT_TOKEN=\${AGENT_TOKEN}
      - WG_CONTAINER=sr-wg-\${NODE_LABEL}
      - WG_IFACE=wg0
      - AGENT_BIND_IP=\${AGENT_BIND_IP}
      - AGENT_PORT=\${AGENT_PORT}
    volumes:
      - ./agent:/app
      - /var/run/docker.sock:/var/run/docker.sock
    working_dir: /app
    command: >
      sh -lc \"apk add --no-cache docker-cli wireguard-tools &&
              pip install --no-cache-dir fastapi uvicorn pydantic &&
              python -m uvicorn app:APP --host \${AGENT_BIND_IP} --port \${AGENT_PORT}\"
    restart: unless-stopped
EOF

docker compose --env-file \"\$ENVFILE\" -f \"\$BASE/docker-compose.yml\" up -d || true
docker ps || true
exit 0
"

# ----------------------------
# Bootstrap notes
# ----------------------------
step "write /root/BOOTSTRAP.md" bash -lc "
PUBKEY=\$(cat /etc/wireguard/mgmt_hub.pub 2>/dev/null || true)
cat > /root/BOOTSTRAP.md <<EOF
SpartaRocket Node Bootstrap
==========================

Node label: ${NODE_LABEL}
Public endpoint: ${PUBLIC_ENDPOINT_DNS}:${WG_PUBLIC_PORT}

Mgmt hub (host):
- Interface: wg-mgmt0
- Address: ${WG_MGMT_ADDR}
- Port: UDP ${WG_MGMT_PORT}
- Subnet: ${MGMT_SUBNET_CIDR}
- Hub public key: \$PUBKEY

Exit node (docker):
- Client subnet: ${CLIENT_SUBNET_CIDR}
- wg0 addr: ${WG0_ADDR}
- Container: sr-wg-${NODE_LABEL}

vpn-agent:
- Bind: ${AGENT_HOST_BIND_IP}:${AGENT_PORT}
- Allowed only from: ${MGMT_SUBNET_CIDR} (UFW)
- Token file: /etc/spartarocket/${NODE_LABEL}.env (chmod 600)

Logs:
- ${LOG}
EOF
chmod 600 /root/BOOTSTRAP.md || true
exit 0
"

echo "=== SpartaRocket Stage-1 END: $(ts) ==="
