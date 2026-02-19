#!/usr/bin/env bash
# SpartaRocket Node Bootstrap (Stage-1) — FAIL FAST on critical steps

set -Eeuo pipefail

LOG=/var/log/spartarocket-bootstrap.log
mkdir -p /var/log
exec > >(tee -a "$LOG") 2>&1

ts(){ date -Is; }
ok(){ echo "[OK  $(ts)] $*"; }
warn(){ echo "[WARN $(ts)] $*"; }
die(){ echo "[FATAL $(ts)] $*"; exit 1; }

require_env() {
  local k="$1"
  [[ -n "${!k:-}" ]] || die "Missing env var: $k"
}

# non-critical step (continues)
soft_step() {
  local name="$1"; shift
  echo; echo "===== SOFT STEP: $name ====="
  set +e
  "$@"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then ok "$name"; else warn "$name failed (exit $rc) — continuing"; fi
  return 0
}

# critical step (stops)
hard_step() {
  local name="$1"; shift
  echo; echo "===== HARD STEP: $name ====="
  "$@" || { echo; echo "---- DIAG: $name failed ----"; diag || true; die "$name failed"; }
  ok "$name"
}

diag() {
  echo "[diag] whoami: $(whoami)"
  echo "[diag] uname: $(uname -a)"
  echo "[diag] docker version:"; docker version || true
  echo "[diag] docker compose version:"; docker compose version || true
  echo "[diag] docker ps -a:"; docker ps -a || true
  echo "[diag] systemctl docker:"; systemctl --no-pager -l status docker || true
  echo "[diag] journalctl docker (tail 120):"; journalctl -u docker --no-pager -n 120 || true
}

echo "=== SpartaRocket Stage-1 BEGIN: $(ts) ==="

# ----------------------------
# REQUIRED ENV (from Stage-0)
# ----------------------------
for k in \
  NODE_LABEL PUBLIC_ENDPOINT_DNS TZ \
  ADMIN_USER \
  WG_PUBLIC_PORT WG0_ADDR CLIENT_SUBNET_CIDR \
  MGMT_SUBNET_CIDR WG_MGMT_ADDR WG_MGMT_PORT \
  AGENT_HOST_BIND_IP AGENT_PORT
do
  require_env "$k"
done

HARDEN_SSH="${HARDEN_SSH:-1}"
ADMIN_SUDO_NOPASSWD="${ADMIN_SUDO_NOPASSWD:-1}"
ROOT_PUBKEY="${ROOT_PUBKEY:-}"

# --- support ADMIN_PUBKEY_FILE ---
ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-}"

if [[ -z "$ADMIN_PUBKEY" && -n "$ADMIN_PUBKEY_FILE" && -f "$ADMIN_PUBKEY_FILE" ]]; then
  ADMIN_PUBKEY="$(cat "$ADMIN_PUBKEY_FILE")"
  export ADMIN_PUBKEY
fi
[[ -n "$ADMIN_PUBKEY" ]] || die "Missing ADMIN_PUBKEY (and ADMIN_PUBKEY_FILE missing)"
# --- end support ---

export DEBIAN_FRONTEND=noninteractive

echo "Node: ${NODE_LABEL}"
echo "Endpoint: ${PUBLIC_ENDPOINT_DNS}:${WG_PUBLIC_PORT}"

# ----------------------------
# Packages
# ----------------------------
hard_step "apt-get update" bash -lc 'apt-get update -y'
soft_step "apt-get upgrade" bash -lc 'apt-get -y upgrade || true'

hard_step "install base packages" bash -lc '
apt-get -y install \
  ca-certificates curl git vim jq \
  ufw fail2ban unattended-upgrades \
  wireguard wireguard-tools \
  gnupg lsb-release \
  python3 \
  || exit 1
'

soft_step "set timezone" timedatectl set-timezone "$TZ"
soft_step "enable NTP" timedatectl set-ntp true

# ----------------------------
# Admin user + sudo
# ----------------------------
hard_step "create admin user" bash -lc "
if ! id -u '$ADMIN_USER' >/dev/null 2>&1; then
  adduser --disabled-password --gecos '' '$ADMIN_USER'
fi
usermod -aG sudo '$ADMIN_USER'
"

soft_step "optional sudo NOPASSWD" bash -lc "
if [[ '$ADMIN_SUDO_NOPASSWD' == '1' ]]; then
  cat > /etc/sudoers.d/90-spartarocket-$ADMIN_USER <<EOF
$ADMIN_USER ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 440 /etc/sudoers.d/90-spartarocket-$ADMIN_USER
  visudo -cf /etc/sudoers.d/90-spartarocket-$ADMIN_USER >/dev/null 2>&1 || true
fi
"

# ----------------------------
# SSH key install + hardening
# ----------------------------
KEY_OK=0
hard_step "install SSH key for admin user" bash -lc "
[[ '$ADMIN_PUBKEY' == ssh-* ]] || { echo 'ADMIN_PUBKEY must start with ssh-'; exit 1; }
install -d -m 700 /home/$ADMIN_USER/.ssh
printf '%s\n' '$ADMIN_PUBKEY' > /home/$ADMIN_USER/.ssh/authorized_keys
chmod 600 /home/$ADMIN_USER/.ssh/authorized_keys
chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh
KEYPART=\$(printf '%s' '$ADMIN_PUBKEY' | awk '{print \$2}')
grep -q \"\$KEYPART\" /home/$ADMIN_USER/.ssh/authorized_keys
"
KEY_OK=1

soft_step "optional root SSH pubkey" bash -lc "
if [[ -n '$ROOT_PUBKEY' ]]; then
  install -d -m 700 /root/.ssh
  printf '%s\n' '$ROOT_PUBKEY' > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi
exit 0
"

soft_step "SSH hardening (key-only)" bash -lc "
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
fi
exit 0
"

# ----------------------------
# Firewall (soft — don’t brick)
# ----------------------------
soft_step "UFW baseline rules" bash -lc "
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
soft_step "enable fail2ban" systemctl enable --now fail2ban
soft_step "enable unattended-upgrades" systemctl enable --now unattended-upgrades

# ----------------------------
# Sysctl forwarding
# ----------------------------
hard_step "enable IP forwarding (sysctl)" bash -lc '
cat > /etc/sysctl.d/99-spartarocket.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.src_valid_mark=1
EOF
sysctl --system
'

# ----------------------------
# mgmt wg on host (optional-ish, but should succeed)
# ----------------------------
hard_step "create mgmt hub keys" bash -lc '
umask 077
install -d -m 700 /etc/wireguard
if [[ ! -f /etc/wireguard/mgmt_hub.key ]]; then
  wg genkey | tee /etc/wireguard/mgmt_hub.key | wg pubkey | tee /etc/wireguard/mgmt_hub.pub >/dev/null
fi
'
hard_step "write wg-mgmt0.conf" bash -lc "
cat > /etc/wireguard/wg-mgmt0.conf <<EOF
[Interface]
Address = ${WG_MGMT_ADDR}
ListenPort = ${WG_MGMT_PORT}
PrivateKey = \$(cat /etc/wireguard/mgmt_hub.key)
SaveConfig = false
EOF
"
soft_step "start wg-mgmt0" bash -lc '
systemctl enable --now wg-quick@wg-mgmt0 || true
wg show wg-mgmt0 || true
ip a show wg-mgmt0 || true
exit 0
'

# ----------------------------
# Docker install (CRITICAL)
# ----------------------------
hard_step "install docker + compose plugin" bash -lc '
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  UBUNTU_CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
systemctl is-active --quiet docker
docker version
docker compose version
'

soft_step "add admin to docker group" usermod -aG docker "$ADMIN_USER"

# ----------------------------
# Node envfile (token)
# ----------------------------
hard_step "create /etc/spartarocket/<node>.env" bash -lc "
umask 077
install -d -m 700 /etc/spartarocket
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
TZ=${TZ}
WG_PUBLIC_PORT=${WG_PUBLIC_PORT}
CLIENT_SUBNET_CIDR=${CLIENT_SUBNET_CIDR}
MGMT_SUBNET_CIDR=${MGMT_SUBNET_CIDR}
AGENT_BIND_IP=${AGENT_HOST_BIND_IP}
AGENT_PORT=${AGENT_PORT}
AGENT_TOKEN=\$AGENT_TOKEN
EOF
  chmod 600 \$ENVFILE
fi
test -s \$ENVFILE
grep -q '^AGENT_TOKEN=' \$ENVFILE
"

# ----------------------------
# Deploy WG + Agent (CRITICAL)
# ----------------------------
hard_step "deploy docker wg + agent" bash -lc "
ENVFILE=/etc/spartarocket/${NODE_LABEL}.env
BASE=/opt/spartarocket/${NODE_LABEL}

set -a
source \"\$ENVFILE\"
set +a

mkdir -p \"\$BASE/wg/wg_confs\" \"\$BASE/agent\"

umask 077
if [[ ! -f \"\$BASE/wg/server.key\" ]]; then
  wg genkey | tee \"\$BASE/wg/server.key\" | wg pubkey | tee \"\$BASE/wg/server.pub\" >/dev/null
fi
WG_PRIV=\$(cat \"\$BASE/wg/server.key\")

cat > \"\$BASE/wg/wg_confs/wg0.conf\" <<EOF
[Interface]
Address = ${WG0_ADDR}
ListenPort = \${WG_PUBLIC_PORT}
PrivateKey = \${WG_PRIV}
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT
EOF

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
PY

cat > \"\$BASE/docker-compose.yml\" <<EOF
services:
  wg:
    image: lscr.io/linuxserver/wireguard:latest
    container_name: sr-wg-\${NODE_LABEL}
    cap_add: [NET_ADMIN, SYS_MODULE]
    environment:
      - PUID=0
      - PGID=0
      - TZ=\${TZ}
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
    depends_on: [wg]
    environment:
      - AGENT_TOKEN=\${AGENT_TOKEN}
      - WG_CONTAINER=sr-wg-\${NODE_LABEL}
      - WG_IFACE=wg0
    volumes:
      - ./agent:/app
      - /var/run/docker.sock:/var/run/docker.sock
    working_dir: /app
    ports:
      - \"\${AGENT_BIND_IP}:\${AGENT_PORT}:\${AGENT_PORT}/tcp\"
    command: >
      sh -lc \"apk add --no-cache docker-cli wireguard-tools &&
              pip install --no-cache-dir fastapi uvicorn pydantic &&
              python -m uvicorn app:APP --host 0.0.0.0 --port \${AGENT_PORT}\"
    restart: unless-stopped
EOF

# HARD checks
test -f \"\$BASE/docker-compose.yml\"
docker compose --env-file \"\$ENVFILE\" -f \"\$BASE/docker-compose.yml\" up -d
docker compose --env-file \"\$ENVFILE\" -f \"\$BASE/docker-compose.yml\" ps
docker ps | grep -E \"sr-wg-\${NODE_LABEL}|sr-agent-\${NODE_LABEL}\"
"

echo "=== SpartaRocket Stage-1 END: $(ts) ==="
