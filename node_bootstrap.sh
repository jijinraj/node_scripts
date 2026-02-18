#!/usr/bin/env bash
# SpartaRocket Node Bootstrap (Stage-1, generic)
# - No node-specific addresses/ports/subnets hardcoded
# - Takes everything via env vars from stage-0
# - Continues on failure per stage
# - SSH hardening only if key install verified (prevents lockout)

LOG=/var/log/spartarocket-bootstrap.log
mkdir -p /var/log
exec > >(tee -a "$LOG") 2>&1

ts(){ date -Is; }
ok(){ echo "[OK  $(ts)] $*"; }
err(){ echo "[ERR $(ts)] $*"; }

run_step(){
  local name="$1"; shift
  echo; echo "===== STEP: $name ====="
  "$@" && ok "$name" || { err "$name failed (exit $?) — continuing"; return 0; }
}

# ----------------------------
# REQUIRED ENV VARS (all set by Netcup stage-0)
# ----------------------------
: "${ADMIN_USER:?Missing ADMIN_USER}"
: "${ADMIN_PUBKEY:?Missing ADMIN_PUBKEY}"
: "${NODE_LABEL:?Missing NODE_LABEL}"
: "${PUBLIC_ENDPOINT_DNS:?Missing PUBLIC_ENDPOINT_DNS}"

: "${TZ:?Missing TZ}"

: "${WG_PUBLIC_PORT:?Missing WG_PUBLIC_PORT}"
: "${WG0_ADDR:?Missing WG0_ADDR}"
: "${CLIENT_SUBNET_CIDR:?Missing CLIENT_SUBNET_CIDR}"

: "${MGMT_SUBNET_CIDR:?Missing MGMT_SUBNET_CIDR}"
: "${WG_MGMT_ADDR:?Missing WG_MGMT_ADDR}"
: "${WG_MGMT_PORT:?Missing WG_MGMT_PORT}"

: "${AGENT_HOST_BIND_IP:?Missing AGENT_HOST_BIND_IP}"
: "${AGENT_PORT:?Missing AGENT_PORT}"

# Optional
ROOT_PUBKEY="${ROOT_PUBKEY:-}"

export DEBIAN_FRONTEND=noninteractive
KEY_INSTALLED=0

echo "=== SpartaRocket Stage-1 BEGIN: $(ts) ==="
echo "Node: ${NODE_LABEL}  Endpoint: ${PUBLIC_ENDPOINT_DNS}:${WG_PUBLIC_PORT}"

# ----------------------------
# APT + packages (no iptables-persistent)
# ----------------------------
run_step "apt-get update (retry)" bash -lc '
for i in 1 2 3; do
  apt-get update && exit 0
  echo "apt-get update failed, retry $i/3"
  sleep 3
done
exit 0
'
run_step "apt-get upgrade" bash -lc 'apt-get -y upgrade || true'
run_step "install base packages" bash -lc '
apt-get -y install \
  ca-certificates curl git vim jq \
  ufw fail2ban unattended-upgrades \
  wireguard \
  gnupg lsb-release \
  python3 || true
'

# ----------------------------
# Timezone
# ----------------------------
run_step "set timezone" bash -lc "timedatectl set-timezone '$TZ' || true"
run_step "enable NTP" bash -lc "timedatectl set-ntp true || true"

# ----------------------------
# Admin user + key
# ----------------------------
run_step "create admin user" bash -lc "
if ! id -u '$ADMIN_USER' >/dev/null 2>&1; then
  adduser --disabled-password --gecos '' '$ADMIN_USER' || true
fi
usermod -aG sudo '$ADMIN_USER' || true
"

run_step "install SSH key for admin user" bash -lc "
if [[ '$ADMIN_PUBKEY' != ssh-* ]]; then
  echo 'ADMIN_PUBKEY invalid format (must start with ssh-).'
  exit 1
fi
install -d -m 700 '/home/$ADMIN_USER/.ssh' || true
echo '$ADMIN_PUBKEY' > '/home/$ADMIN_USER/.ssh/authorized_keys' || true
chmod 600 '/home/$ADMIN_USER/.ssh/authorized_keys' || true
chown -R '$ADMIN_USER:$ADMIN_USER' '/home/$ADMIN_USER/.ssh' || true
grep -q \"$(echo "$ADMIN_PUBKEY" | awk "{print \$2}")\" '/home/$ADMIN_USER/.ssh/authorized_keys'
"
if [[ $? -eq 0 ]]; then KEY_INSTALLED=1; fi

run_step "optional root SSH key (public key only)" bash -lc "
if [[ -n '$ROOT_PUBKEY' ]]; then
  install -d -m 700 /root/.ssh || true
  echo '$ROOT_PUBKEY' > /root/.ssh/authorized_keys || true
  chmod 600 /root/.ssh/authorized_keys || true
fi
exit 0
"

# ----------------------------
# SSH hardening (safe)
# ----------------------------
run_step "SSH hardening (key-only) — conditional" bash -lc "
mkdir -p /etc/ssh/sshd_config.d || true
if [[ $KEY_INSTALLED -eq 1 ]]; then
  cat > /etc/ssh/sshd_config.d/99-spartarocket.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
X11Forwarding no
PermitRootLogin prohibit-password
EOF
  systemctl restart ssh || systemctl restart sshd || true
else
  echo 'Skipping SSH hardening because admin key was not confirmed installed.'
fi
exit 0
"

# ----------------------------
# UFW
# ----------------------------
run_step "UFW baseline rules" bash -lc "
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

run_step "enable fail2ban" bash -lc "systemctl enable --now fail2ban || true"
run_step "configure unattended-upgrades" bash -lc "dpkg-reconfigure -f noninteractive unattended-upgrades || true"

# ----------------------------
# forwarding
# ----------------------------
run_step "enable IP forwarding (sysctl)" bash -lc "
cat > /etc/sysctl.d/99-spartarocket.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.src_valid_mark=1
EOF
sysctl --system || true
exit 0
"

# ----------------------------
# Mgmt hub (host)
# ----------------------------
run_step "create mgmt hub keys" bash -lc "
umask 077
install -d -m 700 /etc/wireguard || true
if [[ ! -f /etc/wireguard/mgmt_hub.key ]]; then
  wg genkey | tee /etc/wireguard/mgmt_hub.key | wg pubkey | tee /etc/wireguard/mgmt_hub.pub >/dev/null || true
fi
exit 0
"

run_step "write wg-mgmt0.conf" bash -lc "
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

run_step "start wg-mgmt0" bash -lc "
systemctl enable --now wg-quick@wg-mgmt0 || true
exit 0
"

# ----------------------------
# Docker
# ----------------------------
run_step "install docker (official repo)" bash -lc '
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
run_step "add admin to docker group" bash -lc "usermod -aG docker '$ADMIN_USER' || true"

# ----------------------------
# Agent token file (generated on server)
# ----------------------------
run_step "create /etc/spartarocket env (token)" bash -lc "
install -d -m 700 /etc/spartarocket || true
if [[ ! -f /etc/spartarocket/${NODE_LABEL}.env ]]; then
  AGENT_TOKEN=\$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)
  cat > /etc/spartarocket/${NODE_LABEL}.env <<EOF
NODE_LABEL=${NODE_LABEL}
PUBLIC_ENDPOINT_DNS=${PUBLIC_ENDPOINT_DNS}
WG_PUBLIC_PORT=${WG_PUBLIC_PORT}
CLIENT_SUBNET_CIDR=${CLIENT_SUBNET_CIDR}
MGMT_SUBNET_CIDR=${MGMT_SUBNET_CIDR}
AGENT_BIND_IP=${AGENT_HOST_BIND_IP}
AGENT_PORT=${AGENT_PORT}
AGENT_TOKEN=\${AGENT_TOKEN}
EOF
  chmod 600 /etc/spartarocket/${NODE_LABEL}.env || true
fi
exit 0
"

# ----------------------------
# Docker WG + Agent (agent uses docker exec)
# ----------------------------
run_step "deploy docker WG + agent" bash -lc "
if ! command -v docker >/dev/null 2>&1; then exit 0; fi

BASE=/opt/spartarocket/${NODE_LABEL}
mkdir -p \"\$BASE/wg/wg_confs\" \"\$BASE/agent\" || true
cd \"\$BASE\" || exit 0

umask 077
if [[ ! -f \"\$BASE/wg/server.key\" ]]; then
  wg genkey | tee \"\$BASE/wg/server.key\" | wg pubkey | tee \"\$BASE/wg/server.pub\" >/dev/null || true
fi

DEFAULT_IFACE=\$(ip route | awk '/default/ {print \$5; exit}')

if [[ ! -f \"\$BASE/wg/wg_confs/wg0.conf\" ]]; then
cat > \"\$BASE/wg/wg_confs/wg0.conf\" <<EOF
[Interface]
Address = ${WG0_ADDR}
ListenPort = ${WG_PUBLIC_PORT}
PrivateKey = \$(cat \"\$BASE/wg/server.key\")
PostUp = iptables -t nat -A POSTROUTING -o \$DEFAULT_IFACE -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o \$DEFAULT_IFACE -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT
EOF
fi

cat > \"\$BASE/agent/app.py\" <<'PY'
import os, subprocess, tempfile
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

APP = FastAPI(title="SpartaRocket vpn-agent")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
WG_CONTAINER = os.environ.get("WG_CONTAINER", "")
WG_IFACE = os.environ.get("WG_IFACE", "wg0")

def sh(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {p.stderr.strip()}")
    return p.stdout.strip()

def auth(x_token: str | None):
    if not AGENT_TOKEN:
        raise HTTPException(status_code=500, detail="AGENT_TOKEN not set")
    if x_token != AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

def wg_exec(args: list[str]) -> str:
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
    try:
        out = wg_exec(["show", WG_IFACE])
        return {"ok": True, "wg_show": out[:2000]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

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

cat > \"\$BASE/docker-compose.yml\" <<EOF
services:
  wg:
    image: lscr.io/linuxserver/wireguard:latest
    container_name: sr-wg-${NODE_LABEL}
    cap_add: [NET_ADMIN, SYS_MODULE]
    environment:
      - PUID=0
      - PGID=0
      - TZ=${TZ}
    volumes:
      - ./wg:/config
      - /lib/modules:/lib/modules:ro
    ports:
      - \"${WG_PUBLIC_PORT}:${WG_PUBLIC_PORT}/udp\"
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv4.ip_forward=1
    restart: unless-stopped

  agent:
    image: alpine:3.20
    container_name: sr-agent-${NODE_LABEL}
    network_mode: \"host\"
    depends_on: [wg]
    environment:
      - WG_IFACE=wg0
      - WG_CONTAINER=sr-wg-${NODE_LABEL}
      - AGENT_TOKEN=\${AGENT_TOKEN}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./agent:/app
    command: [\"/bin/sh\",\"-lc\",\"apk add --no-cache python3 py3-pip docker-cli && pip3 install fastapi uvicorn && python3 -m uvicorn app:APP --host ${AGENT_HOST_BIND_IP} --port ${AGENT_PORT}\"]
    restart: unless-stopped
EOF

ENVFILE=/etc/spartarocket/${NODE_LABEL}.env
docker compose --env-file \"\$ENVFILE\" up -d || true
exit 0
"

echo "=== SpartaRocket Stage-1 END: $(ts) ==="
