#!/usr/bin/env bash
# SpartaRocket Node Bootstrap (Stage-1, generic)
# - Node specifics come only from env vars exported by Stage-0

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
  [[ -n "${!k:-}" ]] || { echo "FATAL: Missing env var: $k"; exit 1; }
}

step() {
  local name="$1"; shift
  echo; echo "===== STEP: $name ====="
  set +e
  "$@"
  local rc=$?
  set -e 2>/dev/null || true
  if [[ $rc -eq 0 ]]; then ok "$name"; else err "$name failed (exit $rc) — continuing"; fi
  return 0
}

echo "=== SpartaRocket Stage-1 BEGIN: $(ts) ==="

# Required env from Stage-0
for k in \
  ADMIN_USER \
  NODE_LABEL PUBLIC_ENDPOINT_DNS TZ \
  WG_PUBLIC_PORT WG0_ADDR CLIENT_SUBNET_CIDR \
  MGMT_SUBNET_CIDR WG_MGMT_ADDR WG_MGMT_PORT \
  AGENT_HOST_BIND_IP AGENT_PORT
do
  require_env "$k"
done

# Admin key can be provided either directly or via file
ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-}"

if [[ -z "$ADMIN_PUBKEY" ]]; then
  if [[ -n "$ADMIN_PUBKEY_FILE" && -f "$ADMIN_PUBKEY_FILE" ]]; then
    ADMIN_PUBKEY="$(cat "$ADMIN_PUBKEY_FILE")"
  fi
fi

if [[ -z "$ADMIN_PUBKEY" ]]; then
  echo "FATAL: Missing ADMIN_PUBKEY (and ADMIN_PUBKEY_FILE not set or file missing)"
  exit 1
fi

# Optional toggles
HARDEN_SSH="${HARDEN_SSH:-1}"
ADMIN_SUDO_NOPASSWD="${ADMIN_SUDO_NOPASSWD:-1}"
ROOT_PUBKEY="${ROOT_PUBKEY:-}"

export DEBIAN_FRONTEND=noninteractive

echo "Node: ${NODE_LABEL}"
echo "Endpoint: ${PUBLIC_ENDPOINT_DNS}:${WG_PUBLIC_PORT}"

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
  wireguard wireguard-tools \
  gnupg lsb-release \
  python3 \
  || true
'

step "set timezone" timedatectl set-timezone "$TZ"
step "enable NTP" timedatectl set-ntp true

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

KEYPART=\$(printf '%s' '$ADMIN_PUBKEY' | awk '{print \$2}')
grep -q \"\$KEYPART\" /home/$ADMIN_USER/.ssh/authorized_keys
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
  echo 'Skipping SSH hardening.'
fi
exit 0
"

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

step "enable unattended-upgrades" bash -lc '
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl restart unattended-upgrades 2>/dev/null || true
exit 0
'

step "enable IP forwarding (sysctl)" bash -lc '
cat > /etc/sysctl.d/99-spartarocket.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.src_valid_mark=1
EOF
sysctl --system || true
exit 0
'

step "create mgmt hub keys" bash -lc '
umask 077
install -d -m 700 /etc/wireguard || true
if [[ ! -f /etc/wireguard/mgmt_hub.key ]]; then
  wg genkey | tee /etc/wireguard/mgmt_hub.key | wg pubkey | tee /etc/wireguard/mgmt_hub.pub >/dev/null || true
fi
exit 0
'

step "write wg-mgmt0.conf" bash -lc "
cat > /etc/wireguard/wg-mgmt0.conf <<EOF
[Interface]
Address = ${WG_MGMT_ADDR}
ListenPort = ${WG_MGMT_PORT}
PrivateKey = \$(cat /etc/wireguard/mgmt_hub.key)
SaveConfig = false
EOF
exit 0
"

step "start wg-mgmt0" bash -lc '
systemctl enable --now wg-quick@wg-mgmt0 || true
wg show wg-mgmt0 || true
ip a show wg-mgmt0 || true
exit 0
'

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
exit 0
"

step "write /root/BOOTSTRAP.md" bash -lc "
PUBKEY=\$(cat /etc/wireguard/mgmt_hub.pub 2>/dev/null || true)
cat > /root/BOOTSTRAP.md <<EOF
Node: ${NODE_LABEL}
Public endpoint: ${PUBLIC_ENDPOINT_DNS}:${WG_PUBLIC_PORT}

Mgmt:
- wg-mgmt0: ${WG_MGMT_ADDR} (UDP ${WG_MGMT_PORT})
- hub pubkey: \$PUBKEY

Agent:
- bind: ${AGENT_HOST_BIND_IP}:${AGENT_PORT}
- env: /etc/spartarocket/${NODE_LABEL}.env
EOF
chmod 600 /root/BOOTSTRAP.md || true
exit 0
"

echo "=== SpartaRocket Stage-1 END: $(ts) ==="
