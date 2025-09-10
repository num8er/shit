#!/usr/bin/env bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Shit Installation Script${NC}"
echo "========================="
echo ""

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (use sudo)${NC}"
  exit 1
fi

if [ ! -d "bin" ]; then
  echo -e "${RED}Error: bin directory not found. Please run ./build.sh first${NC}"
  exit 1
fi

echo "Select what to install:"
echo "1) shit-shell (reverse shell client)"
echo "2) shit-man (server daemon)"
echo "3) shit (CLI tool)"
echo "4) All components"
echo ""
read -p "Enter your choice [1-4]: " choice

install_shit_shell() {
  echo -e "\n${BLUE}Installing shit-shell client...${NC}"

  cp bin/shit-shell /usr/local/bin/
  chmod +x /usr/local/bin/shit-shell

  cat >/etc/systemd/system/shit-shell.service <<EOF
[Unit]
Description=Shit-Shell - Reverse Shell Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shit-shell
Restart=always
RestartSec=5
User=root
Environment="SHIT_MAN_ADDR=127.0.0.1"
Environment="SHIT_KEYS_FILE=/etc/shit/.keys"
Environment="SHIT_DEBUG=false"
WorkingDirectory=/etc/shit

[Install]
WantedBy=multi-user.target
EOF

  mkdir -p /etc/shit
  mkdir -p /etc/shit/logs

  read -p "Enter shit-man server address (default: 127.0.0.1): " server_addr
  if [ ! -z "$server_addr" ]; then
    sed -i "s/SHIT_MAN_ADDR=127.0.0.1/SHIT_MAN_ADDR=$server_addr/" /etc/systemd/system/shit-shell.service
  fi

  systemctl daemon-reload
  systemctl enable shit-shell.service

  echo -e "${GREEN}✓ shit-shell installed successfully${NC}"
  echo "  Binary: /usr/local/bin/shit-shell"
  echo "  Service: /etc/systemd/system/shit-shell.service"
  echo "  Config dir: /etc/shit"
  echo "  Keys file: /etc/shit/.keys"
  echo "  Logs dir: /etc/shit/logs"
  echo ""
  echo "To start: systemctl start shit-shell"
  echo "To check status: systemctl status shit-shell"
}

install_shit_man() {
  echo -e "\n${BLUE}Installing shit-man server...${NC}"

  cp bin/shit-man /usr/local/bin/
  chmod +x /usr/local/bin/shit-man

  cat >/etc/systemd/system/shit-man.service <<EOF
[Unit]
Description=Shit-Man Server - Remote Shell Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shit-man
Restart=always
RestartSec=5
User=root
Environment="SHIT_MAN_LISTEN_AT=0.0.0.0"
Environment="SHIT_SOCKET_PATH=/var/run/shit-man.sock"
Environment="SHIT_AUTHORIZED_KEYS=/etc/shit/.authorized_keys"
Environment="SHIT_SERVER_DEBUG=false"
Environment="SHIT_SERVER_DEBUG_LOG=false"
WorkingDirectory=/etc/shit

[Install]
WantedBy=multi-user.target
EOF

  mkdir -p /etc/shit
  mkdir -p /etc/shit/logs

  read -p "Enter listen address for shit-man (default: 0.0.0.0): " listen_addr
  if [ ! -z "$listen_addr" ]; then
    sed -i "s/SHIT_MAN_LISTEN_AT=0.0.0.0/SHIT_MAN_LISTEN_AT=$listen_addr/" /etc/systemd/system/shit-man.service
  fi

  systemctl daemon-reload
  systemctl enable shit-man.service

  echo -e "${GREEN}✓ shit-man installed successfully${NC}"
  echo "  Binary: /usr/local/bin/shit-man"
  echo "  Service: /etc/systemd/system/shit-man.service"
  echo "  Config dir: /etc/shit"
  echo "  Keys file: /etc/shit/.authorized_keys"
  echo "  Logs dir: /etc/shit/logs"
  echo "  Socket: /var/run/shit-man.sock"
  echo ""
  echo "To start: systemctl start shit-man"
  echo "To check status: systemctl status shit-man"
}

install_shit() {
  echo -e "\n${BLUE}Installing shit CLI tool...${NC}"

  cp bin/shit /usr/local/bin/
  chmod +x /usr/local/bin/shit

  cat >/etc/profile.d/shit.sh <<'EOF'
export SHIT_SOCKET_PATH="/var/run/shit-man.sock"
EOF

  echo -e "${GREEN}✓ shit installed successfully${NC}"
  echo "  Binary: /usr/local/bin/shit"
  echo ""
  echo "Run 'shit' to start the CLI"
}

case $choice in
1)
  install_shit_shell
  ;;
2)
  install_shit_man
  ;;
3)
  install_shit
  ;;
4)
  install_shit_shell
  install_shit_man
  install_shit
  ;;
*)
  echo -e "${RED}Invalid choice${NC}"
  exit 1
  ;;
esac

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Configuration files and keys are stored in /etc/shit/"
echo ""
echo "Quick start guide:"
echo "1. Start the server: systemctl start shit-man"
echo "2. Start the client: systemctl start shit-shell"
echo "3. Use the CLI: shit"
echo ""
echo "Check logs with: journalctl -u shit-man -f"