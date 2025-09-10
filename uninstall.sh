#!/usr/bin/env bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Shit Uninstall Script${NC}"
echo "===================="
echo ""

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (use sudo)${NC}"
  exit 1
fi

echo "Select what to uninstall:"
echo "1) shit-shell (reverse shell client)"
echo "2) shit-man (server daemon)"
echo "3) shit (CLI tool)"
echo "4) All components"
echo ""
read -p "Enter your choice [1-4]: " choice

uninstall_shit_shell() {
  echo -e "\n${BLUE}Uninstalling shit-shell client...${NC}"

  # Stop and disable service
  if systemctl is-active --quiet shit-shell.service; then
    echo "Stopping shit-shell service..."
    systemctl stop shit-shell.service
  fi
  
  if systemctl is-enabled --quiet shit-shell.service 2>/dev/null; then
    echo "Disabling shit-shell service..."
    systemctl disable shit-shell.service
  fi

  # Remove binary
  if [ -f "/usr/local/bin/shit-shell" ]; then
    rm -f /usr/local/bin/shit-shell
    echo "Removed binary: /usr/local/bin/shit-shell"
  fi

  # Remove systemd service file
  if [ -f "/etc/systemd/system/shit-shell.service" ]; then
    rm -f /etc/systemd/system/shit-shell.service
    echo "Removed service: /etc/systemd/system/shit-shell.service"
  fi

  # Keep /etc/shit directory for .keys file
  echo -e "${YELLOW}Note: Keeping /etc/shit directory to preserve configuration files${NC}"

  systemctl daemon-reload

  echo -e "${GREEN}✓ shit-shell uninstalled successfully${NC}"
  echo ""
}

uninstall_shit_man() {
  echo -e "\n${BLUE}Uninstalling shit-man server...${NC}"

  # Stop and disable service
  if systemctl is-active --quiet shit-man.service; then
    echo "Stopping shit-man service..."
    systemctl stop shit-man.service
  fi
  
  if systemctl is-enabled --quiet shit-man.service 2>/dev/null; then
    echo "Disabling shit-man service..."
    systemctl disable shit-man.service
  fi

  # Remove binary
  if [ -f "/usr/local/bin/shit-man" ]; then
    rm -f /usr/local/bin/shit-man
    echo "Removed binary: /usr/local/bin/shit-man"
  fi

  # Remove systemd service file
  if [ -f "/etc/systemd/system/shit-man.service" ]; then
    rm -f /etc/systemd/system/shit-man.service
    echo "Removed service: /etc/systemd/system/shit-man.service"
  fi

  # Remove socket file if it exists
  if [ -S "/var/run/shit-man.sock" ]; then
    rm -f /var/run/shit-man.sock
    echo "Removed socket: /var/run/shit-man.sock"
  fi

  # Keep /etc/shit directory for .authorized_keys file
  echo -e "${YELLOW}Note: Keeping /etc/shit directory to preserve configuration files${NC}"

  systemctl daemon-reload

  echo -e "${GREEN}✓ shit-man uninstalled successfully${NC}"
  echo ""
}

uninstall_shit() {
  echo -e "\n${BLUE}Uninstalling shit CLI tool...${NC}"

  # Remove binary
  if [ -f "/usr/local/bin/shit" ]; then
    rm -f /usr/local/bin/shit
    echo "Removed binary: /usr/local/bin/shit"
  fi

  # Remove environment file
  if [ -f "/etc/profile.d/shit.sh" ]; then
    rm -f /etc/profile.d/shit.sh
    echo "Removed environment config: /etc/profile.d/shit.sh"
  fi

  echo -e "${GREEN}✓ shit uninstalled successfully${NC}"
  echo ""
}

confirm_action() {
  local component="$1"
  echo -e "${YELLOW}This will uninstall $component. Continue? [y/N]${NC}"
  read -r response
  case "$response" in
    [yY][eE][sS]|[yY]) 
      return 0
      ;;
    *)
      echo "Cancelled."
      return 1
      ;;
  esac
}

case $choice in
1)
  if confirm_action "shit-shell client"; then
    uninstall_shit_shell
  fi
  ;;
2)
  if confirm_action "shit-man server"; then
    uninstall_shit_man
  fi
  ;;
3)
  if confirm_action "shit CLI tool"; then
    uninstall_shit
  fi
  ;;
4)
  if confirm_action "all components"; then
    uninstall_shit_shell
    uninstall_shit_man
    uninstall_shit
  fi
  ;;
*)
  echo -e "${RED}Invalid choice${NC}"
  exit 1
  ;;
esac

echo ""
echo -e "${GREEN}Uninstall complete!${NC}"
echo ""
echo -e "${BLUE}Files preserved:${NC}"
echo "• /etc/shit/ (contains .keys, .authorized_keys, and logs)"
echo ""