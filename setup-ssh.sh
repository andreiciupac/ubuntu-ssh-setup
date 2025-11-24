#!/bin/bash

#############################################################################
# SSH Setup Script for Ubuntu Server 24.04 LTS
# Automates OpenSSH installation, configuration, and hardening
#############################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Checklist symbols
CHECK="✓"
CROSS="✗"
ARROW="→"

# Progress tracking
declare -a COMPLETED_STEPS=()

#############################################################################
# Helper Functions
#############################################################################

print_header() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BLUE}$1${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
}

print_step() {
    echo -e "${YELLOW}${ARROW}${NC} $1"
}

print_success() {
    echo -e "${GREEN}${CHECK}${NC} $1"
    COMPLETED_STEPS+=("$1")
}

print_error() {
    echo -e "${RED}${CROSS}${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_checklist() {
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    SETUP CHECKLIST${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
    for step in "${COMPLETED_STEPS[@]}"; do
        echo -e "  ${GREEN}${CHECK}${NC} $step"
    done
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

press_enter() {
    echo -e "\n${YELLOW}Press ENTER to continue...${NC}"
    read -r
}

#############################################################################
# Step 1: Install OpenSSH and fail2ban
#############################################################################

install_packages() {
    print_header "STEP 1: Installing OpenSSH Server & fail2ban"
    
    print_step "Updating package list..."
    if apt update -qq 2>/dev/null; then
        print_success "Package list updated"
    else
        print_error "Failed to update package list"
        exit 1
    fi
    
    print_step "Installing openssh-server and fail2ban..."
    if apt install -y openssh-server fail2ban >/dev/null 2>&1; then
        print_success "Packages installed successfully"
    else
        print_error "Failed to install packages"
        exit 1
    fi
    
    print_step "Enabling and starting SSH service..."
    systemctl enable --now ssh >/dev/null 2>&1
    
    if systemctl is-active --quiet ssh; then
        print_success "SSH service is running"
    else
        print_error "SSH service failed to start"
        exit 1
    fi
    
    print_success "OpenSSH and fail2ban installed"
    press_enter
}

#############################################################################
# Step 2: Display Network Interfaces
#############################################################################

select_interface() {
    print_header "STEP 2: Network Interface Selection"
    
    print_info "Detecting network interfaces..."
    echo ""
    
    # Get interfaces with IP addresses
    local interfaces=()
    local ips=()
    local counter=1
    
    while IFS= read -r line; do
        local interface=$(echo "$line" | awk '{print $2}' | sed 's/:$//')
        local ip=$(echo "$line" | grep -oP 'inet \K[\d.]+')
        
        if [[ -n "$interface" && -n "$ip" && "$interface" != "lo" ]]; then
            interfaces+=("$interface")
            ips+=("$ip")
            echo -e "  ${CYAN}[$counter]${NC} $interface ${ARROW} ${GREEN}$ip${NC}"
            ((counter++))
        fi
    done < <(ip -o -4 addr show | grep -v "127.0.0.1")
    
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        print_error "No network interfaces with IP addresses found"
        exit 1
    fi
    
    echo ""
    echo -e "${YELLOW}Select your primary network interface [1-${#interfaces[@]}]:${NC} "
    read -r selection
    
    if [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -le "${#interfaces[@]}" ]]; then
        SELECTED_INTERFACE="${interfaces[$((selection-1))]}"
        SELECTED_IP="${ips[$((selection-1))]}"
        print_success "Selected interface: $SELECTED_INTERFACE ($SELECTED_IP)"
    else
        print_error "Invalid selection"
        exit 1
    fi
    
    press_enter
}

#############################################################################
# Step 3: Display Public IP
#############################################################################

show_public_ip() {
    print_header "STEP 3: IP Address Information"
    
    echo -e "${CYAN}Local (Private) IP:${NC} ${GREEN}$SELECTED_IP${NC}"
    
    print_step "Fetching public IP address..."
    PUBLIC_IP=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "Unable to detect")
    
    if [[ "$PUBLIC_IP" != "Unable to detect" ]]; then
        echo -e "${CYAN}Public (External) IP:${NC} ${GREEN}$PUBLIC_IP${NC}"
        print_success "IP addresses detected"
    else
        echo -e "${CYAN}Public (External) IP:${NC} ${YELLOW}$PUBLIC_IP${NC}"
        print_info "You may need to check your cloud provider's floating IP"
    fi
    
    press_enter
}

#############################################################################
# Step 4: SSH Key Setup
#############################################################################

setup_ssh_key() {
    print_header "STEP 4: SSH Key Configuration"
    
    print_info "How to generate an SSH key on your CLIENT machine:"
    echo -e "\n${CYAN}──────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${YELLOW}1.${NC} Generate a new key:"
    echo -e "     ${GREEN}ssh-keygen -t ed25519 -C \"your_email@example.com\"${NC}"
    echo -e "\n  ${YELLOW}2.${NC} Display your public key:"
    echo -e "     ${GREEN}cat ~/.ssh/id_ed25519.pub${NC}"
    echo -e "\n  ${YELLOW}3.${NC} Copy the entire output (starts with 'ssh-ed25519')"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}\n"
    
    press_enter
    
    echo -e "${YELLOW}Paste your SSH public key (then press ENTER):${NC}"
    read -r SSH_PUBLIC_KEY
    
    if [[ -z "$SSH_PUBLIC_KEY" ]]; then
        print_error "No SSH key provided"
        exit 1
    fi
    
    # Validate SSH key format
    if [[ ! "$SSH_PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
        print_error "Invalid SSH key format"
        exit 1
    fi
    
    print_success "SSH public key received"
    
    # Select user for key installation
    echo ""
    print_info "Select which user should have this SSH key:"
    echo ""
    
    local users=("root")
    local counter=1
    
    echo -e "  ${CYAN}[$counter]${NC} root"
    ((counter++))
    
    # Get all regular users (UID >= 1000, excluding nobody)
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ $uid -ge 1000 && $uid -lt 65534 && -d "$home" ]]; then
            users+=("$username")
            echo -e "  ${CYAN}[$counter]${NC} $username"
            ((counter++))
        fi
    done < /etc/passwd
    
    echo -e "  ${CYAN}[$counter]${NC} ${GREEN}Create new user${NC}"
    local new_user_option=$counter
    
    echo ""
    echo -e "${YELLOW}Select user [1-$counter]:${NC} "
    read -r user_selection
    
    if [[ ! "$user_selection" =~ ^[0-9]+$ ]] || [[ "$user_selection" -lt 1 ]] || [[ "$user_selection" -gt "$counter" ]]; then
        print_error "Invalid selection"
        exit 1
    fi
    
    # Handle new user creation
    if [[ "$user_selection" -eq "$new_user_option" ]]; then
        echo -e "${YELLOW}Enter new username:${NC} "
        read -r new_username
        
        if [[ -z "$new_username" ]]; then
            print_error "Username cannot be empty"
            exit 1
        fi
        
        print_step "Creating user: $new_username"
        if adduser --disabled-password --gecos "" "$new_username" 2>/dev/null; then
            print_success "User $new_username created"
            
            echo -e "${YELLOW}Add $new_username to sudo group? [y/N]:${NC} "
            read -r add_sudo
            if [[ "$add_sudo" =~ ^[Yy]$ ]]; then
                usermod -aG sudo "$new_username"
                print_success "User added to sudo group"
            fi
            
            TARGET_USER="$new_username"
        else
            print_error "Failed to create user"
            exit 1
        fi
    else
        TARGET_USER="${users[$((user_selection-1))]}"
    fi
    
    # Set up SSH key for selected user
    if [[ "$TARGET_USER" == "root" ]]; then
        USER_HOME="/root"
    else
        USER_HOME=$(eval echo "~$TARGET_USER")
    fi
    
    SSH_DIR="$USER_HOME/.ssh"
    AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
    
    print_step "Setting up SSH key for user: $TARGET_USER"
    
    # Create .ssh directory if it doesn't exist
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    
    # Add the key
    echo "$SSH_PUBLIC_KEY" >> "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    
    # Set ownership
    if [[ "$TARGET_USER" != "root" ]]; then
        chown -R "$TARGET_USER:$TARGET_USER" "$SSH_DIR"
    fi
    
    print_success "SSH key installed for $TARGET_USER"
    press_enter
}

#############################################################################
# Step 5: Configure UFW Firewall
#############################################################################

configure_firewall() {
    print_header "STEP 5: Configuring UFW Firewall"
    
    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_step "Installing UFW..."
        apt install -y ufw >/dev/null 2>&1
    fi
    
    print_step "Configuring firewall rules..."
    
    # Allow SSH before enabling
    ufw --force allow OpenSSH >/dev/null 2>&1
    print_success "SSH access allowed"
    
    # Enable UFW
    print_step "Enabling firewall..."
    echo "y" | ufw enable >/dev/null 2>&1
    
    if ufw status | grep -q "Status: active"; then
        print_success "UFW firewall enabled and configured"
    else
        print_error "Failed to enable UFW"
        exit 1
    fi
    
    echo ""
    print_info "Current firewall status:"
    ufw status
    
    press_enter
}

#############################################################################
# Step 6: Harden SSH Configuration
#############################################################################

harden_ssh_config() {
    print_header "STEP 6: Hardening SSH Configuration"
    
    SSHD_CONFIG="/etc/ssh/sshd_config"
    BACKUP_CONFIG="${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    
    print_step "Creating backup of sshd_config..."
    cp "$SSHD_CONFIG" "$BACKUP_CONFIG"
    print_success "Backup created: $BACKUP_CONFIG"
    
    print_step "Applying security hardening..."
    
    # Create a temporary file with our settings
    cat > /tmp/sshd_hardening.conf << 'EOF'
# SSH Hardening Configuration
Port 22
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 10
EOF
    
    # Append our hardening config to sshd_config
    echo "" >> "$SSHD_CONFIG"
    echo "# Added by setup-ssh.sh on $(date)" >> "$SSHD_CONFIG"
    cat /tmp/sshd_hardening.conf >> "$SSHD_CONFIG"
    rm /tmp/sshd_hardening.conf
    
    print_success "SSH configuration hardened"
    
    print_step "Testing SSH configuration..."
    if sshd -t 2>/dev/null; then
        print_success "SSH configuration is valid"
    else
        print_error "SSH configuration has errors"
        print_info "Restoring backup..."
        cp "$BACKUP_CONFIG" "$SSHD_CONFIG"
        exit 1
    fi
    
    print_step "Restarting SSH service..."
    systemctl restart ssh
    
    if systemctl is-active --quiet ssh; then
        print_success "SSH service restarted successfully"
    else
        print_error "SSH service failed to restart"
        exit 1
    fi
    
    echo ""
    print_info "${YELLOW}IMPORTANT:${NC} Test your SSH key login in a NEW terminal session"
    print_info "Keep this session open until you confirm key authentication works"
    
    press_enter
}

#############################################################################
# Step 7: Enable fail2ban
#############################################################################

enable_fail2ban() {
    print_header "STEP 7: Enabling fail2ban Protection"
    
    print_step "Enabling fail2ban service..."
    systemctl enable --now fail2ban >/dev/null 2>&1
    
    if systemctl is-active --quiet fail2ban; then
        print_success "fail2ban is active and protecting SSH"
    else
        print_error "Failed to start fail2ban"
        exit 1
    fi
    
    sleep 2
    
    print_step "Checking fail2ban status for SSH..."
    if fail2ban-client status sshd &>/dev/null; then
        print_success "fail2ban monitoring SSH connections"
        echo ""
        fail2ban-client status sshd
    else
        print_info "fail2ban is running but SSH jail may need configuration"
    fi
    
    press_enter
}

#############################################################################
# Main Execution
#############################################################################

main() {
    clear
    
    print_header "Ubuntu 24.04 LTS - SSH Setup & Hardening Script"
    
    echo -e "${CYAN}This script will:${NC}"
    echo -e "  ${ARROW} Install OpenSSH server and fail2ban"
    echo -e "  ${ARROW} Configure network settings"
    echo -e "  ${ARROW} Set up SSH key authentication"
    echo -e "  ${ARROW} Configure UFW firewall"
    echo -e "  ${ARROW} Harden SSH configuration"
    echo -e "  ${ARROW} Enable brute-force protection"
    echo ""
    
    check_root
    
    echo -e "${YELLOW}Ready to begin? [y/N]:${NC} "
    read -r confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    
    # Execute all steps
    install_packages
    select_interface
    show_public_ip
    setup_ssh_key
    configure_firewall
    harden_ssh_config
    enable_fail2ban
    
    # Final summary
    clear
    print_header "SSH SETUP COMPLETE!"
    
    print_checklist
    
    echo -e "${GREEN}Your SSH server is now configured and hardened!${NC}\n"
    
    echo -e "${CYAN}Connection Information:${NC}"
    echo -e "  ${ARROW} Local IP:  ${GREEN}$SELECTED_IP${NC}"
    echo -e "  ${ARROW} Public IP: ${GREEN}${PUBLIC_IP:-Check cloud provider}${NC}"
    echo -e "  ${ARROW} SSH User:  ${GREEN}$TARGET_USER${NC}"
    echo -e "  ${ARROW} SSH Port:  ${GREEN}22${NC}"
    echo ""
    
    echo -e "${CYAN}Test your connection from your client:${NC}"
    echo -e "  ${GREEN}ssh $TARGET_USER@$SELECTED_IP${NC}"
    if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" != "Unable to detect" ]]; then
        echo -e "  ${GREEN}ssh $TARGET_USER@$PUBLIC_IP${NC}"
    fi
    echo ""
    
    echo -e "${YELLOW}⚠ IMPORTANT REMINDERS:${NC}"
    echo -e "  ${ARROW} Test SSH key login before closing this session"
    echo -e "  ${ARROW} Password authentication is now DISABLED"
    echo -e "  ${ARROW} Root login via SSH is DISABLED"
    echo -e "  ${ARROW} Backup saved: ${CYAN}$BACKUP_CONFIG${NC}"
    echo ""
    
    print_success "Setup completed successfully!"
}

# Run the main function
main
