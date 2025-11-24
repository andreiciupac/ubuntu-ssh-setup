# SSH Setup, Floating IP & Firewall for Ubuntu Server 24.04 LTS

```
   _____ _____ _    _ 
  / ____/ ____| |  | |
 | (___| (___ | |__| |
  \___ \\___ \|  __  |
  ____) |___) | |  | |
 |_____/_____/|_|  |_|

 Ubuntu 24.04 LTS | OpenSSH | Floating IP | UFW
```

---

## Quick Start

### Automated Setup (Recommended)

Download and run the interactive setup script:

```bash
wget https://raw.githubusercontent.com/andreiciupac/ubuntu-ssh-setup/main/setup-ssh.sh
chmod +x setup-ssh.sh
sudo ./setup-ssh.sh
```

The script will guide you through:
- ✓ Installing OpenSSH and fail2ban
- ✓ Selecting network interface
- ✓ Configuring SSH key authentication
- ✓ Setting up UFW firewall
- ✓ Hardening SSH configuration
- ✓ Enabling brute-force protection

### Manual Setup

```bash
sudo apt update && sudo apt install -y openssh-server fail2ban
sudo systemctl enable --now ssh
sudo systemctl status ssh
```

---

## 1. Install & Enable OpenSSH

```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo systemctl status ssh
```

Expected output:
```
● ssh.service - OpenSSH server daemon
     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)
     Active: active (running)
```

---

## 2. Find Your IPs

### Local IP (Private)
```bash
ip a
```
Look for `inet` near your interface (`eth0`, `ens3`).

Example:
```
inet 192.168.1.100/24 scope global dynamic eth0
```

### Public IP (External / Floating IP)
```bash
curl -s https://ifconfig.me
curl -s https://api.ipify.org
```

---

## 3. Floating / Elastic IP Concept

```
┌──────────────────────────────────────────────────────┐
│                   CLOUD PROVIDER                     │
├──────────────────────────────────────────────────────┤
│                                                      │
│  Floating IP: 203.0.113.45  ──→  Instance A         │
│                                  (Ubuntu 24.04)     │
│                                  eth0: 10.0.0.5     │
│                                                      │
│  Instance fails → reassign Floating IP to Instance B │
│                                                      │
│  Floating IP: 203.0.113.45  ──→  Instance B         │
│                                  (Ubuntu 24.04)     │
│                                  eth0: 10.0.0.6     │
└──────────────────────────────────────────────────────┘
```



---

## 4. Cloud Security Group / UFW Firewall

### Cloud Provider (Security Group Rule)

Set inbound rule:
```
Protocol: TCP
Port: 22
Source: 0.0.0.0/0       (anywhere)
        OR
        x.y.z.w/32      (your IP only - RECOMMENDED)
```

### Server Firewall (UFW)

```bash
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status
```

Output:
```
Status: active

     To                         Action      From
     --                         ------      ----
     OpenSSH                    ALLOW       Anywhere
     OpenSSH (v6)               ALLOW       Anywhere (v6)
```

For non-standard SSH port (e.g., 2222):
```bash
sudo ufw allow 2222/tcp
sudo ufw delete allow OpenSSH
```

---

## 5. Create User and SSH Keys

### Create user:
```bash
sudo adduser gaby
sudo usermod -aG sudo gaby
```

### SSH key authentication (on your client):

Generate key:
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

Copy to server:
```bash
ssh-copy-id gaby@SERVER_IP
```

Test login:
```bash
ssh gaby@SERVER_IP
```

---

## 6. Harden /etc/ssh/sshd_config

Edit the SSH daemon config:
```bash
sudo nano /etc/ssh/sshd_config
```

Find or add these lines:
```
Port 22
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AllowUsers gaby
ClientAliveInterval 300
ClientAliveCountMax 2
```

Check syntax:
```bash
sudo sshd -t
```

Restart SSH:
```bash
sudo systemctl restart ssh
sudo systemctl status ssh
```

⚠️ **Warning:** Test SSH key login before disabling passwords. Keep current session open.

---

## 7. Additional Security: fail2ban

```bash
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban
```

Check status:
```bash
sudo fail2ban-client status sshd
```

View logs:
```bash
sudo journalctl -u ssh -f
```

---

## 8. Troubleshooting

**SSH won't start:**
```bash
sudo journalctl -u ssh -b --no-pager
sudo sshd -t
tail -50 /var/log/auth.log
```

**Firewall blocking:**
```bash
sudo ufw status
sudo ufw allow OpenSSH
```

**Key permission errors:**
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
```

**Locked out:**
Use cloud provider's serial console or rescue mode to fix config.

---

## 9. Commands Cheat Sheet

```bash
# Install and enable
sudo apt update && sudo apt install -y openssh-server fail2ban
sudo systemctl enable --now ssh

# Check IP and status
ip a
curl -s https://ifconfig.me
sudo systemctl status ssh

# Create user
sudo adduser gaby
sudo usermod -aG sudo gaby

# SSH keys
ssh-keygen -t ed25519 -C "email@example.com"
ssh-copy-id gaby@SERVER_IP

# Firewall
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status

# Logs
sudo journalctl -u ssh -f
sudo fail2ban-client status sshd
```

---

## License

MIT License
