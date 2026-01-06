<p align="center">
  <img src="https://github.com/mrdineshpathro/ZoneXplorer/blob/main/zonexplorer_banner.png" alt="ZoneXplorer Banner" width="100%">
</p>

# 🌐 ZoneXplorer v4 Ultimate

**ZoneXplorer** is a military-grade reconnaissance framework designed for advanced DNS exploration and intelligence gathering. Built for security researchers and red teamers, it provides a comprehensive suite of tools to map attack surfaces, hunt for subdomain takeovers, and visualize network topologies in real-time.

---

## 🔥 Key Features

- **🚀 Advanced DNS Attacks**: Support for `AXFR` (Zone Transfer), `IXFR` (Incremental Transfer), and `NSEC` Zone Walking.
- **🕵️ DNS Cache Snooping**: Identify recently resolved domains on a target Name Server.
- **☁️ Cloud Takeover Hunt**: Automatically detect vulnerable subdomains pointing to abandoned cloud services (AWS, Azure, GCP, etc.).
- **📊 Live Terminal Dashboard**: High-fidelity UI using `rich` for real-time scan statistics and findings.
- **🗺️ Topology Visualization**: Generate `.dot` files to visualize network relationships and infrastructure.
- **🛡️ SOCKS5 Support**: Route your reconnaissance traffic through proxies for stealth.

---

## 🛠️ Installation on Kali Linux

Follow these steps to set up **ZoneXplorer** on your Kali Linux system.

### 1. Update System & Install Dependencies
First, ensure your system is up to date and install the necessary Python environment headers.

```bash
sudo apt update && sudo apt install -y python3-venv git
```

### 2. Clone the Repository
Navigate to your desired directory and clone the tool.

```bash
git clone https://github.com/your-repo/ZoneXplorer.git
cd ZoneXplorer
```

### 3. Set Up a Virtual Environment
It is highly recommended to use a Virtual Environment to avoid dependency conflicts.

```bash
# Create the virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate
```

### 4. Install Requirements
With the virtual environment active, install the required Python packages.

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🚀 Usage Guide

ZoneXplorer comes with a powerful CLI. Below are the available options and examples.

### CLI Options

| Flag | Description |
| :--- | :--- |
| `-d`, `--domain` | **(Required)** Target domain to scan. |
| `-o`, `--output` | Folder to save results (default: `results`). |
| `--proxy` | SOCKS5 Proxy string (`IP:PORT`). |
| `--passive` | Enable OSINT reconnaissance via `crt.sh`. |
| `--walk` | Enable NSEC Zone Walking for DNSSEC-secured zones. |
| `--snoop` | Enable DNS Cache Snooping on Name Servers. |
| `--cloud` | Perform Cloud Subdomain Takeover checks. |
| `--graph` | Generate a Network Topology Graph (`.dot` file). |
| `--all` | **Recommended**: Run all features at once. |

### Practical Examples

**1. Basic Passive Reconnaissance**
```bash
python3 main.py -d example.com --passive
```

**2. Full Military-Grade Scan (Run All Features)**
```bash
python3 main.py -d example.com --all
```

**3. Stealthy Scan via SOCKS5 Proxy**
```bash
python3 main.py -d target-corp.com --all --proxy 127.0.0.1:9050
```

**4. Specific NSEC Walk and Graph Generation**
```bash
python3 main.py -d site.gov --walk --graph -o gov_recon
```

---

## 📅 Maintenance & Support

- **Activation**: Remember to run `source .venv/bin/activate` whenever you start a new terminal session.
- **Deactivation**: Type `deactivate` to exit the virtual environment.

---
<p align="center">Made with ❤️ for the Security Community</p>

