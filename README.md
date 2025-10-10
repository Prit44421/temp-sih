# Kavach - System Hardening & Security Compliance Tool

**Kavach** is a comprehensive security hardening toolkit that automates system compliance checks and remediation based on industry security standards. Built for NTRO SIH-25237 specifications, it supports both Windows and Linux environments with an intuitive TUI, Web UI, and CLI interface.

## Features

- **Multi-Platform Support**: Windows (Annexure A) and Linux (Annexure B) hardening rules
- **Configurable Severity Levels**: Basic, Moderate, and Strict hardening profiles
- **Checkpoint & Rollback**: Automatic state snapshots before changes with encrypted storage
- **PDF Report Generation**: Comprehensive compliance reports with execution logs
- **Web Dashboard**: Modern, responsive UI for managing hardening operations
- **Interactive TUI**: Terminal-based interface with real-time status updates
- **Structured Logging**: Detailed audit trails with compliance check tracking
- **Safe Mode**: Dry-run capability for impact assessment

## Architecture

```
kavach/
├── backend/          # FastAPI backend and core logic
│   └── app/
│       ├── api/      # REST API endpoints
│       ├── core/     # Rule engine, checkpoints, logging, reports
│       └── models/   # Pydantic models for validation
├── cli/              # Command-line interface
├── tui/              # Textual-based terminal UI
├── frontend/         # Web UI (HTML/CSS/JavaScript)
└── ruleModules/      # Security rule definitions (JSON)
```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Method 1: Direct Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/prit44421/kavach.git
cd kavach

# Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

### Method 2: Development Mode

```bash
# Clone and navigate to repository
git clone https://github.com/yourusername/kavach.git
cd kavach

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/macOS

# Install dependencies manually
pip install click fastapi uvicorn[standard] pydantic distro cryptography textual reportlab
```

## Quick Start

### Method 1: Using Installed Command (After `pip install -e .`)

```bash
# Launch interactive TUI with integrated Web UI
kavach start

# Apply hardening rules via CLI
kavach apply --level strict

# Generate compliance report
kavach report --output compliance-report.pdf

# List available checkpoints
kavach checkpoints

# Rollback to a checkpoint
kavach rollback <checkpoint-id>
```

### Method 2: Direct Python Module Execution

```bash
# Launch TUI and Web UI
python -m kavach.cli.kavach_cli start

# Apply hardening rules
python -m kavach.cli.kavach_cli apply --level moderate

# Generate report
python -m kavach.cli.kavach_cli report

# View checkpoints
python -m kavach.cli.kavach_cli checkpoints
```

## Usage Guide

### 1. Interactive TUI + Web UI (Recommended)

Start the integrated interface that launches both the terminal UI and web dashboard:

```bash
kavach start
# or
python -m kavach.cli.kavach_cli start
```

- **TUI**: Runs in your terminal with buttons for quick actions
- **Web UI**: Accessible at `http://127.0.0.1:8000/ui`
- **Access Token**: Displayed in the TUI for web authentication

### 2. Command-Line Interface

#### Apply Security Rules

```bash
# Apply basic level rules (least restrictive)
kavach apply --level basic

# Apply moderate level rules (balanced security)
kavach apply --level moderate

# Apply strict level rules (maximum security)
kavach apply --level strict

# Dry-run mode (preview changes without applying)
kavach apply --level strict --dry-run

# Safe mode (check compliance only, no remediation)
kavach apply --level strict --safe-mode
```

#### Generate Reports

```bash
# Generate full compliance report with logs
kavach report --output my-report.pdf

# Generate summary report (quick overview)
kavach report --summary

# Generate report without execution logs
kavach report --no-logs
```

#### Checkpoint Management

```bash
# List all checkpoints
kavach checkpoints

# Rollback to specific checkpoint
kavach rollback <checkpoint-id>

# Example:
kavach rollback 20251008T143055Z-windows.account.password_policy
```

### 3. Web Dashboard

After running `kavach start`, access the web UI at `http://127.0.0.1:8000/ui`

**Features:**

- **Overview**: Compliance score, system info, active rulesets
- **Rules**: View and edit rule definitions
- **Hardening**: Select level and launch hardening jobs
- **Checkpoints & Rollback**: Manage system state snapshots
- **Reports**: Generate and download PDF compliance reports

### 4. REST API

Start the API server separately:

```bash
uvicorn kavach.backend.app.main:app --host 127.0.0.1 --port 8000
```

**Key Endpoints:**

- `GET /api/status` - System information
- `GET /api/rules` - List all rules
- `POST /api/apply` - Apply hardening rules
- `GET /api/checkpoints` - List checkpoints
- `POST /api/rollback/{checkpoint_id}` - Rollback system
- `POST /api/reports/generate` - Generate compliance report

API documentation available at: `http://127.0.0.1:8000/docs`

## Security Rule Configuration

Rules are defined in `kavach/ruleModules/annexure_rules.json` following this structure:

```json
{
  "windows": {
    "modules": {
      "account_policies": {
        "rules": [
          {
            "id": "windows.account.password_policy",
            "title": "Enforce password policy baselines",
            "description": "Align Windows password requirements...",
            "level": "strict",
            "platforms": ["windows"],
            "check": {
              "type": "powershell",
              "cmd": "(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength",
              "expect": "12"
            },
            "remediate": {
              "type": "powershell",
              "cmd": "Set-ADDefaultDomainPasswordPolicy..."
            },
            "validate": {
              "type": "powershell",
              "cmd": "(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength",
              "expect": "12"
            },
            "rollback": {
              "type": "restore_checkpoint"
            }
          }
        ]
      }
    }
  }
}
```

### Rule Severity Levels

- **basic**: Essential security controls (low risk)
- **moderate**: Recommended security controls (balanced)
- **strict**: Maximum security hardening (may impact usability)

## Data Storage

Kavach stores operational data in the `.kavach` directory in your home folder:

**Windows:** `C:\Users\<YourUsername>\.kavach\`
**Linux/macOS:** `~/.kavach/`

```
.kavach/
├── checkpoints/       # Encrypted checkpoint files (*.kcp)
├── logs/              # Structured JSON logs and application logs
│   ├── kavach-operations.jsonl
│   └── kavach-app.log
├── reports/           # Generated PDF compliance reports
└── session.key        # Encryption key for checkpoints
```

### View Your Logs Location

**Windows (PowerShell):**

```powershell
# Navigate to logs directory
cd $env:USERPROFILE\.kavach\logs

# List all files
Get-ChildItem

# View operations log
Get-Content kavach-operations.jsonl | Select-Object -Last 10

# Count total log entries
(Get-Content kavach-operations.jsonl).Count
```

**Linux/macOS:**

```bash
# Navigate to logs directory
cd ~/.kavach/logs

# List all files
ls -lh

# View operations log
tail -n 10 kavach-operations.jsonl

# Count total log entries
wc -l kavach-operations.jsonl
```

## Compliance Logging

All operations are automatically logged with structured data:

- **Compliance Checks**: Rule evaluation results (compliant/non-compliant)
- **Remediation**: Applied changes with before/after state
- **Rollbacks**: Checkpoint restoration attempts
- **Session Tracking**: User, timestamp, and session ID for audit trails

### Log Entry Example

```json
{
  "timestamp": "2025-10-08T18:14:52.571906Z",
  "level": "INFO",
  "rule_id": "windows.firewall.private_profile",
  "action": "compliance_check",
  "status": "compliant",
  "user": "YourUsername",
  "session_id": "c1c505a1-912c-4c55-be2d-738e3761fda6",
  "message": "Compliance check: Rule windows.firewall.private_profile is compliant"
}
```

### Search Logs

**Windows (PowerShell):**

```powershell
# Find all compliance checks
Get-Content $env:USERPROFILE\.kavach\logs\kavach-operations.jsonl | Select-String "compliance_check"

# Find non-compliant rules
Get-Content $env:USERPROFILE\.kavach\logs\kavach-operations.jsonl | Select-String "non_compliant"

# Filter logs for specific rule
Get-Content $env:USERPROFILE\.kavach\logs\kavach-operations.jsonl | Select-String "windows.firewall"
```

**Linux/macOS:**

```bash
# Find all compliance checks
grep "compliance_check" ~/.kavach/logs/kavach-operations.jsonl

# Find non-compliant rules
grep "non_compliant" ~/.kavach/logs/kavach-operations.jsonl

# Filter logs for specific rule
grep "windows.firewall" ~/.kavach/logs/kavach-operations.jsonl
```
