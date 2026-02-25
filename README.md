# Cisco IOS Report Tool

Simple Python script to diagnose Cisco IOS devices by using SSH-based command execution.
Collects data with raw text output and converts it into a Markdown report with analysis and recommended actions.

## Key Features

- ✅ **Automated Data Collection**: Executes 30+ diagnostic commands automatically
- 📊 **Detailed Analysis**: Includes descriptions and interpretations for all collected items
- 📝 **Markdown Report**: Generates a readable diagnostic report
- 🔴 **Issue Detection**: Automatically classifies issues as Critical/Warning
- 💡 **Recommended Actions**: Provides specific solutions for each issue

## Installation and Execution

1. `uv sync`
2. `source .venv/bin/activate`
3. Copy the `.env.example` file to `.env` and enter the connection information
4. Specify the cisco console command information in `command_info.json`
5. `python main.py`

## Project Structure

```bash
cisco_ios_report_tool/
├── main.py                 # Main diagnostic script
├── .env                    # Connection credentials (not in git)
├── .env.example            # Template for .env
├── .gitignore              # Git ignore rules
├── pyproject.toml          # Python dependencies
├── uv.lock                 # UV lock file
├── README.md               # This file
├── cisco_diagnostic/       # Diagnostic module
│   ├── collector.py        # Data collection logic
│   └── analyzer.py         # Data analysis and report generation
└── log/                    # Output directory
    ├── cisco_collected_*.txt       # Raw command outputs
    └── cisco_diagnostic_report_*.md # Analysis reports
```

## Output Files

After execution, the following files are generated in the `log/` directory:

### 1. Raw Data File

- `cisco_collected_YYYYMMDD_HHMMSS.txt`
- Stores the raw output of all commands
- Can be used for re-analysis or TAC submission

### 2. Diagnostic Report

- `cisco_diagnostic_report_YYYYMMDD_HHMMSS.md`
- Contains analysis results and recommended actions
- Easy to read in Markdown format

## Collected Diagnostic Data

### System Information

- `show version` - Basic System Information
- `show inventory` - Model, Serial Number

### Resource Usage

- `show processes cpu sorted` - CPU Usage
- `show processes memory sorted` - Memory Usage
- `show platform resources` - DRAM/Flash Usage

### Environmental Sensors

- `show environment all` - Temperature, Fan, Power Status
- `show logging onboard switch 1 temperature` - Temperature History
- `show logging onboard switch 1 voltage` - Voltage History

### Network Status

- `show ip route summary` - Routing Table
- `show arp summary` - ARP Table
- `show mac address-table count` - MAC Address Table
- `show interfaces status` - Port Status
- `show interfaces counters errors` - Interface Errors

### Reliability and Logs

- `show logging` - System Logs
- `show logging onboard switch 1 uptime detail` - OBFL Reboot History
- `show logging onboard switch 1 message` - OBFL Hardware Errors
- `show core` - Core Dumps
- `dir crashinfo:` - Crash Files

### Redundancy and Stack

- `show redundancy` - Redundancy Status
- `show switch` - Stack Configuration
- `show switch detail` - Stack Details

## Report Structure

The generated Markdown report is structured as follows:

### 📊 Diagnostic Summary

- Overall Status (Normal/Warning/Critical)
- Issue Count Statistics

### 🔴 Critical (Immediate Action Required)

| Category | Issue | Impact | Recommended Action |
|----------|-------|--------|--------------------|
| ... | ... | ... | ... |

### ⚠️ Warning (Needs Attention)

| Category | Issue | Impact | Recommended Action |
|----------|-------|--------|--------------------|
| ... | ... | ... | ... |

### 📋 Detailed Analysis

Each item includes the following information:

| Item | Current Value | Description | Status |
|------|---------------|-------------|--------|
| IOS Version | 16.12.04 | Cisco IOS XE operating system version | ⚠️ |
| Uptime | 1 hour | Time since last reboot | ⚠️ |
| CPU Usage | 5% | Average CPU usage over the last 5 minutes (Normal if below 30%) | ✅ |

**All items include descriptions** - Understandable even without network expertise

### 💡 Recommended Actions

- Prioritized action plan (Urgent/Important)
- Cisco TAC contact and reference materials

## Key Detected Items

### 🔴 Critical

- Abnormal Reboot (PowerOn, Watchdog, Crash)
- Hardware Error (Temperature Sensor, FEP, Fan)
- Overheating (Inlet > 46°C, Hotspot > 105°C)
- CPU/Memory Overload (>80%)
- TCAM Resource Exhaustion (>90%)
- Err-disabled Ports
- Core Dump/Crash Files Detected

### ⚠️ Warning (Needs Attention)

- Outdated IOS Version
- Recent Reboot Detected
- No Power Redundancy
- Incomplete ARP Table
- Interface Errors Detected
- Frequent Reboot History

## Supported Devices

Currently supports the following Cisco devices:

- Catalyst 9300X
