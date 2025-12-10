# OSINT Investigative Framework (OIF)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A comprehensive **Open Source Intelligence (OSINT)** gathering and analysis platform for conducting investigations across multiple data sources. OIF provides automated data collection, pattern recognition, entity extraction, timeline reconstruction, and detailed reporting capabilities.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Command-Line Interface](#command-line-interface)
  - [Interactive Mode](#interactive-mode)
- [Investigation Types](#investigation-types)
- [Data Sources](#data-sources)
- [Analysis Modules](#analysis-modules)
- [Report Formats](#report-formats)
- [Configuration](#configuration)
- [Examples](#examples)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The OSINT Investigation Framework is designed to help security researchers, investigators, and analysts gather, correlate, and analyze open-source intelligence data. It supports multiple investigation types and can process various data formats including log files, CSV, JSON, and network captures.

---

## Features

### Core Capabilities

| Feature                               | Description                                                       |
| ------------------------------------- | ----------------------------------------------------------------- |
| **Multi-Source Data Ingestion** | Process logs, CSV, JSON, network captures, and more               |
| **Pattern Recognition**         | Automated regex-based entity extraction                           |
| **Entity Extraction**           | Identify emails, IPs, URLs, domains, hashes, crypto wallets, etc. |
| **Timeline Reconstruction**     | Chronologically organize events from multiple sources             |
| **Relationship Mapping**        | Discover connections between extracted entities                   |
| **Anomaly Detection**           | Identify unusual patterns in network and log data                 |
| **Automated Reporting**         | Generate reports in Markdown, JSON, or CSV formats                |
| **SQLite Database Storage**     | Persist investigation data for future reference                   |
| **Caching System**              | Improve performance with intelligent data caching                 |
| **LLM Integration**             | Local Ollama-powered AI analysis for enhanced insights            |

### Entity Types Supported

- 📧 **Email Addresses**
- 🌐 **IP Addresses** (IPv4)
- 🔗 **URLs & Domains**
- 📞 **Phone Numbers**
- 🔐 **Hashes** (MD5, SHA1, SHA256)
- 💰 **Cryptocurrency Wallets** (Bitcoin, Ethereum)
- 📱 **Social Media Handles**
- 🖥️ **MAC Addresses**
- 📁 **File Paths**
- ⏰ **Timestamps**

---

## Requirements

- **Python 3.8** or higher
- **Core packages** for full file format support (see requirements.txt)
- **Ollama** (optional, for LLM-enhanced analysis) - [https://ollama.ai](https://ollama.ai)
- **Tesseract** (optional, for OCR text extraction from images)

---

## Installation

### 1. Clone or Download the Repository

```bash
git clone https://github.com/yourusername/OSINT-Investigative-Framework.git
cd OSINT-Investigative-Framework
```

### 2. Create and Activate Virtual Environment

**Windows (PowerShell):**

```powershell
python -m venv oifENV
.\oifENV\Scripts\Activate.ps1
```

**Windows (Command Prompt):**

```cmd
python -m venv oifENV
oifENV\Scripts\activate.bat
```

**Linux/macOS:**

```bash
python3 -m venv oifENV
source oifENV/bin/activate
```

### 3. Install Dependencies (Optional)

The framework uses only Python standard library modules. However, if you want to install optional dependencies for enhanced functionality:

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python oif-v1.py --help
```

---

## Quick Start

### Run in Interactive Mode

Simply run the script without arguments to enter interactive mode:

```bash
python oif-v1.py
```

### Quick File Analysis

Analyze a specific file:

```bash
python oif-v1.py analyze --source ./logs/access.log --output ./results
```

### Extract Entities from a Document

```bash
python oif-v1.py extract --source ./document.txt --format json
```

---

## Usage

### Command-Line Interface

The framework provides several commands for different operations:

#### Initialize a New Investigation

```bash
python oif-v1.py init --name "Case 001" --type person --output ./case001
```

**Options:**

- `--name, -n`: Investigation name (required)
- `--type, -t`: Investigation type (default: incident)
- `--targets`: Comma-separated list of targets
- `--sources`: Comma-separated list of data source paths
- `--output, -o`: Output directory (default: ./investigation)

#### Run an Investigation

```bash
python oif-v1.py run --config ./case001/config.json
```

#### Quick Analysis

```bash
python oif-v1.py analyze --source ./data/logfile.log --output ./analysis
```

#### Extract Entities

```bash
# Text output
python oif-v1.py extract --source ./document.txt

# JSON output
python oif-v1.py extract --source ./document.txt --format json
```

#### Search Investigation Database

```bash
python oif-v1.py search --database ./case001/investigation.db --query "192.168"
```

### Interactive Mode

Launch interactive mode for a guided investigation experience:

```bash
python oif-v1.py
```

**Available Interactive Commands:**

| Command              | Description                       |
| -------------------- | --------------------------------- |
| `help`             | Display help message              |
| `new <type> <name>` | Create a new investigation of specified type |
| `load <config>`    | Load an existing investigation    |
| `add target <t>`   | Add an investigation target       |
| `add source <s>`   | Add a data source                 |
| `run`              | Execute the investigation         |
| `findings`         | Display all findings              |
| `entities`         | Display extracted entities        |
| `export <format>`  | Export report (markdown/json/csv) |
| `status`           | Show investigation status         |
| `exit` or `quit` | Exit interactive mode             |

---

## Investigation Types

The framework supports the following investigation types:

| Type               | Description                      |
| ------------------ | -------------------------------- |
| `PERSON`         | Individual person investigations |
| `ORGANIZATION`   | Company or organization research |
| `DOMAIN`         | Domain name investigations       |
| `IP_ADDRESS`     | IP address analysis              |
| `EMAIL`          | Email address investigations     |
| `PHONE`          | Phone number lookups             |
| `SOCIAL_MEDIA`   | Social media account research    |
| `CRYPTOCURRENCY` | Cryptocurrency wallet tracking   |
| `VEHICLE`        | Vehicle-related investigations   |
| `LOCATION`       | Geographic location research     |
| `INCIDENT`       | Security incident analysis       |
| `NETWORK`        | Network traffic analysis         |
| `MALWARE`        | Malware analysis investigations  |

---

## Data Sources

### Supported File Types

| Category                 | Extensions                                        | Description                                      | Required Package             |
| ------------------------ | ------------------------------------------------- | ------------------------------------------------ | ---------------------------- |
| **Documents**      |                                                   |                                                  |                              |
| PDF Files                | `.pdf`                                          | Adobe PDF documents with text & table extraction | `pdfplumber` or `PyPDF2` |
| Word Documents           | `.docx`                                         | Microsoft Word documents                         | `python-docx`              |
| Text Files               | `.txt`, `.text`, `.md`, `.rst`            | Plain text and markdown                          | Built-in                     |
| **Spreadsheets**   |                                                   |                                                  |                              |
| Excel (modern)           | `.xlsx`                                         | Microsoft Excel 2007+                            | `openpyxl`                 |
| Excel (legacy)           | `.xls`                                          | Microsoft Excel 97-2003                          | `xlrd`                     |
| CSV Files                | `.csv`                                          | Comma-separated values                           | Built-in                     |
| **Data Formats**   |                                                   |                                                  |                              |
| JSON Files               | `.json`                                         | JSON-formatted data                              | Built-in                     |
| XML Files                | `.xml`                                          | XML documents                                    | Built-in                     |
| YAML Files               | `.yaml`, `.yml`                               | YAML configuration files                         | `pyyaml`                   |
| **Email**          |                                                   |                                                  |                              |
| Email Files              | `.eml`, `.msg`                                | Email messages with headers, body & attachments  | Built-in                     |
| **Images**         |                                                   |                                                  |                              |
| Common Formats           | `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp` | Standard image formats                           | `Pillow`                   |
| High Quality             | `.tiff`, `.tif`, `.webp`                    | Professional image formats                       | `Pillow`                   |
| RAW Formats              | `.raw`, `.cr2`, `.nef`, `.arw`            | Camera RAW files                                 | `Pillow`                   |
| Other                    | `.ico`, `.heic`, `.heif`                    | Icons and Apple formats                          | `Pillow`                   |
| **Logs & Network** |                                                   |                                                  |                              |
| Log Files                | `.log`                                          | Application and system logs                      | Built-in                     |
| Network Captures         | `.pcap`, `.netflow`, `.conn`                | Network traffic data                             | Built-in                     |
| Config Files             | `.ini`, `.cfg`, `.conf`                     | Configuration files                              | Built-in                     |
| **Archives**       |                                                   |                                                  |                              |
| Compressed               | `.bz2`                                          | BZ2 compressed files                             | Built-in                     |

### Image Processing Features

When processing images, the framework extracts:

- **EXIF Metadata**: Camera info, date taken, software used
- **GPS Coordinates**: Location data with lat/long conversion
- **Image Properties**: Dimensions, color mode, format
- **OCR Text**: Text extraction from images (requires Tesseract)

### Email Processing Features

Email files are parsed to extract:

- **Headers**: From, To, Cc, Subject, Date, Message-ID, X-Originating-IP
- **Body Content**: Plain text and HTML versions
- **Attachments**: Filename, type, and size information
- **Recipient Lists**: All recipients across To, Cc, Bcc fields

### Data Source Types

- **LOG_FILE**: Application and system logs
- **CSV_FILE**: Structured tabular data
- **JSON_FILE**: API responses and structured data
- **NETWORK_CAPTURE**: Packet captures and flow data
- **WEATHER_DATA**: Location-based weather information
- **PUBLIC_RECORDS**: Public records databases

---

## Analysis Modules

### 1. Entity Extraction Module

Automatically extracts entities from all collected data using regex patterns:

- Emails, IPs, URLs, domains
- Phone numbers, hashes
- Cryptocurrency wallets
- Social media handles
- MAC addresses, file paths

### 2. Timeline Reconstruction Module

Builds a chronological timeline of events by:

- Extracting timestamps from all records
- Sorting events chronologically
- Identifying event sequences and patterns

### 3. Anomaly Detection Module

Identifies suspicious patterns:

- Unusual port activity in network connections
- High error rates in log files
- Abnormal traffic patterns

### 4. Relationship Mapping Module

Maps connections between entities:

- Co-occurrence analysis
- Source correlation
- Entity relationship graphs

### 5. LLM-Enhanced Analysis Module (Ollama Integration)

Leverages local Large Language Models for advanced analysis:

- **Enhanced Entity Extraction**: Uses LLM for contextual entity identification
- **Log Anomaly Detection**: AI-powered detection of suspicious patterns
- **Entity Correlation**: Intelligent relationship discovery between entities
- **Threat Classification**: Automated threat indicator classification
- **Investigation Summaries**: AI-generated executive summaries

**Supported Models** (in order of preference):

- `wizardlm2:latest` - **Default** - Optimized for GTX 1070, strong reasoning
- `llama3.1:latest` - Best overall performance
- `phi3:3.8b` - Fastest inference
- `mistral:7b-instruct` - Best instruction following
- `gemma3:4b` - Good alternative

**Setup Ollama:**

```bash
# Install Ollama (https://ollama.ai)
# Start Ollama server
ollama serve

# Pull a recommended model
ollama pull wizardlm2:latest
```

---

## Report Formats

### Markdown Report (Default)

Human-readable report with:

- Executive summary
- Findings by severity
- Detailed finding descriptions
- Evidence and recommendations

### JSON Report

Machine-readable format ideal for:

- Integration with other tools
- Data interchange
- Automated processing

### CSV Report

Spreadsheet-compatible format for:

- Data analysis in Excel/Google Sheets
- Bulk data review
- Custom filtering

---

## Configuration

### Configuration File Structure (JSON)

```json
{
  "name": "Investigation Name",
  "type": "INCIDENT",
  "targets": ["target1", "target2"],
  "data_sources": ["./path/to/data"],
  "output_dir": "./output",
  "api_keys": {},
  "custom_patterns": {},
  "max_depth": 3,
  "timeout": 30,
  "parallel_workers": 4,
  "enable_caching": true,
  "cache_ttl": 3600,
  "report_format": "markdown"
}
```

### Configuration Options

| Option               | Type   | Default  | Description                    |
| -------------------- | ------ | -------- | ------------------------------ |
| `name`             | string | -        | Investigation name             |
| `type`             | string | INCIDENT | Investigation type             |
| `targets`          | array  | []       | List of investigation targets  |
| `data_sources`     | array  | []       | Paths to data sources          |
| `output_dir`       | string | ./output | Output directory               |
| `api_keys`         | object | {}       | API keys for external services |
| `custom_patterns`  | object | {}       | Custom regex patterns          |
| `max_depth`        | int    | 3        | Maximum recursion depth        |
| `timeout`          | int    | 30       | Request timeout in seconds     |
| `parallel_workers` | int    | 4        | Number of parallel workers     |
| `enable_caching`   | bool   | true     | Enable data caching            |
| `cache_ttl`        | int    | 3600     | Cache time-to-live (seconds)   |
| `report_format`    | string | markdown | Report format                  |

---

## Examples

### Example 1: Analyze Log Files for Security Incidents

```bash
# Initialize investigation
python oif-v1.py init --name "Security Audit 2024" --type incident --output ./audit

# Add data sources to config.json, then run
python oif-v1.py run --config ./audit/config.json
```

### Example 2: Extract Entities from a Document

```bash
python oif-v1.py extract --source ./suspicious_email.txt --format json > entities.json
```

### Example 3: Interactive Investigation Session

```bash
python oif-v1.py

osint> new NETWORK "Network Investigation"
Created NETWORK investigation: Network Investigation

osint> add source ./network_logs/
Added source: ./network_logs/

osint> add target 192.168.1.100
Added target: 192.168.1.100

osint> run
[INFO] Starting investigation: Network Investigation
[INFO] Phase 1: Collecting data...
[INFO] Phase 2: Analyzing data...
[INFO] Phase 3: Generating reports...
[INFO] Investigation complete. Found 5 findings.

osint> findings
[HIGH] High error rate detected in logs
  Error rate: 15.2%

osint> export json
Report exported to ./INVESTIGATIONS/network_investigation/

osint> exit
Goodbye!
```

### Example 4: Creating Different Investigation Types

The framework supports various investigation types. Here are examples of how to create and conduct investigations for each type:

#### Person Investigations

```bash
python oif-v1.py

osint> new PERSON "John Doe"
Created PERSON investigation: John Doe

osint> add target "john.doe@example.com"
osint> add target "@johndoe_twitter"
osint> add source ./john_doe_emails/
osint> run
```

#### Organization Investigations

```bash
osint> new ORGANIZATION "Acme Corporation"
Created ORGANIZATION investigation: Acme Corporation

osint> add target "acme.com"
osint> add target "192.168.1.0/24"
osint> add source ./acme_logs/
osint> run
```

#### Domain Investigations

```bash
osint> new DOMAIN "suspicious-site.net"
Created DOMAIN investigation: suspicious-site.net

osint> add target "suspicious-site.net"
osint> add source ./domain_logs/
osint> run
```

#### IP Address Investigations

```bash
osint> new IP_ADDRESS "192.168.1.100"
Created IP_ADDRESS investigation: 192.168.1.100

osint> add target "192.168.1.100"
osint> add source ./network_logs/
osint> run
```

#### Email Investigations

```bash
osint> new EMAIL "admin@company.com"
Created EMAIL investigation: admin@company.com

osint> add target "admin@company.com"
osint> add source ./email_logs/
osint> run
```

#### Phone Number Investigations

```bash
osint> new PHONE "+1-555-123-4567"
Created PHONE investigation: +1-555-123-4567

osint> add target "+1-555-123-4567"
osint> add source ./phone_records/
osint> run
```

#### Social Media Investigations

```bash
osint> new SOCIAL_MEDIA "@johndoe_twitter"
Created SOCIAL_MEDIA investigation: @johndoe_twitter

osint> add target "@johndoe_twitter"
osint> add target "facebook.com/john.doe"
osint> add source ./social_media_data/
osint> run
```

#### Cryptocurrency Investigations

```bash
osint> new CRYPTOCURRENCY "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
Created CRYPTOCURRENCY investigation: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

osint> add target "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
osint> add source ./blockchain_data/
osint> run
```

#### Vehicle Investigations

```bash
osint> new VEHICLE "VIN: 1HGCM82633A123456"
Created VEHICLE investigation: VIN: 1HGCM82633A123456

osint> add target "1HGCM82633A123456"
osint> add source ./vehicle_records/
osint> run
```

#### Location Investigations

```bash
osint> new LOCATION "New York City, NY"
Created LOCATION investigation: New York City, NY

osint> add target "40.7128,-74.0060"
osint> add source ./location_data/
osint> run
```

#### Incident Investigations

```bash
osint> new INCIDENT "Data Breach 2024"
Created INCIDENT investigation: Data Breach 2024

osint> add target "breach_logs"
osint> add source ./incident_logs/
osint> run
```

#### Network Investigations

```bash
osint> new NETWORK "Corporate LAN Analysis"
Created NETWORK investigation: Corporate LAN Analysis

osint> add target "10.0.0.0/8"
osint> add source ./network_traffic/
osint> run
```

#### Malware Investigations

```bash
osint> new MALWARE "Trojan.Downloader"
Created MALWARE investigation: Trojan.Downloader

osint> add target "trojan_hash"
osint> add source ./malware_samples/
osint> run
```

### Example 5: Loading and Managing Investigations

```bash
# List available investigations
osint> load
Available investigations:
- john_doe (PERSON)
- acme_corp (ORGANIZATION)
- security_breach (INCIDENT)

# Load a specific investigation
osint> load john_doe
Loaded investigation: john_doe

# Check status
osint> status
Investigation: john_doe (PERSON)
Status: Active
Sources: 3 directories
Findings: 15
Last run: 2024-12-09 14:30:00

# View findings
osint> findings
[HIGH] Suspicious email activity detected
  From: suspicious@sender.com
  To: target@company.com

# Export report
osint> export markdown
Report exported to ./INVESTIGATIONS/john_doe/report.md
```

---

## Project Structure

```
OSINT-Investigative-Framework/
├── oif-v1.py              # Main application file
├── oifENV/                # Python virtual environment
├── requirements.txt       # Python dependencies
├── README.md              # This documentation
├── .gitignore             # Git ignore rules
└── INVESTIGATIONS/        # Investigation output directory (created automatically)
    ├── investigation_name/
    │   ├── config.json    # Investigation configuration
    │   ├── report.md      # Markdown report
    │   ├── report.json    # JSON report
    │   ├── investigation.db # SQLite database
    │   └── .cache/        # Cached data
    └── ...
```

---

## Severity Levels

Findings are categorized by severity:

| Level       | Value | Description               |
| ----------- | ----- | ------------------------- |
| 🔴 CRITICAL | 5     | Immediate action required |
| 🟠 HIGH     | 4     | Significant concern       |
| 🟡 MEDIUM   | 3     | Moderate concern          |
| 🟢 LOW      | 2     | Minor concern             |
| 🔵 INFO     | 1     | Informational             |

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for legal and ethical use only. Users are responsible for ensuring compliance with all applicable laws and regulations when conducting OSINT investigations. The authors are not responsible for any misuse of this software.

---

## Support

For questions, issues, or feature requests, please open an issue on the GitHub repository.

---

*OSINT Investigation Framework - Version 1.0.0*
