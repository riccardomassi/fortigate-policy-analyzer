# FortiGate Policy Analyzer

🔐 **A comprehensive tool for analyzing FortiGate firewall policies to identify security issues and misconfigurations**

## Overview

FortiGate Policy Analyzer is a powerful security assessment tool designed for network administrators and security professionals. It analyzes FortiGate firewall configuration files and identifies potential security risks, misconfigurations, and optimization opportunities in firewall policies.

The project provides two interfaces:
1. **CLI Tool** (`fortigate_policy_analyzer.py`) - A command-line analyzer for automated scripting and integration
2. **Web Application** (`webapp/`) - A full-featured web interface with drag-and-drop uploads and interactive reporting

### Key Features

- 🔍 **Comprehensive Policy Analysis** - Detects 20+ categories of security issues
- 📊 **Severity-based Reporting** - Critical, Warning, and Info classifications
- 🔧 **Flexible Input** - Supports both extracted JSON policies and raw .conf files
- 🌐 **Internet Service Support** - Handles modern FortiGate Internet Service destinations
- 👥 **User Authentication Analysis** - Detects group-based authentication issues
- 🖥️ **Multiple Output Formats** - Text, HTML, and JSON reports
- 📱 **Web Interface** - Modern React-based UI with real-time analysis
- 🔄 **Shadowing Detection** - Identifies duplicate, overlapping, and unreachable policies
- 🔍 **Duplicate Detection** - Finds identical policies that can be consolidated

## The 20 Security Checks

Our analyzer detects these policy issues:

### 🔴 CRITICAL Issues
- **BROAD_INBOUND** - Overly permissive inbound access from internet
- **SERVICE_ANY** - Policies allowing any protocol/port (violates least privilege)
- **MISSING_UTM** - Internet-bound policies lacking essential security profiles

### 🟡 WARNING Issues
- **LOGGING_DISABLED** - Logging disabled, preventing forensics/audit
- **NO_SSL_INSPECTION** - HTTPS traffic not inspected on internet-bound policies
- **WIDE_PORT_RANGE** - Port ranges exceeding 1000 ports
- **SRC_ANY / DST_ANY** - Source or destination set to "any/all"
- **POLICY_DISABLED** - Disabled policies that should be removed
- **NEVER_MATCHES** - Shadowed policies that will never trigger
- **USELESS_DENY** - Redundant deny rules with no underlying accept
- **DUPLICATE_POLICY** - Identical policies wasting resources
- **NO_NAME** - Policies without descriptive names

### 🔵 INFO Issues
- **LOGGING_ALL** - Verbose logging may generate excessive logs
- **AUTH_WITH_SRC_ANY** - User authentication with any source (unusual pattern)
- **MIXED_AUTH_TYPES** - Combining active/passive authentication methods
- **ISVC_WITH_DSTADDR** - Internet Service with redundant dstaddr field
- **ISVC_WITH_SERVICE** - Internet Service with redundant service field
- **NAT_ON_VPN** - NAT enabled on VPN interfaces (may hide client IPs)

## Project Structure

```
Project-Fortinet/
├── fortigate_policy_analyzer.py          # CLI Analyzer (Python)
├── README.md                             # This file
└── webapp/                               # Web Application
    ├── backend/                          # Flask REST API
    │   ├── app.py                        # Main Flask server
    │   └── uploads/                      # Temporary file storage
    ├── frontend/                         # React SPA
    │   ├── src/
    │   │   ├── App.jsx                   # Main React component
    │   │   ├── api.js                    # API client
    │   │   └── components/               # UI components
    │   ├── package.json                  # Node.js dependencies
    │   └── vite.config.js                # Build configuration
    ├── uploads/                          # API uploads directory
    ├── README.md                         # Webapp documentation
    ├── requirements.txt                  # Python dependencies
    └── start.sh                          # Development startup script
```

## Command-Line Usage

### Basic Usage

```bash
# Analyze extracted policies JSON
python fortigate_policy_analyzer.py -i policies.json

# Analyze directly from FortiGate backup file
python fortigate_policy_analyzer.py --conf backup.conf --srcintf VPN --dstintf lan

# Generate HTML report
python fortigate_policy_analyzer.py -i policies.json --format html -o report.html

# Override internet interface detection
python fortigate_policy_analyzer.py -i policies.json --internet-intf wan1,pppoe0,custom-wan
```

### CLI Options

```
Options:
  -i, --input FILE          JSON file from extractor
  --conf FILE               .conf FortiGate backup file (extracts + analyzes)
  --srcintf INTERFACE       Filter by source interface (with --conf)
  --dstintf INTERFACE       Filter by destination interface (with --conf)
  --all                     Analyze all policies (overrides interface filters)
  --internet-intf LIST      Override internet interface detection (comma-separated)
  --format TYPE             Output format: text, json, or html (default: text)
  -o, --output FILE         Output file (default: stdout)
```

### Examples

```bash
# Analyze all policies from backup
python fortigate_policy_analyzer.py --conf fortigate.conf --all --format html -o full-report.html

# Analyze only VPN-to-LAN policies with custom internet interfaces
python fortigate_policy_analyzer.py --conf fortigate.conf \
  --srcintf VPN \
  --dstintf lan \
  --internet-intf wan1,pppoe0,external \
  --format json \
  -o vpn-lan-analysis.json
```

## Web Application Usage

### Prerequisites

- **Python 3.7+** with pip
- **Node.js 16+** with npm
- FortiGate backup configuration files (.conf format)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/fortigate-policy-analyzer.git
cd fortigate-policy-analyzer/webapp

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
cd frontend
npm install
cd ..
```

### Running the Application

**Step 1: Start the Backend API**

```bash
cd webapp
python backend/app.py
```

The Flask API starts on http://localhost:5000

**Step 2: Start the Frontend**

```bash
cd webapp/frontend
npm run dev
```

The React app starts on http://localhost:3000

**Step 3: Access the Web App**

Open http://localhost:3000 in your browser

### Web Interface Features

1. **Drag-and-Drop Upload** - Simply drop your .conf file onto the upload area
2. **Configuration Options** - Set filters and internet interface overrides
3. **Interactive Results** - Click on policy cards for detailed information
4. **Export Reports** - Download HTML, JSON, or text reports
5. **Responsive Design** - Works on both desktop and mobile devices

## Security Analysis Details

### Policy Shadowing Detection

The analyzer performs sophisticated cross-policy analysis to detect:
- **NEVER_MATCHES** - ACCEPT policies completely shadowed by broader ACCEPT rules
- **USELESS_DENY** - DENY rules without justification from underlying ACCEPT policies
- **DUPLICATE_POLICY** - Policies with identical configurations (wasting resources)

### Internet Service (ISDB) Support

Modern FortiGate uses Internet Service database objects instead of destination addresses. Our analyzer correctly handles:
- ISDB destinations vs traditional dstaddr
- Service fields that are ignored when ISDB is used
- Detection of redundant dstaddr fields when ISDB is active

### User Authentication Analysis

Detects unusual authentication patterns:
- Policies with user groups but source "any" (only authenticated users match)
- Mixed active and passive authentication methods
- Recommendations for authentication architecture improvements

## Technical Architecture

### Core Engine (`fortigate_policy_analyzer.py`)

The analyzer implements 20+ independent checks organized in three layers:

1. **Single Policy Checks** - Validate individual policy configurations
2. **Cross-Policy Analysis** - Detect interactions between policies (shadowing, duplicates)
3. **Severity Classification** - Aggregate and categorize findings

Key algorithms:
- **Subnet Coverage** - Determines if one address set covers another
- **Service Port Analysis** - Validates port ranges and "any" services
- **Interface Classification** - Detects internet-facing interfaces with configurable patterns
- **Canonical Key Generation** - Creates comparable representations for duplicate detection

### Web Application Architecture

**Backend (Flask API)**
- RESTful endpoints for file upload, analysis, and cleanup
- CORS support for frontend communication
- Temporary file management with automatic cleanup
- Integration with CLI analyzer via subprocess

**Frontend (React SPA)**
- Modern React functional components with hooks
- Tailwind CSS for responsive styling
- Real-time upload progress and analysis status
- Interactive policy detail cards with issue descriptions

**API Endpoints**

```bash
POST   /api/upload          # Upload .conf file
POST   /api/analyze         # Run analysis
DELETE /api/files/:id       # Delete uploaded file
GET    /api/health          # Health check
```

## Development

### CLI Development

```bash
# Run tests
python fortigate_policy_analyzer.py --conf test.conf --format json

# Debug analysis
python fortigate_policy_analyzer.py --conf debug.conf --format text
```

### Web Application Development

```bash
# Frontend development with hot reload
cd webapp/frontend
npm run dev

# Frontend production build
npm run build

# Backend development (Flask debug mode)
cd webapp
FLASK_ENV=development python backend/app.py
```

## Troubleshooting

### CLI Issues

**"File not found"**
- Ensure the input file exists and is readable
- Verify file path is correct

**"Invalid JSON"**
- When using `-i`, ensure it's valid JSON from the extractor
- When using `--conf`, ensure it's valid FortiGate config format

### Web Application Issues

**Backend connection failed**
- Ensure Flask server is running on port 5000
- Check firewall isn't blocking localhost:5000

**File upload fails**
- Verify file is .conf format and under 50MB
- Check uploads/ directory has write permissions

**No policies found**
- Verify config contains valid firewall policies
- Try "Analyze All" checkbox to bypass filters
- Check browser console for JavaScript errors

### Python Module Errors

```bash
# Install missing Python packages
pip install -r webapp/requirements.txt

# Install missing Node packages
cd webapp/frontend
npm install
```

## Limitations

- Maximum file size: 50MB (web interface)
- Temporary files are stored for 1 hour before automatic cleanup
- Only FortiGate .conf files are supported
- Requires manual restart if backend crashes
- No authentication (designed for local network use)

## Contributing

Contributions are welcome! Areas for improvement:
- Additional security checks and policies
- Performance optimizations for large configurations
- Enhanced reporting features
- Integration with FortiManager API
- Multi-language support

## License

This project is provided as-is for security assessment purposes. Always test in non-production environments first.

## Support

For issues with:
- **Analyzer logic** - Review code in `fortigate_policy_analyzer.py`
- **Web application** - Check `webapp/backend/app.py` and `webapp/frontend/src/`
- **Security practices** - Consult Fortinet documentation and security frameworks

## Credits

Built for security professionals who need deep insights into FortiGate firewall configurations and policy effectiveness.
