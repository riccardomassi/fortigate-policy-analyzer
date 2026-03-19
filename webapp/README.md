# FortiGate Policy Analyzer Web App

A web application for analyzing Fortinet firewall policies from backup configuration files. Upload your `.conf` files, configure analysis parameters, and view detailed security reports with severity-based categorization.

## Features

- 📤 **Drag-and-drop file upload** for FortiGate `.conf` files
- ⚙️ **Configuration options** for interface filtering and internet interface detection
- 📊 **Interactive results** with severity-based categorization (Critical, Warning, Info)
- 🔍 **Policy details** with comprehensive information and issue descriptions
- 📥 **Export options** for HTML, JSON, and text reports
- 📱 **Responsive design** that works on desktop and mobile devices

## Architecture

- **Backend**: Flask REST API with CORS support
- **Frontend**: Modern React SPA with Vite bundler
- **Storage**: Local filesystem for uploaded config files
- **Styling**: Tailwind CSS for responsive design

## Prerequisites

- Python 3.7+ with pip
- Node.js 16+ with npm
- FortiGate backup configuration files (.conf format)

## Installation

### 1. Install Backend Dependencies

```bash
cd /Users/riccardovem/Project-Fortinet/webapp
pip install -r requirements.txt
```

### 2. Install Frontend Dependencies

```bash
cd /Users/riccardovem/Project-Fortinet/webapp/frontend
npm install
```

## Running the Application

### Step 1: Start the Backend API

Open a terminal and run:

```bash
cd /Users/riccardovem/Project-Fortinet/webapp
python backend/app.py
```

The Flask API will start on http://localhost:5000

You should see:
```
[*] Starting FortiGate Policy Analyzer Web API...
[*] FortiGate Policy Analyzer Web API started
[*] Upload folder: /Users/riccardovem/Project-Fortinet/webapp/uploads
```

### Step 2: Start the Frontend

Open another terminal and run:

```bash
cd /Users/riccardovem/Project-Fortinet/webapp/frontend
npm run dev
```

The React app will start on http://localhost:3000

You should see:
```
VITE v5.x.x
ready in x ms

  ➜  Local:   http://localhost:3000/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

### Step 3: Access the Web App

Open your browser and navigate to: http://localhost:3000

## Usage

### 1. Upload Configuration File

- Drag and drop your `.conf` file onto the upload area
- Or click to browse and select the file
- Maximum file size: 50MB
- Only `.conf` files are accepted

### 2. Configure Analysis (Optional)

- **Source Interface**: Filter policies by source interface (e.g., "VPN")
- **Destination Interface**: Filter policies by destination interface (e.g., "lan")
- **Internet Interfaces**: Override default internet interface detection (comma-separated, e.g., "wan1,pppoe0")
- **Analyze All**: Check to analyze all policies (overrides interface filters)

### 3. View Results

The results show:

**Summary Statistics**:
- Total number of policies analyzed
- Clean policies (no issues)
- Policies with critical issues
- Policies with warnings
- Policies with info messages

**Categories** (grouped by severity):
- 🔴 **CRITICAL**: Critical issues like "Service ANY", "Broad Inbound" access
- 🟡 **WARNING**: Warnings like "Missing UTM", "Wide Port Range"
- 🔵 **INFO**: Informational messages like "Logging All"

**Policy Details**:
- Policy ID and Name
- Source and Destination interfaces
- Action (ACCEPT/DENY) and Status (enabled/disabled)
- Source and Destination addresses
- Service
- Authentication/Groups
- Issue description

### 4. Export Results

Click on policy cards to view detailed information. The app displays:
- Complete policy configuration
- Issue descriptions and recommendations
- Severity indicators

## Troubleshooting

### Backend connection failed

**Error**: "Backend connection failed. Please ensure the Flask server is running on port 5000."

**Solution**: Make sure the Flask server is running in a separate terminal:
```bash
cd /Users/riccardovem/Project-Fortinet/webapp
python backend/app.py
```

### File upload fails

**Error**: "Only .conf files are allowed" or "File size exceeds 50MB limit"

**Solution**: Ensure you're uploading a valid FortiGate configuration file with `.conf` extension and size under 50MB.

### No policies found

**Error**: Analyzer returns no policies

**Solution**:
1. Verify your config file contains valid firewall policies
2. Try the "Analyze all" checkbox to bypass interface filters
3. Check that the analyzer script (`fortigate_policy_analyzer.py`) is in the parent directory

### Python module not found

**Error**: `ModuleNotFoundError: No module named 'flask'` or similar

**Solution**: Install the required Python packages:
```bash
pip install Flask Flask-CORS
```

### Node modules not found

**Error**: `Cannot find module 'react'` or similar

**Solution**: Install the required Node packages:
```bash
cd /Users/riccardovem/Project-Fortinet/webapp/frontend
npm install
```

## API Endpoints

### POST /api/upload
Upload a .conf file

**Request**: Multipart form data with `file` field

**Response**:
```json
{
  "file_id": "uuid-string",
  "filename": "backup.conf",
  "size": 10240,
  "message": "File uploaded successfully"
}
```

### POST /api/analyze
Analyze uploaded config file

**Request Body**:
```json
{
  "file_id": "uuid-string",
  "srcintf": "VPN",
  "dstintf": "lan",
  "internet_intf": "wan1,pppoe0",
  "analyze_all": false
}
```

**Response**:
```json
{
  "success": true,
  "results": { /* Analysis results */ },
  "html": "html report",
  "message": "Analysis completed successfully"
}
```

### DELETE /api/files/:id
Delete uploaded file

**Response**:
```json
{
  "message": "File deleted successfully"
}
```

### GET /api/health
Health check

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00",
  "version": "1.0.0"
}
```

## Development

### Backend Development

Backend code is in `/Users/riccardovem/Project-Fortinet/webapp/backend/`

Key files:
- `backend/app.py` - Flask API server
- References `fortigate_policy_analyzer.py` in parent directory

### Frontend Development

Frontend code is in `/Users/riccardovem/Project-Fortinet/webapp/frontend/`

Key files:
- `src/App.jsx` - Main React component
- `src/api.js` - API client for backend communication
- `src/components/` - React components (FileUpload, Configuration, ResultsViewer, etc.)

### Building for Production

```bash
# Build frontend
cd /Users/riccardovem/Project-Fortinet/webapp/frontend
npm run build

# The build output will be in the `dist` directory
```

## Limitations

- Maximum file upload size: 50MB
- Files are stored temporarily for 1 hour before automatic cleanup
- Only supports FortiGate configuration files in .conf format
- Requires manual restart if backend crashes
- No authentication (designed for local network use)

## Support

For issues with the analyzer itself, see: `fortigate_policy_analyzer.py`

For security best practices, consult Fortinet documentation.
