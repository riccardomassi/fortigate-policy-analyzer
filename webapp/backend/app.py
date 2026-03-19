#!/usr/bin/env python3
"""
FortiGate Policy Analyzer Web API

Flask backend for the Fortinet Policy Analyzer web application.
Provides REST API for file upload, analysis, and results retrieval.
"""

import os
import json
import uuid
import shutil
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import subprocess
import sys
from datetime import datetime

# Configuration
# Use environment variable or default to relative path
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', str(BASE_DIR / 'uploads'))
ALLOWED_EXTENSIONS = {'conf'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Enable CORS for all routes
CORS(app)

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_file_id():
    """Generate unique file ID"""
    return str(uuid.uuid4())


def cleanup_old_files():
    """Clean up files older than 1 hour"""
    upload_path = Path(UPLOAD_FOLDER)
    for file_path in upload_path.iterdir():
        if file_path.is_file():
            try:
                stat = file_path.stat()
                age_hours = (datetime.now().timestamp() - stat.st_mtime) / 3600
                if age_hours > 1:
                    file_path.unlink()
            except Exception:
                pass  # Ignore errors during cleanup


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload Fortinet config file"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        # Check filename
        if file.filename == '':
            return jsonify({'error': 'No filename'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'File must be a .conf file'}), 400

        # Generate unique ID and secure filename
        file_id = generate_file_id()
        filename = secure_filename(file.filename)

        # Save file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}.conf")
        file.save(filepath)

        # Get file size
        file_size = os.path.getsize(filepath)

        return jsonify({
            'file_id': file_id,
            'filename': filename,
            'size': file_size,
            'message': 'File uploaded successfully'
        }), 200

    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    """Analyze uploaded config file"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        file_id = data.get('file_id')
        if not file_id:
            return jsonify({'error': 'file_id is required'}), 400

        # Verify file exists
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}.conf")
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404

        # Get analysis parameters
        srcintf = data.get('srcintf', '')
        dstintf = data.get('dstintf', '')
        internet_intf = data.get('internet_intf', '')
        analyze_all = data.get('analyze_all', False)

        # Build analyzer command
        analyzer_script = os.environ.get('ANALYZER_PATH', str(BASE_DIR.parent / 'fortigate_policy_analyzer.py'))
        cmd = [sys.executable, analyzer_script, '--conf', filepath, '--format', 'json']

        # Add parameters if provided
        if analyze_all:
            cmd.append('--all')
        elif srcintf or dstintf:
            if srcintf:
                cmd.extend(['--srcintf', srcintf])
            if dstintf:
                cmd.extend(['--dstintf', dstintf])

        # Add internet interface override if provided
        if internet_intf:
            cmd.extend(['--internet-intf', internet_intf])

        # Execute analyzer
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            return jsonify({
                'error': 'Analysis failed',
                'details': result.stderr
            }), 500

        # Parse results
        try:
            analysis_results = json.loads(result.stdout)

            # Also generate HTML for export
            cmd_html = cmd.copy()
            cmd_html[cmd_html.index('--format') + 1] = 'html'
            result_html = subprocess.run(cmd_html, capture_output=True, text=True, timeout=300)

            html_content = result_html.stdout if result_html.returncode == 0 else ''

            return jsonify({
                'success': True,
                'results': analysis_results,
                'html': html_content,
                'message': 'Analysis completed successfully'
            }), 200

        except json.JSONDecodeError as e:
            return jsonify({
                'error': 'Invalid JSON output from analyzer',
                'details': str(e)
            }), 500

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Analysis timed out (5 minutes)'}), 504
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete uploaded file"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}.conf")
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'message': 'File deleted successfully'}), 200
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    }), 200


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': f'File too large (max {MAX_FILE_SIZE // (1024*1024)}MB)'}), 413


if __name__ == '__main__':
    print("[*] Starting FortiGate Policy Analyzer Web API...")
    # Initialize application - cleanup old files
    cleanup_old_files()
    print("[*] FortiGate Policy Analyzer Web API started")
    print(f"[*] Upload folder: {UPLOAD_FOLDER}")
    print("[*] Backend running on http://localhost:8515")
    app.run(debug=True, host='0.0.0.0', port=8515)
