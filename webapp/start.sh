#!/bin/bash

echo "Starting FortiGate Policy Analyzer Web App..."
echo "================================================"

# Start Backend API
echo "[1/2] Starting Flask backend on http://localhost:5000..."
cd backend
python app.py &
BACKEND_PID=$!

sleep 2

# Start Frontend
echo "[2/2] Starting React frontend on http://localhost:3000..."
cd ../frontend
npm install > /dev/null 2>&1
npm run dev

# Cleanup on exit
echo ""
echo "Stopping backend server..."
kill $BACKEND_PID 2>/dev/null

echo "Done!"
