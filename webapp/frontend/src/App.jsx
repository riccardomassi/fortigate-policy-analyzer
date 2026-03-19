import React, { useState, useEffect } from 'react'
import { uploadFile, analyzeFile, deleteFile, checkHealth } from './api'
import FileUpload from './components/FileUpload'
import Configuration from './components/Configuration'
import ResultsViewer from './components/ResultsViewer'
import LoadingSpinner from './components/LoadingSpinner'
import ErrorMessage from './components/ErrorMessage'

function App() {
  const [file, setFile] = useState(null)
  const [fileInfo, setFileInfo] = useState(null)
  const [config, setConfig] = useState({
    srcintf: '',
    dstintf: '',
    internet_intf: '',
    analyze_all: false
  })
  const [results, setResults] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [backendReady, setBackendReady] = useState(false)

  useEffect(() => {
    // Check if backend is ready
    checkHealth()
      .then(() => {
        setBackendReady(true)
      })
      .catch((err) => {
        setError('Backend connection failed. Please ensure the Flask server is running on port 5000.')
      })
  }, [])

  const handleFileUpload = (uploadedFile) => {
    setFile(uploadedFile)
    setError(null)
  }

  const handleUploadComplete = (info) => {
    setFileInfo(info)
  }

  const handleConfigChange = (newConfig) => {
    setConfig(newConfig)
  }

  const handleAnalyze = async () => {
    if (!fileInfo) {
      setError('Please upload a file first')
      return
    }

    setIsLoading(true)
    setError(null)
    setResults(null)

    try {
      const params = {
        file_id: fileInfo.file_id,
        srcintf: config.srcintf || '',
        dstintf: config.dstintf || '',
        internet_intf: config.internet_intf || '',
        analyze_all: config.analyze_all
      }

      const response = await analyzeFile(params)

      if (response.success) {
        setResults(response.results)
      } else {
        setError(response.error || 'Analysis failed')
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Analysis failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleReset = () => {
    if (fileInfo?.file_id) {
      deleteFile(fileInfo.file_id).catch(console.error)
    }
    setFile(null)
    setFileInfo(null)
    setResults(null)
    setError(null)
    setConfig({
      srcintf: '',
      dstintf: '',
      internet_intf: '',
      analyze_all: false
    })
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                🔐 FortiGate Policy Analyzer
              </h1>
              <p className="text-sm text-gray-600 mt-1">
                Analyze and optimize your Fortinet firewall policies
              </p>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                backendReady ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
              }`}>
                {backendReady ? '● Connected' : '● Disconnected'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Message */}
        {error && (
          <ErrorMessage message={error} onDismiss={() => setError(null)} />
        )}

        {/* Loading Spinner */}
        {isLoading && (
          <LoadingSpinner message="Analyzing your firewall policies..." />
        )}

        {/* Results View */}
        {results && !isLoading && (
          <ResultsViewer
            results={results}
            html={''}
            onReset={handleReset}
          />
        )}

        {/* Upload & Configure (shown when no results) */}
        {!results && !isLoading && (
          <div className="space-y-6">
            {/* File Upload */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">
                1. Upload Configuration File
              </h2>
              <p className="text-sm text-gray-600 mb-4">
                Upload your FortiGate backup configuration file (.conf)
              </p>
              <FileUpload
                onFileSelect={handleFileUpload}
                onUploadComplete={handleUploadComplete}
                disabled={isLoading}
              />
            </div>

            {/* Configuration */}
            <Configuration
              config={config}
              onConfigChange={handleConfigChange}
              fileInfo={fileInfo}
              onAnalyze={handleAnalyze}
              disabled={isLoading || !fileInfo}
            />
          </div>
        )}
      </main>
    </div>
  )
}

export default App
