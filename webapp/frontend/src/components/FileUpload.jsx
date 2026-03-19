import React, { useState, useRef, useCallback, useEffect } from 'react'
import PropTypes from 'prop-types'
import { uploadFile } from '../api'

/**
 * FileUpload Component
 *
 * Handles drag-and-drop file upload for FortiGate .conf configuration files.
 * Features include:
 * - Drag and drop zone with visual feedback
 * - Click to browse files
 * - File type validation (.conf files only)
 * - File size validation (50MB max)
 * - Upload progress indicator
 * - File preview with details
 */
const FileUpload = ({ onFileSelect, onUploadComplete, disabled }) => {
  const [isDragging, setIsDragging] = useState(false)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [selectedFile, setSelectedFile] = useState(null)
  const [error, setError] = useState(null)
  const fileInputRef = useRef(null)

  // Constants for validation
  const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB in bytes
  const ALLOWED_EXTENSION = '.conf'

  /**
   * Validates the uploaded file
   * @param {File} file - The file to validate
   * @returns {Object} - { valid: boolean, error: string | null }
   */
  const validateFile = useCallback((file) => {
    if (!file) {
      return { valid: false, error: 'No file selected' }
    }

    // Check file extension
    const fileName = file.name.toLowerCase()
    if (!fileName.endsWith(ALLOWED_EXTENSION)) {
      return {
        valid: false,
        error: `Only ${ALLOWED_EXTENSION} files are allowed`
      }
    }

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      return {
        valid: false,
        error: `File size exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit`
      }
    }

    // Check if file is empty
    if (file.size === 0) {
      return {
        valid: false,
        error: 'File is empty'
      }
    }

    return { valid: true, error: null }
  }, [])

  /**
   * Uploads the file to the backend
   * @param {File} file - The file to upload
   */
  const handleFileUpload = async (file) => {
    setError(null)
    setIsUploading(true)
    setUploadProgress(0)

    try {
      // Simulate progress updates (since XMLHttpRequest isn't easily used with axios for progress)
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval)
            return 90
          }
          return prev + 10
        })
      }, 200)

      const result = await uploadFile(file)

      clearInterval(progressInterval)
      setUploadProgress(100)

      // Notify parent component of upload completion
      if (onUploadComplete) {
        onUploadComplete(result)
      }

      // Keep the selected file state for display
      setSelectedFile(file)
    } catch (err) {
      const errorMsg = err.response?.data?.error || err.message || 'Upload failed'
      setError(errorMsg)
      setSelectedFile(null)
      if (onFileSelect) {
        onFileSelect(null)
      }
    } finally {
      setIsUploading(false)
      setTimeout(() => setUploadProgress(0), 1000)
    }
  }

  /**
   * Handles file selection from various sources (drop, file input, etc.)
   * @param {File} file - The selected file
   */
  const handleFileSelection = (file) => {
    // Reset previous state
    setError(null)

    // Validate file
    const validation = validateFile(file)
    if (!validation.valid) {
      setError(validation.error)
      return
    }

    // Set file state
    setSelectedFile(file)

    // Notify parent component
    if (onFileSelect) {
      onFileSelect(file)
    }

    // Auto-upload the file
    handleFileUpload(file)
  }

  // Drag and drop event handlers
  const handleDragEnter = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    if (disabled) return

    const files = e.dataTransfer.files
    if (files && files.length > 0) {
      handleFileSelection(files[0])
    }
  }

  // File input change handler
  const handleFileInputChange = (e) => {
    const files = e.target.files
    if (files && files.length > 0) {
      handleFileSelection(files[0])
    }
    // Reset input value to allow selecting the same file again
    e.target.value = ''
  }

  // Click handler for the drop zone
  const handleClick = () => {
    if (!disabled && !isUploading) {
      fileInputRef.current?.click()
    }
  }

  // Remove selected file
  const handleRemoveFile = (e) => {
    e.stopPropagation()

    // Optionally delete the file from backend if we have a file_id
    // This would need to be handled by parent component
    setSelectedFile(null)
    setError(null)
    if (onFileSelect) {
      onFileSelect(null)
    }
  }

  // Format file size for display
  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
  }

  return (
    <div className="w-full">
      {/* Hidden file input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileInputChange}
        accept=".conf"
        className="hidden"
        disabled={disabled || isUploading}
      />

      {/* Error message */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-start">
            <svg
              className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                clipRule="evenodd"
              />
            </svg>
            <p className="ml-3 text-sm text-red-700">{error}</p>
          </div>
        </div>
      )}

      {/* Drop zone */}
      <div
        onClick={handleClick}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-lg p-8 text-center transition-all duration-200
          ${isDragging
            ? 'border-blue-500 bg-blue-50'
            : 'border-gray-300 hover:border-gray-400'
          }
          ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
          ${isUploading ? 'cursor-wait' : ''}
        `}
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label={isUploading ? 'File uploading' : 'Upload configuration file'}
        onKeyPress={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleClick()
          }
        }}
      >
        {/* Upload progress overlay */}
        {isUploading && (
          <div className="absolute inset-0 bg-white/90 rounded-lg flex flex-col items-center justify-center z-10">
            <div className="w-64">
              <div className="flex justify-between text-sm text-gray-600 mb-2">
                <span>Uploading...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          </div>
        )}

        {/* Dragging overlay */}
        {isDragging && !isUploading && (
          <div className="absolute inset-0 bg-blue-50 rounded-lg flex items-center justify-center">
            <p className="text-lg font-semibold text-blue-600">Drop your file here</p>
          </div>
        )}

        {/* Upload prompt (when no file selected) */}
        {!selectedFile && !isUploading && (
          <div className="space-y-4">
            {/* Upload icon */}
            <div className="mx-auto">
              <svg
                className="w-16 h-16 text-gray-400 mx-auto"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                />
              </svg>
            </div>

            {/* Main text */}
            <div>
              <p className="text-base font-medium text-gray-700">
                Drop your .conf file here
              </p>
              <p className="text-sm text-gray-500 mt-1">
                or click to browse
              </p>
            </div>

            {/* File requirements */}
            <div className="flex flex-wrap justify-center gap-3 text-xs text-gray-500">
              <span className="inline-flex items-center">
                <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fillRule="evenodd"
                    d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                    clipRule="evenodd"
                  />
                </svg>
                .conf files only
              </span>
              <span className="inline-flex items-center">
                <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fillRule="evenodd"
                    d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                    clipRule="evenodd"
                  />
                </svg>
                Max {MAX_FILE_SIZE / 1024 / 1024}MB
              </span>
            </div>
          </div>
        )}

        {/* File selected display */}
        {selectedFile && !isUploading && (
          <div className="space-y-3">
            {/* Success icon */}
            <div className="mx-auto">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto">
                <svg
                  className="w-8 h-8 text-green-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
            </div>

            {/* File info */}
            <div>
              <p className="text-base font-medium text-gray-900">
                {selectedFile.name}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                {formatFileSize(selectedFile.size)}
              </p>
            </div>

            {/* Action buttons */}
            <div className="flex justify-center gap-2">
              <button
                type="button"
                onClick={handleClick}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              >
                Change File
              </button>
              <button
                type="button"
                onClick={handleRemoveFile}
                className="px-4 py-2 text-sm font-medium text-red-700 bg-red-50 hover:bg-red-100 rounded-md transition-colors"
              >
                Remove
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

FileUpload.propTypes = {
  /**
   * Callback function when a file is selected
   * @param {File | null} file - The selected file or null if none
   */
  onFileSelect: PropTypes.func,

  /**
   * Callback function when file upload completes
   * @param {Object} result - The upload result from the API
   */
  onUploadComplete: PropTypes.func,

  /**
   * Whether the upload is disabled
   */
  disabled: PropTypes.bool
}

FileUpload.defaultProps = {
  onFileSelect: () => {},
  onUploadComplete: () => {},
  disabled: false
}

export default FileUpload
