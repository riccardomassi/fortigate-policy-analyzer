import React from 'react'
import PropTypes from 'prop-types'

const Configuration = ({ config, onConfigChange, fileInfo, onAnalyze, disabled }) => {
  const handleChange = (field, value) => {
    onConfigChange({ ...config, [field]: value })
  }

  const handleCheckboxChange = (field, checked) => {
    onConfigChange({ ...config, [field]: checked })
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-4">
        2. Configuration (Optional)
      </h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Source Interface */}
        <div>
          <label htmlFor="srcintf" className="block text-sm font-medium text-gray-700 mb-2">
            Source Interface
          </label>
          <input
            type="text"
            id="srcintf"
            value={config.srcintf}
            onChange={(e) => handleChange('srcintf', e.target.value)}
            disabled={disabled}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
            placeholder="e.g., VPN"
          />
          <p className="mt-2 text-xs text-gray-500">
            Filter policies by source interface (optional)
          </p>
        </div>

        {/* Destination Interface */}
        <div>
          <label htmlFor="dstintf" className="block text-sm font-medium text-gray-700 mb-2">
            Destination Interface
          </label>
          <input
            type="text"
            id="dstintf"
            value={config.dstintf}
            onChange={(e) => handleChange('dstintf', e.target.value)}
            disabled={disabled}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
            placeholder="e.g., lan"
          />
          <p className="mt-2 text-xs text-gray-500">
            Filter policies by destination interface (optional)
          </p>
        </div>

        {/* Internet Interface Override */}
        <div className="md:col-span-2">
          <label htmlFor="internet_intf" className="block text-sm font-medium text-gray-700 mb-2">
            Internet Interfaces
          </label>
          <input
            type="text"
            id="internet_intf"
            value={config.internet_intf}
            onChange={(e) => handleChange('internet_intf', e.target.value)}
            disabled={disabled}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
            placeholder="e.g., wan1,pppoe0"
          />
          <p className="mt-2 text-xs text-gray-500">
            Override default internet interface detection (comma-separated)
          </p>
        </div>

        {/* Analyze All Checkbox */}
        <div className="md:col-span-2">
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={config.analyze_all}
              onChange={(e) => handleCheckboxChange('analyze_all', e.target.checked)}
              disabled={disabled}
              className="h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
            />
            <span className="ml-2 text-sm text-gray-700">
              Analyze all policies (override interface filters)
            </span>
          </label>
        </div>
      </div>

      {/* File Info */}
      {fileInfo && (
        <div className="mt-4 p-3 bg-blue-50 rounded-md text-sm text-blue-800">
          <strong>File uploaded:</strong> {fileInfo.filename}
          {' '}
          ({(fileInfo.size / 1024).toFixed(2)} KB)
        </div>
      )}

      {/* Analyze Button */}
      <div className="mt-6 flex justify-end">
        <button
          onClick={onAnalyze}
          disabled={disabled || !fileInfo}
          className={
            `px-6 py-2 font-medium rounded-md text-white focus:outline-none focus:ring-2 focus:ring-offset-2 ${
              disabled || !fileInfo
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 focus:ring-blue-500'
            }`
          }
        >
          {disabled ? 'Analyzing...' : 'Analyze Policies'}
        </button>
      </div>

      {!fileInfo && (
        <p className="mt-4 text-sm text-yellow-700">
          ⚠️ Please upload a configuration file first to enable analysis
        </p>
      )}
    </div>
  )
}

Configuration.propTypes = {
  config: PropTypes.shape({
    srcintf: PropTypes.string,
    dstintf: PropTypes.string,
    internet_intf: PropTypes.string,
    analyze_all: PropTypes.bool
  }).isRequired,
  onConfigChange: PropTypes.func.isRequired,
  fileInfo: PropTypes.object,
  onAnalyze: PropTypes.func.isRequired,
  disabled: PropTypes.bool
}

export default Configuration
