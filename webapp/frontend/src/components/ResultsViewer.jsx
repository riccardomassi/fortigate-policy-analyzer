import React from 'react'
import PropTypes from 'prop-types'
import CategorySection from './CategorySection'

/**
 * ResultsViewer Component - Displays the analysis results
 * Shows statistics, categories, and policy details with proper formatting
 */
const ResultsViewer = ({ results, html, onReset }) => {
  // Statistics colors mapping
  const statColors = {
    total: 'text-gray-900',
    clean: 'text-green-600',
    CRITICAL: 'text-red-600',
    WARNING: 'text-orange-600',
    INFO: 'text-blue-600'
  }

  // Check if results are valid
  if (!results || !results.categories || !results.stats) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="text-center">
          <h2 className="text-lg font-semibold text-gray-900">No results available</h2>
          <p className="mt-2 text-sm text-gray-600">There was an issue displaying the results</p>
          <button onClick={onReset} className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
            Try Again
          </button>
        </div>
      </div>
    )
  }

  const { stats, categories } = results

  return (
    <div className="space-y-6">
      {/* Header with Summary Stats */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Analysis Results</h2>
          <div className="flex gap-2">
            <button
              onClick={onReset}
              className="px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
            >
              Analyze Another File
            </button>
          </div>
        </div>

        {/* Summary Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className={`text-2xl font-bold ${statColors.total}`}>{stats.total}</div>
            <div className="text-sm font-medium text-gray-600 mt-1">Total Policies</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className={`text-2xl font-bold ${statColors.clean}`}>{stats.clean}</div>
            <div className="text-sm font-medium text-gray-600 mt-1">Clean Policies</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className={`text-2xl font-bold ${statColors.CRITICAL}`}>{stats.CRITICAL}</div>
            <div className="text-sm font-medium text-gray-600 mt-1">Critical Issues</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className={`text-2xl font-bold ${statColors.WARNING}`}>{stats.WARNING}</div>
            <div className="text-sm font-medium text-gray-600 mt-1">Warnings</div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className={`text-2xl font-bold ${statColors.INFO}`}>{stats.INFO}</div>
            <div className="text-sm font-medium text-gray-600 mt-1">Info</div>
          </div>
        </div>
      </div>

      {/* Results Meta Info */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-semibold text-blue-900">Analysis Date:</span>
            <span className="text-blue-700 ml-2">
              {results.analysis_date ? new Date(results.analysis_date).toLocaleString() : 'N/A'}
            </span>
          </div>
          <div>
            <span className="font-semibold text-blue-900">Source File:</span>
            <span className="text-blue-700 ml-2">{results.source_file || 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* Category Sections */}
      <div className="space-y-6">
        {categories?.map((category, index) => {
          return(
            <CategorySection
              key={index}
              category={category.label}
              severity={category.severity}
              entries={category.entries}
            />
          )
        })}

        {categories?.length === 0 && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-8 text-center">
            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
              <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-green-900">No Issues Found!</h3>
            <p className="mt-2 text-sm text-green-700">
              Your firewall policies are properly configured.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

ResultsViewer.propTypes = {
  results: PropTypes.shape({
    categories: PropTypes.arrayOf(PropTypes.shape({
      label: PropTypes.string,
      severity: PropTypes.string,
      entries: PropTypes.arrayOf(PropTypes.object)
    })),
    stats: PropTypes.shape({
      total: PropTypes.number,
      clean: PropTypes.number,
      CRITICAL: PropTypes.number,
      WARNING: PropTypes.number,
      INFO: PropTypes.number
    }),
    analysis_date: PropTypes.string,
    source_file: PropTypes.string
  }),
  html: PropTypes.string,
  onReset: PropTypes.func.isRequired
}

export default ResultsViewer
