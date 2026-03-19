import React from 'react'
import PolicyRow from './PolicyRow'
import { useState } from 'react'
import PropTypes from 'prop-types'

const CategorySection = ({ category, entries, severity }) => {
  const [isOpen, setIsOpen] = useState(true)

  const severityColors = {
    CRITICAL: 'border-critical border-l-4 bg-red-50',
    WARNING: 'border-warning border-l-4 bg-orange-50',
    INFO: 'border-info border-l-4 bg-blue-50',
    OK: 'border-success border-l-4 bg-green-50'
  }

  const getSeverityEmoji = (severity) => {
    const emojiMap = {
      'CRITICAL': '🧨',
      'WARNING': '⚠️',
      'INFO': 'ℹ️',
      'OK': '✅'
    }
    return emojiMap[severity] || '•'
  }

  const isDuplicateCategory = category === 'DUPLICATE_POLICY'

  return (
    <div className={`mb-6 rounded-lg shadow-sm ${severityColors[severity] || 'border-l-4 border-gray-300 bg-gray-50'}`}>
      <div
        className="p-4 cursor-pointer select-none"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">{getSeverityEmoji(severity)}</span>
            <h2 className="text-lg font-semibold text-gray-900">
              {category.replace('_', ' ')}
            </h2>
          </div>
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-white text-gray-600">
              {entries.length} {entries.length === 1 ? 'policy' : 'policies'}
            </span>
            <span className={`transform transition-transform ${isOpen ? 'rotate-180' : ''}`}>
              ▼
            </span>
          </div>
        </div>
      </div>

      {isOpen && (
        <div className="px-4 pb-4">
          {isDuplicateCategory && entries[0]?.msg && (
            <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded text-yellow-800 text-sm">
              ⚠️ {entries[0].msg}
            </div>
          )}

          {isDuplicateCategory ? (
            <div className="space-y-2">
              {entries.map((entry, index) => {
                if (entry._is_group) {
                  return (
                    <div key={index} className="space-y-3">
                      {entry.members?.map((policy, idx) => (
                        <PolicyRow
                          key={`${index}-${idx}`}
                          policy={policy}
                          categories={category}
                        />
                      ))}
                    </div>
                  )
                }
                return null
              })}
            </div>
          ) : (
            <div className="space-y-3">
              {entries.map((policy, index) => (
                <PolicyRow key={index} policy={policy} categories={category} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

CategorySection.propTypes = {
  category: PropTypes.string.isRequired,
  entries: PropTypes.arrayOf(PropTypes.object).isRequired,
  severity: PropTypes.string
}

export default CategorySection
