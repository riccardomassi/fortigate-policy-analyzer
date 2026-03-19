import React from 'react'
import PropTypes from 'prop-types'

const PolicyRow = ({ policy, categories }) => {
  const getActionColor = (action) => {
    return action === 'accept' ? 'bg-success' : 'bg-critical'
  }

  const getActionText = (action) => {
    return action === 'accept' ? 'text-green-700' : 'text-red-700'
  }

  const isDuplicateCategory = categories === 'DUPLICATE_POLICY'

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          {/* Header row with policy ID and name */}
          <div className="flex items-center gap-3">
            <span className="font-semibold text-gray-900">
              ID {policy.policy_id}
            </span>
            {policy.policy_name && (
              <span className="text-sm text-gray-600 italic shrink-0">
                {policy.policy_name}
              </span>
            )}

            {/* Action badge */}
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
              policy.action === 'accept' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800 shrink-0'
            }`}>
              {policy.action?.toUpperCase() || 'UNKNOWN'}
            </span>

            {/* Disabled badge if applicable */}
            {policy.status === 'disable' && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 shrink-0">
                DISABLED
              </span>
            )}
          </div>

          {/* Interface flow */}
          <div className="mt-2 flex items-center text-sm text-gray-700">
            <span className="font-medium bg-blue-50 px-2 py-0.5 rounded">
              {policy.srcintf}
            </span>
            <span className="mx-2 text-gray-400">→</span>
            <span className="font-medium bg-purple-50 px-2 py-0.5 rounded">
              {policy.dstintf}
            </span>
          </div>

          {/* Source and Destination */}
          <div className="mt-2 flex items-center gap-4 text-sm">
            <div className="flex-1 min-w-0">
              <span className="text-gray-500">Src:</span>
              <span className="ml-1 font-mono text-xs text-gray-700 truncate">
                {policy.srcaddr || '—'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <span className="text-gray-500">Dst:</span>
              <span className="ml-1 font-mono text-xs text-gray-700 truncate">
                {policy.dstaddr || '—'}
              </span>
            </div>
            {policy.auth && (
              <div className="flex-1 min-w-0 shrink-0">
                <span className="text-gray-500">Auth:</span>
                <span className="ml-1 font-mono text-xs text-gray-500 truncate">
                  {policy.auth}
                </span>
              </div>
            )}
          </div>

          {/* Service */}
          <div className="mt-2">
            <span className="text-gray-500 text-sm">Service:</span>
            <span className="ml-1 font-mono text-xs text-blue-600">
              {policy.service || '—'}
            </span>
          </div>

          {/* Message (for non-duplicate categories) */}
          {!isDuplicateCategory && policy.msg && (
            <div className="mt-3 text-sm text-gray-600 p-2 bg-gray-50 rounded">
              <span className="text-gray-400">↳</span> {policy.msg}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

PolicyRow.propTypes = {
  policy: PropTypes.shape({
    policy_id: PropTypes.oneOfType([
      PropTypes.string,
      PropTypes.number
    ]).isRequired,
    policy_name: PropTypes.string,
    srcintf: PropTypes.string.isRequired,
    dstintf: PropTypes.string.isRequired,
    action: PropTypes.string,
    status: PropTypes.string,
    srcaddr: PropTypes.string,
    dstaddr: PropTypes.string,
    service: PropTypes.string,
    auth: PropTypes.string,
    msg: PropTypes.string
  }).isRequired,
  categories: PropTypes.string
}

export default PolicyRow
