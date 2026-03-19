import React from 'react'
import PropTypes from 'prop-types'

const LoadingSpinner = ({ message }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
        {message && (
          <p className="mt-4 text-gray-600">
            {message}
          </p>
        )}
      </div>
    </div>
  )
}

LoadingSpinner.propTypes = {
  message: PropTypes.string
}

export default LoadingSpinner
