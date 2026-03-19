import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api'

export const uploadFile = async (file) => {
  const formData = new FormData()
  formData.append('file', file)

  const response = await axios.post(`${API_BASE}/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  })
  return response.data
}

export const analyzeFile = async (params) => {
  const response = await axios.post(`${API_BASE}/analyze`, params)
  return response.data
}

export const deleteFile = async (fileId) => {
  const response = await axios.delete(`${API_BASE}/files/${fileId}`)
  return response.data
}

export const checkHealth = async () => {
  const response = await axios.get(`${API_BASE}/health`)
  return response.data
}
