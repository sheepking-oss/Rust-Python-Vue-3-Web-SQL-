import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json'
  }
})

export const healthCheck = () => api.get('/health')

export const getDashboardStats = () => api.get('/dashboard/stats')

export const getMaliciousIPs = (params = {}) => api.get('/malicious-ips', { params })

export const getMaliciousIP = (ip) => api.get(`/malicious-ips/${ip}`)

export const getVulnerabilities = (params = {}) => api.get('/vulnerabilities', { params })

export const startScan = (data) => api.post('/scan', data)

export const getScanStatus = (scanId) => api.get(`/scan/${scanId}`)

export const getAllScans = (params = {}) => api.get('/scans', { params })

export const runReplayTest = (data) => api.post('/replay', data)

export default api
