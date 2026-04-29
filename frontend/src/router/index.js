import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Scans from '../views/Scans.vue'
import Vulnerabilities from '../views/Vulnerabilities.vue'
import MaliciousIPs from '../views/MaliciousIPs.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/scans',
    name: 'Scans',
    component: Scans
  },
  {
    path: '/vulnerabilities',
    name: 'Vulnerabilities',
    component: Vulnerabilities
  },
  {
    path: '/malicious-ips',
    name: 'MaliciousIPs',
    component: MaliciousIPs
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
