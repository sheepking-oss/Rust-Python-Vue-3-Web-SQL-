<template>
  <div class="dashboard">
    <el-row :gutter="20" class="stats-row">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <el-icon :size="40" class="stat-icon warning"><Warning/></el-icon>
          <div class="stat-value">{{ stats.vulnerability_stats?.total_findings || 0 }}</div>
          <div class="stat-label">发现漏洞</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <el-icon :size="40" class="stat-icon danger"><CircleCloseFilled/></el-icon>
          <div class="stat-value highlight-danger">{{ stats.vulnerability_stats?.confirmed_vulnerabilities || 0 }}</div>
          <div class="stat-label">确认漏洞</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <el-icon :size="40" class="stat-icon primary"><User/></el-icon>
          <div class="stat-value">{{ stats.malicious_ips_count || 0 }}</div>
          <div class="stat-label">恶意IP</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <el-icon :size="40" class="stat-icon success"><Search/></el-icon>
          <div class="stat-value highlight-success">{{ stats.vulnerability_stats?.total_scans || 0 }}</div>
          <div class="stat-label">扫描次数</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="charts-row">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span class="card-title">漏洞类型分布</span>
          </template>
          <div ref="pieChartRef" class="chart-container"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span class="card-title">扫描趋势</span>
          </template>
          <div ref="lineChartRef" class="chart-container"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="recent-row">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span class="card-title">最近发现</span>
          </template>
          <el-table :data="recentFindings" stripe style="width: 100%">
            <el-table-column prop="method" label="方法" width="80">
              <template #default="scope">
                <el-tag :type="getMethodTagType(scope.row.method)" size="small">
                  {{ scope.row.method }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="url" label="URL" show-overflow-tooltip>
              <template #default="scope">
                <span class="url-text">{{ scope.row.url || 'N/A' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="severity" label="严重性" width="100">
              <template #default="scope">
                <el-tag :type="getSeverityTagType(scope.row.severity)" size="small">
                  {{ scope.row.severity }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span class="card-title">恶意IP活跃度</span>
              <el-button type="primary" size="small" @click="refreshData">
                <el-icon><Refresh/></el-icon>
                刷新
              </el-button>
            </div>
          </template>
          <div ref="barChartRef" class="chart-container"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog
      v-model="scanDialogVisible"
      title="新建扫描任务"
      width="600px"
    >
      <el-form :model="scanForm" label-width="120px">
        <el-form-item label="会话JSON文件">
          <el-input
            v-model="scanForm.sessions_json"
            placeholder="请输入Rust引擎输出的JSON文件路径"
          />
        </el-form-item>
        <el-form-item label="基础URL">
          <el-input
            v-model="scanForm.base_url"
            placeholder="可选，用于漏洞重放测试"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="scanDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="startNewScan">开始扫描</el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'
import { Warning, CircleCloseFilled, User, Search, Refresh } from '@element-plus/icons-vue'
import { getDashboardStats, startScan } from '../api'

const pieChartRef = ref(null)
const lineChartRef = ref(null)
const barChartRef = ref(null)

let pieChart = null
let lineChart = null
let barChart = null

const stats = ref({
  vulnerability_stats: {
    total_findings: 0,
    confirmed_vulnerabilities: 0,
    total_scans: 0,
    by_type: {}
  },
  malicious_ips_count: 0,
  recent_findings: []
})

const recentFindings = ref([])
const scanDialogVisible = ref(false)
const scanForm = reactive({
  sessions_json: '',
  base_url: ''
})

const getMethodTagType = (method) => {
  const types = {
    'GET': 'success',
    'POST': 'primary',
    'PUT': 'warning',
    'DELETE': 'danger'
  }
  return types[method] || 'info'
}

const getSeverityTagType = (severity) => {
  const types = {
    'HIGH': 'danger',
    'MEDIUM': 'warning',
    'LOW': 'info'
  }
  return types[severity] || 'info'
}

const initCharts = () => {
  if (pieChartRef.value) {
    pieChart = echarts.init(pieChartRef.value)
  }
  if (lineChartRef.value) {
    lineChart = echarts.init(lineChartRef.value)
  }
  if (barChartRef.value) {
    barChart = echarts.init(barChartRef.value)
  }
}

const updatePieChart = () => {
  if (!pieChart) return
  
  const byType = stats.value.vulnerability_stats?.by_type || {}
  const data = Object.entries(byType).map(([name, value]) => ({ name, value }))
  
  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left'
    },
    series: [
      {
        name: '漏洞类型',
        type: 'pie',
        radius: ['40%', '70%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 10,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: false,
          position: 'center'
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 16,
            fontWeight: 'bold'
          }
        },
        labelLine: {
          show: false
        },
        data: data.length > 0 ? data : [
          { name: '暂无数据', value: 1 }
        ]
      }
    ],
    color: ['#5470c6', '#91cc75', '#fac858', '#ee6666', '#73c0de', '#3ba272', '#fc8452']
  }
  
  pieChart.setOption(option)
}

const updateLineChart = () => {
  if (!lineChart) return
  
  const now = new Date()
  const days = []
  const scanData = []
  
  for (let i = 6; i >= 0; i--) {
    const date = new Date(now)
    date.setDate(date.getDate() - i)
    days.push(`${date.getMonth() + 1}/${date.getDate()}`)
    scanData.push(Math.floor(Math.random() * 10))
  }
  
  if (stats.value.vulnerability_stats?.total_scans > 0) {
    scanData[scanData.length - 1] = stats.value.vulnerability_stats.total_scans % 10 + 1
  }
  
  const option = {
    tooltip: {
      trigger: 'axis'
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: days
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        name: '扫描次数',
        type: 'line',
        stack: 'Total',
        data: scanData,
        smooth: true,
        areaStyle: {
          opacity: 0.3
        }
      }
    ]
  }
  
  lineChart.setOption(option)
}

const updateBarChart = () => {
  if (!barChart) return
  
  const mockIPData = [
    { name: '192.168.1.100', value: 15 },
    { name: '10.0.0.50', value: 12 },
    { name: '172.16.0.10', value: 8 },
    { name: '192.168.2.200', value: 5 },
    { name: '10.10.10.10', value: 3 }
  ]
  
  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'shadow'
      }
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: mockIPData.map(d => d.name),
      axisLabel: {
        rotate: 30
      }
    },
    yAxis: {
      type: 'value',
      name: '攻击次数'
    },
    series: [
      {
        name: '攻击次数',
        type: 'bar',
        data: mockIPData.map(d => d.value),
        itemStyle: {
          color: '#ee6666'
        }
      }
    ]
  }
  
  barChart.setOption(option)
}

const fetchStats = async () => {
  try {
    const response = await getDashboardStats()
    stats.value = response.data
    recentFindings.value = response.data.recent_findings || []
    updatePieChart()
    updateLineChart()
    updateBarChart()
  } catch (error) {
    console.error('获取统计数据失败:', error)
    updatePieChart()
    updateLineChart()
    updateBarChart()
  }
}

const refreshData = () => {
  fetchStats()
  ElMessage.success('数据已刷新')
}

const startNewScan = async () => {
  if (!scanForm.sessions_json) {
    ElMessage.warning('请输入会话JSON文件路径')
    return
  }
  
  try {
    const response = await startScan({
      sessions_json: scanForm.sessions_json,
      base_url: scanForm.base_url || undefined
    })
    
    ElMessage.success(`扫描任务已启动: ${response.data.scan_id}`)
    scanDialogVisible.value = false
    scanForm.sessions_json = ''
    scanForm.base_url = ''
    
    setTimeout(fetchStats, 2000)
  } catch (error) {
    ElMessage.error('启动扫描失败: ' + (error.response?.data?.error || error.message))
  }
}

const handleResize = () => {
  pieChart?.resize()
  lineChart?.resize()
  barChart?.resize()
}

onMounted(() => {
  initCharts()
  fetchStats()
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  pieChart?.dispose()
  lineChart?.dispose()
  barChart?.dispose()
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
.dashboard {
  height: 100%;
}

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  text-align: center;
  padding: 20px;
}

.stat-icon {
  margin-bottom: 10px;
}

.stat-icon.primary {
  color: #409EFF;
}

.stat-icon.success {
  color: #67C23A;
}

.stat-icon.warning {
  color: #E6A23C;
}

.stat-icon.danger {
  color: #F56C6C;
}

.stat-value {
  font-size: 36px;
  font-weight: bold;
  color: #409EFF;
}

.highlight-danger {
  color: #F56C6C;
}

.highlight-success {
  color: #67C23A;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 8px;
}

.charts-row {
  margin-bottom: 20px;
}

.chart-container {
  height: 350px;
  width: 100%;
}

.recent-row {
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.url-text {
  font-family: monospace;
  font-size: 12px;
  color: #606266;
}

.card-title {
  font-size: 16px;
  font-weight: bold;
  color: #303133;
}
</style>
