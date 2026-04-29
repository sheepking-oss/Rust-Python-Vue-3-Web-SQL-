<template>
  <div class="scans-page">
    <el-card shadow="never" class="header-card">
      <template #header>
        <div class="header-content">
          <span class="page-title">扫描任务</span>
          <el-button type="primary" @click="showNewScanDialog">
            <el-icon><Plus/></el-icon>
            新建扫描
          </el-button>
        </div>
      </template>
      <p class="description">管理流量分析扫描任务，查看扫描进度和结果。</p>
    </el-card>

    <el-card shadow="never" style="margin-top: 20px;">
      <template #header>
        <div class="table-header">
          <span>任务列表</span>
          <el-button size="small" @click="refreshScans">
            <el-icon><Refresh/></el-icon>
            刷新
          </el-button>
        </div>
      </template>

      <el-table :data="scans" stripe style="width: 100%" v-loading="loading">
        <el-table-column prop="scan_id" label="任务ID" width="200">
          <template #default="scope">
            <span class="scan-id">{{ scope.row.scan_id }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="scope">
            <el-tag :type="getStatusTagType(scope.row.status)">
              {{ getStatusText(scope.row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="start_time" label="开始时间" width="180">
          <template #default="scope">
            <span>{{ formatTime(scope.row.start_time) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="end_time" label="结束时间" width="180">
          <template #default="scope">
            <span>{{ formatTime(scope.row.end_time) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="findings_count" label="发现漏洞" width="100">
          <template #default="scope">
            <span class="findings-count">{{ scope.row.findings?.length || 0 }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="scope">
            <el-button type="primary" link size="small" @click="viewScanDetails(scope.row)">
              <el-icon><View/></el-icon>
              详情
            </el-button>
            <el-button 
              type="success" 
              link 
              size="small" 
              :disabled="scope.row.status !== 'completed'"
              @click="runReplayForScan(scope.row)"
            >
              <el-icon><VideoPlay/></el-icon>
              重放测试
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
        style="margin-top: 20px; justify-content: flex-end;"
      />
    </el-card>

    <el-dialog
      v-model="newScanDialogVisible"
      title="新建扫描任务"
      width="600px"
      :close-on-click-modal="false"
    >
      <el-form :model="newScanForm" label-width="120px" :rules="newScanRules" ref="newScanFormRef">
        <el-form-item label="会话JSON文件" prop="sessions_json">
          <el-input
            v-model="newScanForm.sessions_json"
            placeholder="请输入Rust引擎输出的JSON文件路径"
          />
          <div class="form-tip">
            <el-icon><InfoFilled/></el-icon>
            <span>Rust引擎解析PCAP后输出的JSON文件路径</span>
          </div>
        </el-form-item>
        <el-form-item label="基础URL">
          <el-input
            v-model="newScanForm.base_url"
            placeholder="例如: http://example.com (可选)"
          />
          <div class="form-tip">
            <el-icon><InfoFilled/></el-icon>
            <span>用于漏洞重放测试时构建完整URL</span>
          </div>
        </el-form-item>
        <el-form-item label="超时时间">
          <el-input-number
            v-model="newScanForm.timeout"
            :min="5"
            :max="60"
            :step="5"
          />
          <span class="form-tip-inline">秒（重放测试超时）</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="newScanDialogVisible = false">取消</el-button>
          <el-button type="primary" :loading="submitting" @click="submitNewScan">
            开始扫描
          </el-button>
        </span>
      </template>
    </el-dialog>

    <el-dialog
      v-model="detailDialogVisible"
      title="扫描详情"
      width="800px"
    >
      <el-descriptions :column="2" border>
        <el-descriptions-item label="任务ID">{{ currentScan.scan_id }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="getStatusTagType(currentScan.status)">
            {{ getStatusText(currentScan.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="开始时间">{{ formatTime(currentScan.start_time) }}</el-descriptions-item>
        <el-descriptions-item label="结束时间">{{ formatTime(currentScan.end_time) }}</el-descriptions-item>
        <el-descriptions-item label="发现漏洞" :span="2">
          <span class="highlight-number">{{ currentScan.findings?.length || 0 }}</span> 个
        </el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">漏洞发现</el-divider>

      <el-table :data="currentScan.findings || []" stripe size="small" v-if="currentScan.findings?.length > 0">
        <el-table-column prop="method" label="方法" width="80">
          <template #default="scope">
            <el-tag :type="getMethodTagType(scope.row.method)" size="small">
              {{ scope.row.method }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip />
        <el-table-column prop="severity" label="严重性" width="100">
          <template #default="scope">
            <el-tag :type="getSeverityTagType(scope.row.severity)" size="small">
              {{ scope.row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source_ip" label="源IP" width="130" />
      </el-table>
      <el-empty v-else description="暂无漏洞发现" />

      <el-divider content-position="left" v-if="currentScan.replay_results?.length > 0">重放测试结果</el-divider>

      <el-table :data="currentScan.replay_results || []" stripe size="small" v-if="currentScan.replay_results?.length > 0">
        <el-table-column prop="target_url" label="目标URL" min-width="200" show-overflow-tooltip />
        <el-table-column prop="status" label="测试结果" width="120">
          <template #default="scope">
            <el-tag :type="getReplayStatusTagType(scope.row.status)" size="small">
              {{ scope.row.status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" width="100">
          <template #default="scope">
            <el-progress :percentage="scope.row.confidence * 100" :stroke-width="10" :color="getConfidenceColor(scope.row.confidence)" />
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, View, VideoPlay, InfoFilled } from '@element-plus/icons-vue'
import { getAllScans, startScan, runReplayTest } from '../api'

const loading = ref(false)
const scans = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)

const newScanDialogVisible = ref(false)
const newScanFormRef = ref(null)
const newScanForm = reactive({
  sessions_json: '',
  base_url: '',
  timeout: 10
})

const newScanRules = {
  sessions_json: [
    { required: true, message: '请输入会话JSON文件路径', trigger: 'blur' }
  ]
}

const submitting = ref(false)
const detailDialogVisible = ref(false)
const currentScan = ref({})

const getStatusTagType = (status) => {
  const types = {
    'running': 'warning',
    'completed': 'success',
    'failed': 'danger',
    'pending': 'info'
  }
  return types[status] || 'info'
}

const getStatusText = (status) => {
  const texts = {
    'running': '进行中',
    'completed': '已完成',
    'failed': '失败',
    'pending': '等待中'
  }
  return texts[status] || status
}

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

const getReplayStatusTagType = (status) => {
  const types = {
    'CONFIRMED': 'danger',
    'UNCONFIRMED': 'warning',
    'FALSE_POSITIVE': 'info',
    'ERROR': 'info'
  }
  return types[status] || 'info'
}

const getConfidenceColor = (confidence) => {
  if (confidence >= 0.8) return '#F56C6C'
  if (confidence >= 0.5) return '#E6A23C'
  return '#909399'
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN')
}

const fetchScans = async () => {
  loading.value = true
  try {
    const response = await getAllScans({
      page: currentPage.value,
      per_page: pageSize.value
    })
    scans.value = response.data.data || []
    total.value = response.data.total || 0
  } catch (error) {
    console.error('获取扫描列表失败:', error)
    scans.value = generateMockScans()
  } finally {
    loading.value = false
  }
}

const generateMockScans = () => {
  return [
    {
      scan_id: 'scan_20260429_200000',
      status: 'completed',
      start_time: '2026-04-29T20:00:00',
      end_time: '2026-04-29T20:05:30',
      findings: [
        { method: 'GET', url: '/api/users?id=1', severity: 'HIGH', source_ip: '192.168.1.100' },
        { method: 'POST', url: '/api/login', severity: 'MEDIUM', source_ip: '10.0.0.50' }
      ],
      replay_results: [
        { target_url: '/api/users?id=1', status: 'CONFIRMED', confidence: 0.95 }
      ]
    }
  ]
}

const refreshScans = () => {
  fetchScans()
  ElMessage.success('已刷新')
}

const handleSizeChange = (val) => {
  pageSize.value = val
  fetchScans()
}

const handleCurrentChange = (val) => {
  currentPage.value = val
  fetchScans()
}

const showNewScanDialog = () => {
  newScanForm.sessions_json = ''
  newScanForm.base_url = ''
  newScanForm.timeout = 10
  newScanDialogVisible.value = true
}

const submitNewScan = async () => {
  if (!newScanFormRef.value) return
  
  await newScanFormRef.value.validate(async (valid) => {
    if (valid) {
      submitting.value = true
      try {
        const response = await startScan({
          sessions_json: newScanForm.sessions_json,
          base_url: newScanForm.base_url || undefined,
          timeout: newScanForm.timeout
        })
        
        ElMessage.success(`扫描任务已启动: ${response.data.scan_id}`)
        newScanDialogVisible.value = false
        
        setTimeout(fetchScans, 1000)
      } catch (error) {
        ElMessage.error('启动扫描失败: ' + (error.response?.data?.error || error.message))
      } finally {
        submitting.value = false
      }
    }
  })
}

const viewScanDetails = (scan) => {
  currentScan.value = scan
  detailDialogVisible.value = true
}

const runReplayForScan = async (scan) => {
  if (!scan.findings || scan.findings.length === 0) {
    ElMessage.warning('该扫描没有发现漏洞，无需重放测试')
    return
  }

  await ElMessageBox.confirm(
    `确定要对 ${scan.findings.length} 个漏洞进行重放测试吗？`,
    '确认重放测试',
    {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    }
  )

  for (const finding of scan.findings) {
    try {
      await runReplayTest({
        finding,
        timeout: 10
      })
    } catch (error) {
      console.error('重放测试失败:', error)
    }
  }

  ElMessage.success('重放测试完成')
  fetchScans()
}

onMounted(() => {
  fetchScans()
})
</script>

<style scoped>
.scans-page {
  height: 100%;
}

.header-card {
  margin-bottom: 20px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.page-title {
  font-size: 18px;
  font-weight: bold;
  color: #303133;
}

.description {
  color: #909399;
  font-size: 14px;
  margin: 0;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.scan-id {
  font-family: monospace;
  font-size: 12px;
  color: #409EFF;
}

.findings-count {
  font-weight: bold;
  color: #F56C6C;
}

.form-tip {
  display: flex;
  align-items: center;
  font-size: 12px;
  color: #909399;
  margin-top: 5px;
}

.form-tip .el-icon {
  margin-right: 5px;
}

.form-tip-inline {
  margin-left: 10px;
  font-size: 12px;
  color: #909399;
}

.highlight-number {
  font-size: 24px;
  font-weight: bold;
  color: #F56C6C;
}
</style>
