<template>
  <div class="vulnerabilities-page">
    <el-card shadow="never" class="header-card">
      <template #header>
        <span class="page-title">漏洞发现</span>
      </template>
      <p class="description">查看所有检测到的 SQL 注入漏洞，包括详细信息和重放测试结果。</p>
    </el-card>

    <el-card shadow="never" style="margin-top: 20px;">
      <template #header>
        <div class="filter-bar">
          <div class="filter-left">
            <el-select v-model="filterStatus" placeholder="状态筛选" clearable @change="fetchVulnerabilities" style="width: 140px; margin-right: 10px;">
              <el-option label="HIGH" value="HIGH" />
              <el-option label="MEDIUM" value="MEDIUM" />
              <el-option label="LOW" value="LOW" />
            </el-select>
            <el-select v-model="filterType" placeholder="类型筛选" clearable @change="fetchVulnerabilities" style="width: 160px; margin-right: 10px;">
              <el-option label="UNION-Based" value="UNION-Based" />
              <el-option label="Error-Based" value="Error-Based" />
              <el-option label="Boolean-Based" value="Boolean-Based" />
              <el-option label="Time-Based" value="Time-Based" />
              <el-option label="Blind" value="Blind" />
              <el-option label="Stacked Queries" value="Stacked Queries" />
            </el-select>
          </div>
          <el-button size="small" @click="fetchVulnerabilities">
            <el-icon><Refresh/></el-icon>
            刷新
          </el-button>
        </div>
      </template>

      <el-table :data="vulnerabilities" stripe style="width: 100%" v-loading="loading">
        <el-table-column prop="method" label="方法" width="80">
          <template #default="scope">
            <el-tag :type="getMethodTagType(scope.row.method)" size="small">
              {{ scope.row.method }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip>
          <template #default="scope">
            <span class="url-text">{{ scope.row.url }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="严重性" width="100">
          <template #default="scope">
            <el-tag :type="getSeverityTagType(scope.row.severity)" size="small">
              {{ scope.row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source_ip" label="源IP" width="130" />
        <el-table-column prop="dest_ip" label="目标IP" width="130" />
        <el-table-column prop="payload_types" label="Payload类型" min-width="180">
          <template #default="scope">
            <div class="payload-tags">
              <el-tag 
                v-for="(type, index) in getUniquePayloadTypes(scope.row.payloads)" 
                :key="index"
                size="mini"
                style="margin-right: 4px; margin-bottom: 4px;"
              >
                {{ type }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="max_confidence" label="最高置信度" width="120">
          <template #default="scope">
            <el-progress 
              :percentage="getMaxConfidence(scope.row.payloads) * 100" 
              :stroke-width="10"
              :color="getConfidenceColor(getMaxConfidence(scope.row.payloads))"
              :format="formatPercentage"
            />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="scope">
            <el-button type="primary" link size="small" @click="viewDetails(scope.row)">
              <el-icon><View/></el-icon>
              详情
            </el-button>
            <el-button type="success" link size="small" @click="runReplay(scope.row)">
              <el-icon><VideoPlay/></el-icon>
              重放测试
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
        style="margin-top: 20px; justify-content: flex-end;"
      />
    </el-card>

    <el-dialog
      v-model="detailDialogVisible"
      title="漏洞详情"
      width="900px"
    >
      <el-descriptions :column="2" border>
        <el-descriptions-item label="会话ID">{{ currentVulnerability.session_id }}</el-descriptions-item>
        <el-descriptions-item label="方法">
          <el-tag :type="getMethodTagType(currentVulnerability.method)" size="small">
            {{ currentVulnerability.method }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="URL" :span="2">{{ currentVulnerability.url }}</el-descriptions-item>
        <el-descriptions-item label="源IP">{{ currentVulnerability.source_ip }}</el-descriptions-item>
        <el-descriptions-item label="目标IP">{{ currentVulnerability.dest_ip }}</el-descriptions-item>
        <el-descriptions-item label="严重性">
          <el-tag :type="getSeverityTagType(currentVulnerability.severity)" size="small">
            {{ currentVulnerability.severity }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Payload数量">{{ currentVulnerability.payloads?.length || 0 }} 个</el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">Payload 详情</el-divider>

      <el-table :data="currentVulnerability.payloads || []" stripe size="small">
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="payload" label="Payload内容" min-width="250" show-overflow-tooltip>
          <template #default="scope">
            <code class="payload-code">{{ scope.row.payload }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="injection_type" label="注入类型" width="140">
          <template #default="scope">
            <el-tag size="small">{{ scope.row.injection_type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="location" label="位置" width="140" />
        <el-table-column prop="confidence" label="置信度" width="120">
          <template #default="scope">
            <el-progress 
              :percentage="scope.row.confidence * 100" 
              :stroke-width="8"
              :color="getConfidenceColor(scope.row.confidence)"
            />
          </template>
        </el-table-column>
      </el-table>

      <el-divider content-position="left" v-if="currentVulnerability.context">上下文</el-divider>
      <el-input
        v-if="currentVulnerability.context"
        type="textarea"
        :rows="4"
        :model-value="currentVulnerability.context"
        readonly
        style="font-family: monospace;"
      />

      <el-divider content-position="left">原始请求</el-divider>
      <el-input
        type="textarea"
        :rows="8"
        :model-value="currentVulnerability.request_raw"
        readonly
        style="font-family: monospace; font-size: 12px;"
      />

      <el-divider content-position="left" v-if="currentVulnerability.response_raw">原始响应</el-divider>
      <el-input
        v-if="currentVulnerability.response_raw"
        type="textarea"
        :rows="8"
        :model-value="currentVulnerability.response_raw"
        readonly
        style="font-family: monospace; font-size: 12px;"
      />
    </el-dialog>

    <el-dialog
      v-model="replayDialogVisible"
      title="漏洞重放测试"
      width="700px"
    >
      <el-form :model="replayForm" label-width="120px">
        <el-form-item label="目标URL">
          <el-input v-model="replayForm.target_url" placeholder="请输入目标URL" />
        </el-form-item>
        <el-form-item label="基础URL">
          <el-input v-model="replayForm.base_url" placeholder="例如: http://example.com (可选)" />
        </el-form-item>
        <el-form-item label="超时时间">
          <el-input-number
            v-model="replayForm.timeout"
            :min="5"
            :max="60"
            :step="5"
          />
          <span style="margin-left: 10px; color: #909399;">秒</span>
        </el-form-item>
      </el-form>

      <el-divider v-if="replayResult">测试结果</el-divider>

      <div v-if="replayResult" class="replay-result">
        <el-alert
          :title="`测试状态: ${replayResult.status}`"
          :type="getReplayAlertType(replayResult.status)"
          :closable="false"
          style="margin-bottom: 15px;"
        />

        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="目标URL">{{ replayResult.target_url }}</el-descriptions-item>
          <el-descriptions-item label="置信度">
            <el-progress 
              :percentage="replayResult.confidence * 100" 
              :stroke-width="12"
              :color="getConfidenceColor(replayResult.confidence)"
            />
          </el-descriptions-item>
        </el-descriptions>

        <el-divider>证据</el-divider>
        <div v-if="replayResult.evidence?.length > 0" class="evidence-list">
          <div v-for="(evidence, index) in replayResult.evidence" :key="index" class="evidence-item">
            <el-icon><CaretRight/></el-icon>
            <span>{{ evidence }}</span>
          </div>
        </div>
        <el-empty v-else description="暂无证据" :image-size="60" />

        <el-divider v-if="replayResult.error_message">错误信息</el-divider>
        <el-alert
          v-if="replayResult.error_message"
          :title="replayResult.error_message"
          type="error"
          :closable="false"
        />
      </div>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="replayDialogVisible = false">关闭</el-button>
          <el-button type="primary" :loading="replaying" @click="executeReplay">
            执行测试
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, View, VideoPlay, CaretRight } from '@element-plus/icons-vue'
import { getVulnerabilities, runReplayTest } from '../api'

const loading = ref(false)
const vulnerabilities = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const filterStatus = ref('')
const filterType = ref('')

const detailDialogVisible = ref(false)
const currentVulnerability = ref({})

const replayDialogVisible = ref(false)
const replaying = ref(false)
const replayForm = reactive({
  target_url: '',
  base_url: '',
  timeout: 10
})
const replayResult = ref(null)

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

const getConfidenceColor = (confidence) => {
  if (confidence >= 0.8) return '#F56C6C'
  if (confidence >= 0.5) return '#E6A23C'
  return '#909399'
}

const formatPercentage = (percentage) => `${(percentage / 100).toFixed(2)}`

const getUniquePayloadTypes = (payloads) => {
  if (!payloads) return []
  return [...new Set(payloads.map(p => p.injection_type))]
}

const getMaxConfidence = (payloads) => {
  if (!payloads || payloads.length === 0) return 0
  return Math.max(...payloads.map(p => p.confidence))
}

const getReplayAlertType = (status) => {
  const types = {
    'CONFIRMED': 'error',
    'UNCONFIRMED': 'warning',
    'FALSE_POSITIVE': 'info',
    'ERROR': 'warning'
  }
  return types[status] || 'info'
}

const fetchVulnerabilities = async () => {
  loading.value = true
  try {
    const params = {
      page: currentPage.value,
      per_page: pageSize.value
    }
    if (filterStatus.value) params.status = filterStatus.value
    if (filterType.value) params.type = filterType.value

    const response = await getVulnerabilities(params)
    vulnerabilities.value = response.data.data || generateMockVulnerabilities()
    total.value = response.data.total || vulnerabilities.value.length
  } catch (error) {
    console.error('获取漏洞列表失败:', error)
    vulnerabilities.value = generateMockVulnerabilities()
    total.value = vulnerabilities.value.length
  } finally {
    loading.value = false
  }
}

const generateMockVulnerabilities = () => {
  return [
    {
      session_id: 'session_001',
      method: 'GET',
      url: '/api/users?id=1 UNION SELECT 1,2,3--',
      severity: 'HIGH',
      source_ip: '192.168.1.100',
      dest_ip: '10.0.0.1',
      payloads: [
        { payload: 'UNION SELECT 1,2,3--', injection_type: 'UNION-Based', location: 'URI', confidence: 0.95 },
        { payload: '--', injection_type: 'Comment', location: 'URI', confidence: 0.5 }
      ]
    },
    {
      session_id: 'session_002',
      method: 'POST',
      url: '/api/login',
      severity: 'MEDIUM',
      source_ip: '10.0.0.50',
      dest_ip: '10.0.0.1',
      payloads: [
        { payload: "' OR '1'='1", injection_type: 'Boolean-Based', location: 'Body', confidence: 0.8 }
      ]
    },
    {
      session_id: 'session_003',
      method: 'GET',
      url: '/api/search?q=test AND SLEEP(5)--',
      severity: 'HIGH',
      source_ip: '172.16.0.10',
      dest_ip: '10.0.0.1',
      payloads: [
        { payload: 'AND SLEEP(5)--', injection_type: 'Time-Based', location: 'URI', confidence: 0.95 },
        { payload: '--', injection_type: 'Comment', location: 'URI', confidence: 0.5 }
      ]
    }
  ]
}

const handleSizeChange = (val) => {
  pageSize.value = val
  fetchVulnerabilities()
}

const handleCurrentChange = (val) => {
  currentPage.value = val
  fetchVulnerabilities()
}

const viewDetails = (vulnerability) => {
  currentVulnerability.value = vulnerability
  detailDialogVisible.value = true
}

const runReplay = (vulnerability) => {
  replayForm.target_url = vulnerability.url || ''
  replayForm.base_url = ''
  replayForm.timeout = 10
  replayResult.value = null
  currentVulnerability.value = vulnerability
  replayDialogVisible.value = true
}

const executeReplay = async () => {
  if (!replayForm.target_url) {
    ElMessage.warning('请输入目标URL')
    return
  }

  replaying.value = true
  try {
    const response = await runReplayTest({
      finding: {
        ...currentVulnerability.value,
        url: replayForm.target_url
      },
      base_url: replayForm.base_url || undefined,
      timeout: replayForm.timeout
    })
    replayResult.value = response.data
    ElMessage.success('重放测试完成')
  } catch (error) {
    ElMessage.error('重放测试失败: ' + (error.response?.data?.error || error.message))
    replayResult.value = {
      status: 'ERROR',
      target_url: replayForm.target_url,
      confidence: 0,
      evidence: [],
      error_message: error.message
    }
  } finally {
    replaying.value = false
  }
}

onMounted(() => {
  fetchVulnerabilities()
})
</script>

<style scoped>
.vulnerabilities-page {
  height: 100%;
}

.header-card {
  margin-bottom: 20px;
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

.filter-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filter-left {
  display: flex;
  align-items: center;
}

.url-text {
  font-family: monospace;
  font-size: 12px;
  color: #606266;
}

.payload-tags {
  display: flex;
  flex-wrap: wrap;
}

.payload-code {
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 11px;
  color: #F56C6C;
}

.replay-result {
  max-height: 400px;
  overflow-y: auto;
}

.evidence-list {
  background: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
}

.evidence-item {
  display: flex;
  align-items: flex-start;
  padding: 5px 0;
  color: #606266;
}

.evidence-item .el-icon {
  margin-right: 8px;
  margin-top: 2px;
  color: #409EFF;
}
</style>
