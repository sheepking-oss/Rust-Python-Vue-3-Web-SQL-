<template>
  <div class="malicious-ips-page">
    <el-card shadow="never" class="header-card">
      <template #header>
        <div class="header-content">
          <span class="page-title">恶意IP</span>
          <div class="header-actions">
            <el-input
              v-model="searchIP"
              placeholder="搜索IP地址"
              style="width: 200px; margin-right: 10px;"
              clearable
              @clear="fetchIPs"
              @keyup.enter="searchIPs"
            >
              <template #prefix>
                <el-icon><Search/></el-icon>
              </template>
            </el-input>
            <el-button type="primary" @click="searchIPs">
              <el-icon><Search/></el-icon>
              搜索
            </el-button>
          </div>
        </div>
      </template>
      <p class="description">检测到的恶意IP地址列表，显示攻击类型、攻击次数和目标。</p>
    </el-card>

    <el-row :gutter="20" style="margin-bottom: 20px;">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon-box primary">
            <el-icon :size="24"><User/></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-number">{{ ipStats.total }}</div>
            <div class="stat-label">恶意IP总数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon-box danger">
            <el-icon :size="24"><Warning/></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-number">{{ ipStats.highRisk }}</div>
            <div class="stat-label">高风险IP</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon-box warning">
            <el-icon :size="24"><TrendCharts/></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-number">{{ ipStats.totalAttacks }}</div>
            <div class="stat-label">总攻击次数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon-box success">
            <el-icon :size="24"><Target/></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-number">{{ ipStats.targets }}</div>
            <div class="stat-label">受攻击目标</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>
        <div class="table-header">
          <span>IP列表</span>
          <el-button size="small" @click="fetchIPs">
            <el-icon><Refresh/></el-icon>
            刷新
          </el-button>
        </div>
      </template>

      <el-table :data="maliciousIPs" stripe style="width: 100%" v-loading="loading">
        <el-table-column prop="ip" label="IP地址" width="160">
          <template #default="scope">
            <span class="ip-address">{{ scope.row.ip }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="风险等级" width="100">
          <template #default="scope">
            <el-tag :type="getSeverityTagType(scope.row.severity)" size="small">
              {{ scope.row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="attack_count" label="攻击次数" width="100" sortable>
          <template #default="scope">
            <span class="attack-count">{{ scope.row.attack_count }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="attack_types" label="攻击类型" min-width="250">
          <template #default="scope">
            <div class="attack-tags">
              <el-tag 
                v-for="(type, index) in scope.row.attack_types" 
                :key="index"
                size="mini"
                :type="getAttackTagType(type)"
                style="margin-right: 4px; margin-bottom: 4px;"
              >
                {{ type }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="targets" label="目标IP" min-width="150" show-overflow-tooltip>
          <template #default="scope">
            <div class="target-list">
              <span v-for="(target, index) in scope.row.targets?.slice(0, 3)" :key="index" class="target-item">
                {{ target }}
              </span>
              <el-tag v-if="scope.row.targets?.length > 3" size="mini" type="info">
                +{{ scope.row.targets.length - 3 }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="first_seen" label="首次发现" width="160">
          <template #default="scope">
            <span>{{ formatTime(scope.row.first_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最近活动" width="160">
          <template #default="scope">
            <span>{{ formatTime(scope.row.last_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="scope">
            <el-button type="primary" link size="small" @click="viewIPDetails(scope.row)">
              <el-icon><View/></el-icon>
              详情
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
      title="IP详情"
      width="700px"
    >
      <el-descriptions :column="2" border>
        <el-descriptions-item label="IP地址">
          <span class="detail-ip">{{ currentIP.ip }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="风险等级">
          <el-tag :type="getSeverityTagType(currentIP.severity)" size="small">
            {{ currentIP.severity }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="攻击次数">
          <span class="highlight-number">{{ currentIP.attack_count }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="攻击类型数量">
          <span class="highlight-number">{{ currentIP.attack_types?.length || 0 }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="首次发现" :span="2">
          {{ formatTime(currentIP.first_seen) }}
        </el-descriptions-item>
        <el-descriptions-item label="最近活动" :span="2">
          {{ formatTime(currentIP.last_seen) }}
        </el-descriptions-item>
      </el-descriptions>

      <el-divider content-position="left">攻击类型</el-divider>
      <div class="detail-attack-types">
        <el-tag 
          v-for="(type, index) in currentIP.attack_types" 
          :key="index"
          :type="getAttackTagType(type)"
          style="margin-right: 8px; margin-bottom: 8px;"
        >
          {{ type }}
        </el-tag>
      </div>

      <el-divider content-position="left">攻击目标 ({{ currentIP.targets?.length || 0 }})</el-divider>
      <el-table :data="currentIP.targets || []" stripe size="small" v-if="currentIP.targets?.length > 0">
        <el-table-column type="index" label="序号" width="60" />
        <el-table-column prop="target" label="目标IP">
          <template #default="scope">
            <span class="target-ip">{{ scope.row }}</span>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-else description="暂无目标记录" :image-size="60" />
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, User, Warning, TrendCharts, Target, Refresh, View } from '@element-plus/icons-vue'
import { getMaliciousIPs, getMaliciousIP } from '../api'

const loading = ref(false)
const maliciousIPs = ref([])
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const searchIP = ref('')

const detailDialogVisible = ref(false)
const currentIP = ref({})

const ipStats = computed(() => {
  const ips = maliciousIPs.value || []
  const highRisk = ips.filter(ip => ip.severity === 'HIGH').length
  const totalAttacks = ips.reduce((sum, ip) => sum + (ip.attack_count || 0), 0)
  const targets = new Set()
  ips.forEach(ip => {
    ip.targets?.forEach(t => targets.add(t))
  })

  return {
    total: total.value || ips.length,
    highRisk,
    totalAttacks,
    targets: targets.size
  }
})

const getSeverityTagType = (severity) => {
  const types = {
    'HIGH': 'danger',
    'MEDIUM': 'warning',
    'LOW': 'info'
  }
  return types[severity] || 'info'
}

const getAttackTagType = (type) => {
  const types = {
    'Time-Based': 'danger',
    'UNION-Based': 'warning',
    'Error-Based': 'danger',
    'Boolean-Based': 'warning',
    'Blind': 'info',
    'Stacked Queries': 'danger',
    'Comment': 'info'
  }
  return types[type] || 'info'
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN')
}

const fetchIPs = async () => {
  loading.value = true
  try {
    const response = await getMaliciousIPs({
      page: currentPage.value,
      per_page: pageSize.value
    })
    maliciousIPs.value = response.data.data || generateMockIPs()
    total.value = response.data.total || maliciousIPs.value.length
  } catch (error) {
    console.error('获取恶意IP列表失败:', error)
    maliciousIPs.value = generateMockIPs()
    total.value = maliciousIPs.value.length
  } finally {
    loading.value = false
  }
}

const generateMockIPs = () => {
  return [
    {
      ip: '192.168.1.100',
      severity: 'HIGH',
      attack_count: 15,
      attack_types: ['Time-Based', 'UNION-Based', 'Boolean-Based'],
      targets: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
      first_seen: '2026-04-29T18:00:00',
      last_seen: '2026-04-29T20:30:00'
    },
    {
      ip: '10.0.0.50',
      severity: 'MEDIUM',
      attack_count: 12,
      attack_types: ['Boolean-Based', 'Error-Based'],
      targets: ['10.0.0.1'],
      first_seen: '2026-04-28T10:00:00',
      last_seen: '2026-04-29T19:00:00'
    },
    {
      ip: '172.16.0.10',
      severity: 'HIGH',
      attack_count: 8,
      attack_types: ['Time-Based', 'Stacked Queries'],
      targets: ['10.0.0.1', '10.0.0.5'],
      first_seen: '2026-04-29T15:00:00',
      last_seen: '2026-04-29T20:00:00'
    },
    {
      ip: '192.168.2.200',
      severity: 'LOW',
      attack_count: 3,
      attack_types: ['Comment'],
      targets: ['10.0.0.1'],
      first_seen: '2026-04-29T12:00:00',
      last_seen: '2026-04-29T13:00:00'
    }
  ]
}

const handleSizeChange = (val) => {
  pageSize.value = val
  fetchIPs()
}

const handleCurrentChange = (val) => {
  currentPage.value = val
  fetchIPs()
}

const searchIPs = () => {
  if (!searchIP.value) {
    fetchIPs()
    return
  }

  loading.value = true
  setTimeout(() => {
    const filtered = maliciousIPs.value.filter(ip => 
      ip.ip.includes(searchIP.value)
    )
    maliciousIPs.value = filtered
    total.value = filtered.length
    loading.value = false
    ElMessage.info(`找到 ${filtered.length} 个匹配结果`)
  }, 500)
}

const viewIPDetails = (ip) => {
  currentIP.value = ip
  detailDialogVisible.value = true
}

onMounted(() => {
  fetchIPs()
})
</script>

<style scoped>
.malicious-ips-page {
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

.header-actions {
  display: flex;
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

.stat-card {
  display: flex;
  align-items: center;
  padding: 15px;
}

.stat-icon-box {
  width: 60px;
  height: 60px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 15px;
}

.stat-icon-box.primary {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
}

.stat-icon-box.danger {
  background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
  color: white;
}

.stat-icon-box.warning {
  background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
  color: white;
}

.stat-icon-box.success {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: white;
}

.stat-info {
  flex: 1;
}

.stat-number {
  font-size: 28px;
  font-weight: bold;
  color: #303133;
}

.stat-label {
  font-size: 13px;
  color: #909399;
  margin-top: 4px;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.ip-address {
  font-family: monospace;
  font-size: 14px;
  font-weight: bold;
  color: #409EFF;
}

.attack-count {
  font-weight: bold;
  color: #F56C6C;
}

.attack-tags {
  display: flex;
  flex-wrap: wrap;
}

.target-list {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
}

.target-item {
  font-family: monospace;
  font-size: 12px;
  color: #606266;
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 4px;
  margin-right: 4px;
  margin-bottom: 4px;
}

.detail-ip {
  font-family: monospace;
  font-size: 18px;
  font-weight: bold;
  color: #409EFF;
}

.highlight-number {
  font-size: 20px;
  font-weight: bold;
  color: #F56C6C;
}

.detail-attack-types {
  display: flex;
  flex-wrap: wrap;
}

.target-ip {
  font-family: monospace;
  color: #606266;
}
</style>
