<template>
  <el-config-provider :locale="zhCn">
    <div class="app-container">
      <el-container class="main-container">
        <el-aside width="200px" class="sidebar">
          <div class="logo">
            <el-icon :size="32"><Shield/></el-icon>
            <span class="logo-text">流量分析沙盒</span>
          </div>
          <el-menu
            :default-active="$route.path"
            class="el-menu-vertical-demo"
            background-color="#304156"
            text-color="#bfcbd9"
            active-text-color="#409EFF"
            router
          >
            <el-menu-item index="/">
              <el-icon><Monitor/></el-icon>
              <span>仪表盘</span>
            </el-menu-item>
            <el-menu-item index="/scans">
              <el-icon><Search/></el-icon>
              <span>扫描任务</span>
            </el-menu-item>
            <el-menu-item index="/vulnerabilities">
              <el-icon><Warning/></el-icon>
              <span>漏洞发现</span>
            </el-menu-item>
            <el-menu-item index="/malicious-ips">
              <el-icon><User/></el-icon>
              <span>恶意IP</span>
            </el-menu-item>
          </el-menu>
        </el-aside>
        <el-main class="main-content">
          <router-view/>
        </el-main>
      </el-container>
    </div>
  </el-config-provider>
</template>

<script setup>
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'
import { Shield, Monitor, Search, Warning, User } from '@element-plus/icons-vue'
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body, #app {
  height: 100%;
  width: 100%;
}

.app-container {
  height: 100%;
  width: 100%;
}

.main-container {
  height: 100%;
}

.sidebar {
  background-color: #304156;
  height: 100%;
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  color: #fff;
  border-bottom: 1px solid #1f2d3d;
}

.logo-text {
  margin-left: 10px;
  font-size: 16px;
  font-weight: bold;
}

.el-menu-vertical-demo:not(.el-menu--collapse) {
  width: 200px;
  min-height: 400px;
  border: none;
}

.main-content {
  background-color: #f0f2f5;
  padding: 20px;
  overflow-y: auto;
}

.card-title {
  font-size: 16px;
  font-weight: bold;
  color: #303133;
}

.stat-card {
  text-align: center;
  padding: 20px;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: #409EFF;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 8px;
}

.highlight-warning {
  color: #E6A23C;
}

.highlight-danger {
  color: #F56C6C;
}

.highlight-success {
  color: #67C23A;
}
</style>
