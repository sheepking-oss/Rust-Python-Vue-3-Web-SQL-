# 自动化漏洞扫描与流量分析沙盒

面向 CTF 竞赛的高性能流量分析沙盒。Rust 构建底层的极速流量包解析引擎，Python 负责对切片后的流量进行正则特征提取（如定位 SQL 注入）并进行漏洞重放测试，前端负责直观呈现分析结果。

## 项目结构

```
Rust-Python-Vue-3-Web-SQL-/
├── rust-engine/              # Rust 底层引擎
│   ├── src/
│   │   ├── main.rs          # 主程序入口
│   │   ├── lib.rs           # 库定义
│   │   ├── pcap_parser.rs   # PCAP 流量包解析
│   │   └── http_session.rs  # HTTP 会话还原
│   └── Cargo.toml
│
├── python-module/            # Python 分析模块
│   ├── main.py               # 命令行入口
│   ├── api_server.py         # Flask API 服务
│   ├── sql_injection_detector.py  # SQL 注入检测
│   ├── replay_tester.py      # 漏洞重放测试
│   └── requirements.txt
│
├── frontend/                  # Vue 3 前端仪表盘
│   ├── src/
│   │   ├── views/
│   │   │   ├── Dashboard.vue      # 仪表盘主页
│   │   │   ├── Scans.vue          # 扫描任务管理
│   │   │   ├── Vulnerabilities.vue # 漏洞发现
│   │   │   └── MaliciousIPs.vue   # 恶意IP列表
│   │   ├── api/index.js      # API 接口封装
│   │   ├── router/index.js   # 路由配置
│   │   ├── App.vue           # 根组件
│   │   └── main.js           # 入口文件
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
└── README.md
```

## 功能特性

### 1. Rust 底层引擎
- **PCAP 解析**：高性能解析网络流量包（支持 PCAP 格式）
- **协议解析**：支持 Ethernet、IPv4/IPv6、TCP/UDP 协议
- **会话还原**：智能重组 TCP 流，还原完整 HTTP 会话
- **JSON 输出**：将还原的会话数据输出为 JSON 格式供 Python 处理

### 2. Python 分析模块
- **SQL 注入检测**：使用正则表达式匹配多种 SQL 注入特征
  - UNION-Based 注入
  - Error-Based 注入
  - Boolean-Based 注入
  - Time-Based 盲注
  - 堆叠查询攻击
- **漏洞重放测试**：对检测到的漏洞进行目标 URL 重放验证
  - 时间延迟检测
  - 布尔条件对比
  - 错误信息分析
- **API 服务**：提供 RESTful API 供前端调用

### 3. Vue 3 前端仪表盘
- **实时数据展示**：动态渲染统计数据和图表
- **漏洞类型分布**：饼图展示各类 SQL 注入分布
- **扫描趋势**：折线图展示扫描历史趋势
- **恶意IP监控**：柱状图展示恶意IP活跃度
- **任务管理**：创建、查看、管理扫描任务
- **详细信息**：查看漏洞详情、Payload 信息、原始请求响应

## 快速开始

### 环境要求
- Rust 1.70+
- Python 3.9+
- Node.js 18+
- npm 或 yarn

### 1. 构建 Rust 引擎

```bash
cd rust-engine
cargo build --release
```

使用方式：
```bash
# 解析 PCAP 文件并输出 JSON
cargo run --release -- -i input.pcap -o sessions.json

# 或使用编译后的二进制
./target/release/pcap_engine -i input.pcap -o sessions.json
```

### 2. 安装 Python 依赖

```bash
cd python-module
pip install -r requirements.txt
```

命令行使用：
```bash
# 检测 SQL 注入漏洞
python main.py detect -i sessions.json -o findings.json

# 漏洞重放测试
python main.py replay -i findings.json -u http://target.com

# 完整扫描（检测 + 重放）
python main.py scan -i sessions.json -u http://target.com -o result.json
```

启动 API 服务：
```bash
python api_server.py
```

### 3. 安装前端依赖

```bash
cd frontend
npm install
```

开发模式：
```bash
npm run dev
```

生产构建：
```bash
npm run build
```

## API 接口

| 接口 | 方法 | 描述 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/dashboard/stats` | GET | 获取仪表盘统计数据 |
| `/api/malicious-ips` | GET | 获取恶意IP列表 |
| `/api/malicious-ips/{ip}` | GET | 获取指定IP详情 |
| `/api/vulnerabilities` | GET | 获取漏洞列表 |
| `/api/scan` | POST | 启动新扫描任务 |
| `/api/scan/{id}` | GET | 获取扫描任务状态 |
| `/api/scans` | GET | 获取所有扫描任务 |
| `/api/replay` | POST | 执行漏洞重放测试 |

## SQL 注入检测规则

检测引擎包含以下规则类型：

1. **UNION 注入**：`UNION SELECT`, `UNION ALL SELECT`
2. **报错注入**：`EXTRACTVALUE`, `UPDATEXML`, `XPATH error`
3. **布尔注入**：`AND 1=1`, `OR 1=1`, `AND TRUE`
4. **时间盲注**：`SLEEP()`, `WAITFOR DELAY`, `PG_SLEEP()`
5. **注释符**：`--`, `#`, `/* */`
6. **堆叠查询**：`; DROP`, `; INSERT`, `; UPDATE`
7. **盲注特征**：`SUBSTRING()`, `ASCII()`, `CHAR()`, `LIKE`

## 工作流程

1. **流量捕获**：使用 Wireshark 或 tcpdump 捕获网络流量，保存为 PCAP 文件
2. **流量解析**：Rust 引擎解析 PCAP 文件，还原 HTTP 会话
3. **漏洞检测**：Python 模块分析还原的会话，提取 SQL 注入 Payload
4. **重放验证**：对可疑 Payload 进行目标 URL 重放测试
5. **结果展示**：前端仪表盘动态展示恶意 IP 和漏洞验证结果

## 注意事项

- 本工具仅用于合法的安全测试和 CTF 竞赛
- 未经授权测试他人系统属于违法行为
- 重放测试可能对目标系统造成影响，请谨慎使用
- 检测规则可能产生误报，需结合人工分析确认

## 许可证

MIT License

