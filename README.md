# ThreatSync

威胁感知爬虫工具 - 一个用于采集和同步各种威胁情报数据的自动化工具

## 功能特性

- 🔄 **多源数据采集**: 支持从 NVD、GitHub、OSV、CNVD 等多个数据源采集威胁情报
- 📊 **结构化存储**: 将非结构化数据转换为标准化的JSON格式
- 🔒 **安全配置**: 支持本地配置文件和环境变量，防止敏感信息泄露
- 📁 **智能存储**: 按年份和数据源自动分类存储数据文件
- 🔍 **增量同步**: 支持基于时间戳的增量数据同步
- 🧪 **完整测试**: 包含模拟数据测试和实际网络测试

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/XJTUOSS/ThreatSync.git
cd ThreatSync
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置API密钥（重要）

**方法A: 使用本地配置文件（推荐）**

```bash
# 复制配置模板
cp config/config.example.yaml config/config.local.yaml

# 编辑本地配置文件，填入真实的API密钥
# 注意：config.local.yaml 不会被提交到git
```

**方法B: 使用环境变量**

```bash
# Windows PowerShell
$env:GITHUB_TOKEN = "your_github_token_here"
$env:NVD_API_KEY = "your_nvd_api_key_here"

# Linux/Mac
export GITHUB_TOKEN="your_github_token_here"
export NVD_API_KEY="your_nvd_api_key_here"
```

### 4. 验证配置

```bash
python tests/test_security.py
```

### 5. 运行测试

```bash
# 运行模拟数据测试（不需要网络）
python tests/test_cnvd_json_mock.py

# 运行实际网络测试
python tests/test_cnvd_collector.py
```

## 项目结构

```
ThreatSync/
├── config/                 # 配置文件
│   ├── config.yaml         # 主配置文件（可提交）
│   ├── config.local.yaml   # 本地配置（不提交，包含密钥）
│   └── config.example.yaml # 配置示例（可提交）
├── data/                   # 数据文件（不提交）
│   ├── structured/         # 结构化数据
│   │   ├── nvd/           # NVD数据
│   │   ├── github/        # GitHub数据
│   │   └── osv/           # OSV数据
│   └── unstructured/      # 非结构化数据
│       └── cnvd/          # CNVD数据（按年份分类）
├── logs/                  # 日志文件（不提交）
├── src/                   # 源代码
│   ├── collectors/        # 数据采集器
│   ├── models/           # 数据模型
│   └── utils/            # 工具模块
├── tests/                # 测试文件
└── docs/                 # 文档
```

## 安全性

本项目采用了多层安全措施：

- 🔐 **配置分离**: 敏感配置与公共配置分离
- 🚫 **Git忽略**: 自动排除敏感文件和数据文件
- 🔑 **环境变量**: 支持使用环境变量管理密钥
- ✅ **安全测试**: 包含配置安全性验证

详细说明请参考 [SECURITY.md](SECURITY.md)

## 使用示例

### CNVD数据采集

```python
from src.main import ThreatSyncEngine

# 初始化引擎
engine = ThreatSyncEngine()

# 采集CNVD数据（保存为JSON文件）
engine.collectors['cnvd'].collect(
    days_back=7, 
    max_pages=5, 
    save_raw_json=True
)
```

## 参考资料

- [NVD API Documentation](https://nvd.nist.gov/developers/start-here)
- [NVD API Client Reference](https://github.com/eslerm/nvd-api-client.git)
- [Github advisory database](https://github.com/github/advisory-database.git)
- [Github graphql](https://docs.github.com/en/graphql/reference/queries#securityadvisories)
- [Github API](https://docs.github.com/zh/rest/security-advisories/global-advisories?apiVersion=2022-11-28)