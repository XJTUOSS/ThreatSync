# 安全配置指南

## 配置文件安全

### 1. 配置文件层次结构

- `config.local.yaml` - 本地配置，包含敏感信息，**不会**被提交
- `config.example.yaml` - 配置示例，**可以**提交到git

### 2. 设置API密钥的方法

#### 方法1: 使用本地配置文件（推荐）

1. 复制示例配置：
```bash
cp config/config.example.yaml config/config.local.yaml
```

2. 编辑 `config/config.local.yaml`，填入真实的API密钥：
```yaml
apis:
  github:
    token: "ghp_your_real_github_token_here"
  nvd:
    api_key: "your_real_nvd_api_key_here"
```

#### 方法2: 使用环境变量

设置环境变量：
```bash
# Windows PowerShell
$env:GITHUB_TOKEN = "ghp_your_real_github_token_here"
$env:NVD_API_KEY = "your_real_nvd_api_key_here"

# Linux/Mac
export GITHUB_TOKEN="ghp_your_real_github_token_here"
export NVD_API_KEY="your_real_nvd_api_key_here"
```

## 数据文件安全

### 已排除的文件和目录

以下文件/目录已在 `.gitignore` 中排除，不会被提交到GitHub：

- `data/` - 所有采集的数据文件
- `logs/` - 日志文件
- `config/config.local.yaml` - 本地配置文件
- `*.json` - JSON数据文件
- `*.db` - 数据库文件
- `.env*` - 环境变量文件

### 保留的目录结构

使用 `.gitkeep` 文件确保必要的目录被保留：
- `data/.gitkeep`
- `logs/.gitkeep`

## 验证配置

运行以下命令验证配置是否正确加载：

```bash
python -c "
from src.utils.config import ConfigManager
config = ConfigManager()
print('GitHub Token设置:', '✅' if config.get_api_config('github')['token'] else '❌')
print('NVD API Key设置:', '✅' if config.get_api_config('nvd')['api_key'] else '❌')
"
```