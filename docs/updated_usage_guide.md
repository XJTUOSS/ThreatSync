# ThreatSync 更新后的使用指南

## 新版本主要改进

### 🚀 核心架构变更
- **移除数据库依赖**: 不再需要MongoDB或SQLite，完全基于文件存储
- **遵循NVD最佳实践**: 严格按照官方文档优化API调用
- **统一配置管理**: 消除重复配置，简化配置文件结构
- **增强的命令行界面**: 提供更丰富的功能选项

### 📁 文件存储结构
```
data/
├── structured/           # 结构化数据
│   ├── nvd/             # NVD CVE数据
│   ├── github/          # GitHub漏洞数据
│   └── osv/             # OSV数据
├── unstructured/        # 非结构化数据
│   └── cnvd/            # CNVD数据
└── collection_results/  # 采集结果摘要
```

## 快速开始

### 1. 配置设置
复制示例配置并设置API密钥：
```bash
cp config.example.yaml config.yaml
# 编辑 config.local.yaml 设置真实的API密钥
```

### 2. 基本使用

#### 显示帮助信息
```bash
python run.py --help
```

#### 查看数据存储配置
```bash
python run.py --info
```

#### 查看统计信息
```bash
python run.py --stats
```

#### 执行数据采集
```bash
# 采集所有数据源最近7天数据
python run.py

# 采集指定数据源
python run.py --sources nvd --days 1
python run.py --sources github osv --days 3

# 采集CNVD非结构化数据
python run.py --sources cnvd
```

#### 导出数据
```bash
# 导出所有数据
python run.py --export data_export.json

# 导出指定数据源
python run.py --export nvd_data.json --sources nvd
```

#### 定时采集
```bash
# 启动定时任务（按配置文件中的间隔执行）
python run.py --mode schedule
```

#### 清理过期文件
```bash
python run.py --cleanup
```

## 命令行参数详解

| 参数 | 短参数 | 说明 | 示例 |
|------|--------|------|------|
| `--config` | `-c` | 指定配置文件路径 | `--config my_config.yaml` |
| `--mode` | `-m` | 运行模式：once/schedule | `--mode schedule` |
| `--sources` | `-s` | 指定数据源 | `--sources nvd github` |
| `--export` | `-e` | 导出数据到文件 | `--export data.json` |
| `--stats` | | 显示统计信息 | `--stats` |
| `--info` | | 显示存储配置信息 | `--info` |
| `--cleanup` | | 清理过期文件 | `--cleanup` |
| `--days` | `-d` | 回溯天数 | `--days 7` |

## 配置文件说明

### 主要配置项

#### API配置
```yaml
apis:
  nvd:
    api_key: "your_api_key"
    rate_limit:
      requests_per_30s: 50      # API速率限制
      sleep_between_requests: 6  # 请求间隔
    pagination:
      results_per_page: 2000    # 分页大小
```

#### 存储配置
```yaml
storage:
  data_dir: "data"
  file_organization:
    group_by: "daily"          # 文件分组方式
    filename_format: "{source}_{date}_{timestamp}.json"
  retention:
    retention_days: 365        # 数据保留天数
```

#### 调度配置
```yaml
schedule:
  structured_interval: 2       # 结构化数据采集间隔（小时）
  unstructured_interval: 12    # 非结构化数据采集间隔（小时）
```

## 环境变量支持

- `GITHUB_TOKEN`: GitHub API Token
- `NVD_API_KEY`: NVD API Key

## 使用示例

### 示例1: 日常数据采集
```bash
# 采集NVD最新数据
python run.py --sources nvd --days 1

# 查看采集结果
python run.py --stats
```

### 示例2: 批量数据处理
```bash
# 采集多个数据源
python run.py --sources nvd github osv --days 7

# 导出合并数据
python run.py --export weekly_report.json
```

### 示例3: 定期维护
```bash
# 清理过期文件
python run.py --cleanup

# 检查系统状态
python run.py --info
python run.py --stats
```

### 示例4: 自动化部署
```bash
# 设置环境变量
export NVD_API_KEY="your_nvd_api_key"
export GITHUB_TOKEN="your_github_token"

# 启动定时采集
python run.py --mode schedule
```

## 数据格式说明

### 采集结果文件格式
```json
{
  "metadata": {
    "source": "nvd",
    "data_type": "structured",
    "collected_at": "2025-08-07T23:33:46.190856",
    "count": 266,
    "version": "1.0"
  },
  "data": [
    {
      "id": "CVE-2025-XXXX",
      "cve_id": "CVE-2025-XXXX",
      "title": "...",
      "description": "...",
      "severity": "HIGH",
      "cvss_scores": [...],
      "published_date": "2025-08-07T...",
      "raw_data": {...}
    }
  ]
}
```

### 导出文件格式
```json
{
  "metadata": {
    "export_time": "2025-08-07T23:44:12.370021",
    "source_filter": "nvd",
    "version": "1.0"
  },
  "data": {
    "NVD": [...],
    "GITHUB": [...],
    "OSV": [...]
  }
}
```

## 性能优化

### NVD API优化
- 遵循官方建议的6秒请求间隔
- 使用API Key提高速率限制（50请求/30秒）
- 2小时最小采集间隔，符合官方要求
- 智能分页处理，避免数据丢失

### 存储优化
- 按日期自动组织文件
- 支持数据压缩和清理
- 元数据完整记录，便于追踪
- 灵活的导出格式

### 内存优化
- 移除数据库连接池
- 流式处理大数据集
- 智能文件缓存机制

## 故障排除

### 常见问题

1. **API密钥问题**
   ```bash
   # 检查配置
   python run.py --info
   
   # 设置环境变量
   export NVD_API_KEY="your_key"
   ```

2. **网络连接问题**
   - 检查代理设置
   - 验证网络连通性
   - 调整超时时间

3. **存储空间问题**
   ```bash
   # 清理过期文件
   python run.py --cleanup
   
   # 检查磁盘空间
   python run.py --stats
   ```

4. **权限问题**
   - 确保数据目录有写权限
   - 检查日志文件权限

### 调试模式
```bash
# 设置详细日志
export LOG_LEVEL=DEBUG
python run.py --sources nvd --days 1
```

## 迁移指南

### 从旧版本迁移
1. 备份现有数据库数据
2. 更新配置文件格式
3. 运行迁移测试：`python examples/test_new_config.py`
4. 逐步切换到新版本

### 数据迁移
- 旧数据库数据可通过导出功能转换
- 新数据直接采集到文件系统
- 保持数据格式向后兼容

## 扩展开发

### 添加新数据源
1. 继承`BaseCollector`类
2. 实现采集逻辑
3. 更新配置文件
4. 注册到主程序

### 自定义存储格式
1. 扩展`FileStorage`类
2. 实现自定义序列化
3. 更新配置选项

这个新版本的ThreatSync提供了更简洁、高效、可维护的威胁情报采集解决方案！
