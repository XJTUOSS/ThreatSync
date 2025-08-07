# ThreatSync 数据存储说明

## 概述

ThreatSync 现在使用文件系统存储威胁情报数据，分为结构化和非结构化两种类型的数据存储。

## 目录结构

```
data/
├── structured/          # 结构化威胁数据
│   ├── nvd/            # NVD (国家漏洞数据库)
│   ├── github/         # GitHub 安全公告
│   └── osv/            # OSV (开源漏洞数据库)
├── unstructured/       # 非结构化威胁情报
│   └── cnvd/          # CNVD (国家信息安全漏洞库)
└── collection_results/  # 采集结果记录
```

## 数据组织方式

### 结构化数据
- 按数据源分文件夹存储
- 每个数据源按日期创建子文件夹 (YYYY-MM-DD)
- 每个漏洞保存为单独的 JSON 文件，文件名为漏洞ID

示例路径：
```
data/structured/nvd/2025-08-07/CVE-2025-0001.json
data/structured/github/2025-08-07/GHSA-xxxx-xxxx-xxxx.json
```

### 非结构化数据
- 按数据源分文件夹存储
- 每个数据源按日期创建子文件夹 (YYYY-MM-DD)
- 每个情报保存为单独的 JSON 文件

示例路径：
```
data/unstructured/cnvd/2025-08-07/CNVD-2025-001.json
```

### 采集结果
- 每次采集任务的结果保存为单独文件
- 文件名格式：{数据源}_{时间戳}.json

示例路径：
```
data/collection_results/NVD_20250807_205646.json
```

## 使用方法

### 1. 基本运行
```bash
# 显示统计信息
python run.py --stats

# 采集所有数据源
python run.py -m once

# 采集指定数据源
python run.py -s nvd github
```

### 2. 数据导出
```bash
# 导出所有数据
python run.py --export output/all_data.json

# 导出指定数据源
python run.py --export output/nvd_data.json -s nvd
```

### 3. 定时采集
```bash
# 启动定时采集服务
python run.py -m schedule
```

## 数据格式

每个漏洞JSON文件包含以下字段：
- `id`: 漏洞唯一标识
- `cve_id`: CVE编号（如果有）
- `title`: 漏洞标题
- `description`: 漏洞描述
- `severity`: 严重性等级
- `source`: 数据源
- `published_date`: 发布日期
- `modified_date`: 修改日期
- `cvss_scores`: CVSS评分信息
- `affected_products`: 受影响产品
- `references`: 参考链接
- `saved_time`: 保存时间

## 数据源类型分类

### 结构化数据源
- **NVD**: 提供标准化的 CVE 漏洞信息
- **GitHub**: GitHub 安全公告和漏洞修复信息
- **OSV**: 开源软件漏洞数据库

### 非结构化数据源
- **CNVD**: 国家信息安全漏洞库，包含更多本土化威胁情报

## 优势

1. **文件系统存储**: 便于备份、迁移和分析
2. **分类存储**: 结构化和非结构化数据分开管理
3. **按日期组织**: 便于历史数据查询和管理
4. **JSON格式**: 便于数据交换和处理
5. **独立文件**: 每个漏洞独立存储，便于单独处理
