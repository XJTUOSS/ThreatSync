#!/usr/bin/env pwsh
# ThreatSync 威胁情报采集工具启动脚本
# PowerShell 版本

param(
    [string]$Config,
    [ValidateSet("once", "schedule")]
    [string]$Mode = "once",
    [ValidateSet("nvd", "github", "osv", "cnvd")]
    [string[]]$Sources,
    [string]$Export,
    [switch]$Stats,
    [switch]$Info,
    [switch]$Cleanup,
    [int]$Days = 7,
    [switch]$Help,
    [switch]$Interactive
)

# 切换到脚本所在目录
Set-Location $PSScriptRoot

function Show-Banner {
    Write-Host "ThreatSync 威胁情报采集工具" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Dependencies {
    Write-Host "检查依赖..." -ForegroundColor Yellow
    
    # 检查Python
    try {
        $pythonVersion = python --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Python未找到"
        }
        Write-Host "✓ $pythonVersion" -ForegroundColor Green
    } catch {
        Write-Host "✗ 错误: 未找到Python，请确保Python已安装并添加到PATH" -ForegroundColor Red
        exit 1
    }
    
    # 检查虚拟环境
    if (Test-Path "venv\Scripts\Activate.ps1") {
        Write-Host "✓ 激活虚拟环境 (venv)..." -ForegroundColor Green
        & "venv\Scripts\Activate.ps1"
    } elseif (Test-Path ".venv\Scripts\Activate.ps1") {
        Write-Host "✓ 激活虚拟环境 (.venv)..." -ForegroundColor Green
        & ".venv\Scripts\Activate.ps1"
    } else {
        Write-Host "⚠ 警告: 未找到虚拟环境，使用全局Python环境" -ForegroundColor Yellow
    }
    
    # 检查关键依赖
    try {
        python -c "import requests, yaml, pandas" 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "依赖缺失"
        }
        Write-Host "✓ 依赖检查通过" -ForegroundColor Green
    } catch {
        Write-Host "⚠ 依赖未完全安装，正在安装..." -ForegroundColor Yellow
        pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            Write-Host "✗ 错误: 依赖安装失败" -ForegroundColor Red
            exit 1
        }
        Write-Host "✓ 依赖安装完成" -ForegroundColor Green
    }
    Write-Host ""
}

function Show-Help {
    Write-Host @"
ThreatSync 威胁情报采集工具使用说明
===================================

使用方法: .\run.ps1 [选项]

基本选项:
  -Help              显示此帮助信息
  -Interactive       交互式启动模式

功能选项:
  -Config <路径>     指定配置文件路径
  -Mode <模式>       运行模式 (once/schedule，默认: once)
  -Sources <源>      指定数据源 (nvd, github, osv, cnvd)
  -Export <路径>     导出数据到指定路径
  -Stats             显示统计信息
  -Info              显示数据存储信息
  -Cleanup           清理过期文件
  -Days <天数>       回溯天数 (默认: 7)

示例:
  .\run.ps1                                      # 默认单次采集
  .\run.ps1 -Interactive                         # 交互式启动
  .\run.ps1 -Mode once -Sources nvd,github       # 采集指定数据源
  .\run.ps1 -Stats                               # 显示统计信息
  .\run.ps1 -Mode schedule                       # 启动定时调度
  .\run.ps1 -Export "output.json" -Sources nvd   # 导出NVD数据
  .\run.ps1 -Cleanup                             # 清理过期文件

"@ -ForegroundColor White
}

function Start-Interactive {
    Write-Host "交互式启动模式" -ForegroundColor Cyan
    Write-Host "================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "请选择运行模式:"
    Write-Host "1. 单次采集 (默认)"
    Write-Host "2. 定时调度"
    Write-Host "3. 显示统计信息"
    Write-Host "4. 显示存储信息"
    Write-Host "5. 清理过期文件"
    Write-Host "6. 导出数据"
    Write-Host "7. 帮助信息"
    Write-Host ""
    
    $choice = Read-Host "请输入选项 (1-7)"
    Write-Host ""
    
    switch ($choice) {
        "1" {
            Write-Host "可选数据源: nvd, github, osv, cnvd" -ForegroundColor Yellow
            $sourcesInput = Read-Host "请输入数据源 (逗号分隔，留空则采集所有)"
            $daysInput = Read-Host "请输入回溯天数 (默认7天)"
            
            $args = @("--mode", "once")
            if ($daysInput) { $args += @("--days", $daysInput) } else { $args += @("--days", "7") }
            if ($sourcesInput) { $args += @("--sources") + ($sourcesInput -split ",").Trim() }
            
            python -m ThreatSync.main @args
        }
        "2" {
            Write-Host "启动定时调度模式..." -ForegroundColor Green
            python -m ThreatSync.main --mode schedule
        }
        "3" {
            python -m ThreatSync.main --stats
        }
        "4" {
            python -m ThreatSync.main --info
        }
        "5" {
            Write-Host "清理过期文件..." -ForegroundColor Yellow
            python -m ThreatSync.main --cleanup
        }
        "6" {
            $exportPath = Read-Host "请输入导出路径"
            $exportSource = Read-Host "请输入数据源 (可选: nvd, github, osv, cnvd)"
            
            $args = @("--export", $exportPath)
            if ($exportSource) { $args += @("--sources", $exportSource) }
            
            python -m ThreatSync.main @args
        }
        "7" {
            Show-Help
        }
        default {
            Write-Host "无效选项，使用默认单次采集模式" -ForegroundColor Yellow
            python -m ThreatSync.main --mode once
        }
    }
}

function Start-Main {
    # 构建命令行参数
    $args = @()
    
    if ($Config) { $args += @("--config", $Config) }
    if ($Mode) { $args += @("--mode", $Mode) }
    if ($Sources) { $args += @("--sources") + $Sources }
    if ($Export) { $args += @("--export", $Export) }
    if ($Stats) { $args += @("--stats") }
    if ($Info) { $args += @("--info") }
    if ($Cleanup) { $args += @("--cleanup") }
    if ($Days -ne 7) { $args += @("--days", $Days) }
    
    # 如果没有任何功能参数，默认执行单次采集
    if (-not ($Stats -or $Info -or $Cleanup -or $Export)) {
        if (-not $Mode) { $args += @("--mode", "once") }
    }
    
    python -m ThreatSync.main @args
}

# 主逻辑
try {
    Show-Banner
    
    if ($Help) {
        Show-Help
        return
    }
    
    Test-Dependencies
    
    if ($Interactive -or ($args.Count -eq 0 -and -not ($Stats -or $Info -or $Cleanup -or $Export))) {
        Start-Interactive
    } else {
        Start-Main
    }
    
} catch {
    Write-Host "错误: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Write-Host ""
    Write-Host "程序执行完成，按任意键退出..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
