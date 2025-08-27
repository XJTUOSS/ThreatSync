@echo off
REM ThreatSync 威胁情报采集工具启动脚本
REM Windows 批处理版本

cd /d "%~dp0"

echo ThreatSync 威胁情报采集工具
echo ================================

REM 检查Python是否存在
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请确保Python已安装并添加到PATH
    pause
    exit /b 1
)

REM 检查虚拟环境
if exist "venv\Scripts\activate.bat" (
    echo 激活虚拟环境...
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo 激活虚拟环境...
    call .venv\Scripts\activate.bat
) else (
    echo 警告: 未找到虚拟环境，使用全局Python环境
)

REM 检查依赖是否安装
echo 检查依赖...
python -c "import requests, yaml, pandas" >nul 2>&1
if errorlevel 1 (
    echo 依赖未完全安装，正在安装...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo 错误: 依赖安装失败
        pause
        exit /b 1
    )
)

REM 根据参数运行不同模式
if "%1"=="" goto :interactive
if "%1"=="help" goto :help
if "%1"=="--help" goto :help
if "%1"=="-h" goto :help

REM 直接传递所有参数给Python脚本
python -m ThreatSync.main %*
goto :end

:interactive
echo.
echo 交互式启动模式
echo ================
echo 请选择运行模式:
echo 1. 单次采集 (默认)
echo 2. 定时调度
echo 3. 显示统计信息
echo 4. 显示存储信息
echo 5. 清理过期文件
echo 6. 导出数据
echo 7. 帮助信息
echo.

set /p choice=请输入选项 (1-7): 

if "%choice%"=="1" (
    echo.
    echo 可选数据源: nvd, github, osv, cnvd
    set /p sources=请输入数据源 ^(空格分隔，留空则采集所有^): 
    set /p days=请输入回溯天数 ^(默认7天^): 
    if "%days%"=="" set days=7
    if "%sources%"=="" (
        python -m ThreatSync.main --mode once --days %days%
    ) else (
        python -m ThreatSync.main --mode once --sources %sources% --days %days%
    )
) else if "%choice%"=="2" (
    echo 启动定时调度模式...
    python -m ThreatSync.main --mode schedule
) else if "%choice%"=="3" (
    python -m ThreatSync.main --stats
) else if "%choice%"=="4" (
    python -m ThreatSync.main --info
) else if "%choice%"=="5" (
    echo 清理过期文件...
    python -m ThreatSync.main --cleanup
) else if "%choice%"=="6" (
    set /p export_path=请输入导出路径: 
    set /p export_source=请输入数据源 ^(可选: nvd, github, osv, cnvd^): 
    if "%export_source%"=="" (
        python -m ThreatSync.main --export "%export_path%"
    ) else (
        python -m ThreatSync.main --export "%export_path%" --sources %export_source%
    )
) else if "%choice%"=="7" (
    goto :help
) else (
    echo 无效选项，使用默认单次采集模式
    python -m ThreatSync.main --mode once
)
goto :end

:help
echo.
echo ThreatSync 威胁情报采集工具使用说明
echo ===================================
echo.
echo 使用方法: run.bat [选项]
echo.
echo 选项:
echo   无参数           - 交互式启动
echo   help, -h, --help - 显示帮助信息
echo.
echo 直接传递给main.py的参数:
echo   --config, -c     - 指定配置文件路径
echo   --mode, -m       - 运行模式 (once/schedule)
echo   --sources, -s    - 指定数据源 (nvd github osv cnvd)
echo   --export, -e     - 导出数据到指定路径
echo   --stats          - 显示统计信息
echo   --info           - 显示数据存储信息
echo   --cleanup        - 清理过期文件
echo   --days, -d       - 回溯天数 (默认7天)
echo.
echo 示例:
echo   run.bat                                    # 交互式启动
echo   run.bat --mode once --sources nvd github  # 采集NVD和GitHub数据
echo   run.bat --stats                           # 显示统计信息
echo   run.bat --mode schedule                   # 启动定时调度
echo.

:end
echo.
echo 按任意键退出...
pause >nul
