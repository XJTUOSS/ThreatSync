#!/bin/bash
# ThreatSync 威胁情报采集工具启动脚本
# Linux/macOS 版本

set -e

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 显示横幅
show_banner() {
    echo -e "${CYAN}ThreatSync 威胁情报采集工具${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
}

# 检查依赖
check_dependencies() {
    echo -e "${YELLOW}检查依赖...${NC}"
    
    # 检查Python
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        echo -e "${RED}✗ 错误: 未找到Python，请确保Python已安装${NC}"
        exit 1
    fi
    
    # 确定Python命令
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    else
        PYTHON_CMD="python"
    fi
    
    echo -e "${GREEN}✓ 找到Python: $($PYTHON_CMD --version)${NC}"
    
    # 检查虚拟环境
    if [ -f "venv/bin/activate" ]; then
        echo -e "${GREEN}✓ 激活虚拟环境 (venv)...${NC}"
        source venv/bin/activate
    elif [ -f ".venv/bin/activate" ]; then
        echo -e "${GREEN}✓ 激活虚拟环境 (.venv)...${NC}"
        source .venv/bin/activate
    else
        echo -e "${YELLOW}⚠ 警告: 未找到虚拟环境，使用全局Python环境${NC}"
    fi
    
    # 检查关键依赖
    if ! $PYTHON_CMD -c "import requests, yaml, pandas" 2>/dev/null; then
        echo -e "${YELLOW}⚠ 依赖未完全安装，正在安装...${NC}"
        pip install -r requirements.txt
        if [ $? -ne 0 ]; then
            echo -e "${RED}✗ 错误: 依赖安装失败${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ 依赖安装完成${NC}"
    else
        echo -e "${GREEN}✓ 依赖检查通过${NC}"
    fi
    echo ""
}

# 显示帮助
show_help() {
    cat << EOF
ThreatSync 威胁情报采集工具使用说明
===================================

使用方法: ./run.sh [选项]

基本选项:
  -h, --help         显示此帮助信息
  -i, --interactive  交互式启动模式

功能选项:
  -c, --config       指定配置文件路径
  -m, --mode         运行模式 (once/schedule，默认: once)
  -s, --sources      指定数据源 (nvd github osv cnvd)
  -e, --export       导出数据到指定路径
  --stats            显示统计信息
  --info             显示数据存储信息
  --cleanup          清理过期文件
  -d, --days         回溯天数 (默认: 7)

示例:
  ./run.sh                                    # 默认单次采集
  ./run.sh -i                                 # 交互式启动
  ./run.sh -m once -s nvd github              # 采集指定数据源
  ./run.sh --stats                            # 显示统计信息
  ./run.sh -m schedule                        # 启动定时调度
  ./run.sh -e output.json -s nvd              # 导出NVD数据
  ./run.sh --cleanup                          # 清理过期文件

EOF
}

# 交互式启动
start_interactive() {
    echo -e "${CYAN}交互式启动模式${NC}"
    echo -e "${CYAN}================${NC}"
    echo ""
    echo "请选择运行模式:"
    echo "1. 单次采集 (默认)"
    echo "2. 定时调度"
    echo "3. 显示统计信息"
    echo "4. 显示存储信息"
    echo "5. 清理过期文件"
    echo "6. 导出数据"
    echo "7. 帮助信息"
    echo ""
    
    read -p "请输入选项 (1-7): " choice
    echo ""
    
    case $choice in
        1)
            echo -e "${YELLOW}可选数据源: nvd, github, osv, cnvd${NC}"
            read -p "请输入数据源 (空格分隔，留空则采集所有): " sources
            read -p "请输入回溯天数 (默认7天): " days
            
            args=("--mode" "once")
            if [ ! -z "$days" ]; then
                args+=("--days" "$days")
            else
                args+=("--days" "7")
            fi
            if [ ! -z "$sources" ]; then
                args+=("--sources")
                for source in $sources; do
                    args+=("$source")
                done
            fi
            
            $PYTHON_CMD -m ThreatSync.main "${args[@]}"
            ;;
        2)
            echo -e "${GREEN}启动定时调度模式...${NC}"
            $PYTHON_CMD -m ThreatSync.main --mode schedule
            ;;
        3)
            $PYTHON_CMD -m ThreatSync.main --stats
            ;;
        4)
            $PYTHON_CMD -m ThreatSync.main --info
            ;;
        5)
            echo -e "${YELLOW}清理过期文件...${NC}"
            $PYTHON_CMD -m ThreatSync.main --cleanup
            ;;
        6)
            read -p "请输入导出路径: " export_path
            read -p "请输入数据源 (可选: nvd github osv cnvd): " export_source
            
            args=("--export" "$export_path")
            if [ ! -z "$export_source" ]; then
                args+=("--sources" "$export_source")
            fi
            
            $PYTHON_CMD -m ThreatSync.main "${args[@]}"
            ;;
        7)
            show_help
            ;;
        *)
            echo -e "${YELLOW}无效选项，使用默认单次采集模式${NC}"
            $PYTHON_CMD -m ThreatSync.main --mode once
            ;;
    esac
}

# 解析命令行参数
parse_args() {
    local args=()
    local interactive=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--interactive)
                interactive=true
                shift
                ;;
            -c|--config)
                args+=("--config" "$2")
                shift 2
                ;;
            -m|--mode)
                args+=("--mode" "$2")
                shift 2
                ;;
            -s|--sources)
                args+=("--sources")
                shift
                while [[ $# -gt 0 && ! $1 =~ ^- ]]; do
                    args+=("$1")
                    shift
                done
                ;;
            -e|--export)
                args+=("--export" "$2")
                shift 2
                ;;
            --stats)
                args+=("--stats")
                shift
                ;;
            --info)
                args+=("--info")
                shift
                ;;
            --cleanup)
                args+=("--cleanup")
                shift
                ;;
            -d|--days)
                args+=("--days" "$2")
                shift 2
                ;;
            *)
                echo -e "${RED}未知选项: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
    
    if [ "$interactive" = true ] || [ ${#args[@]} -eq 0 ]; then
        start_interactive
    else
        # 如果没有指定模式，默认为once
        if [[ ! " ${args[@]} " =~ " --mode " ]] && [[ ! " ${args[@]} " =~ " --stats " ]] && [[ ! " ${args[@]} " =~ " --info " ]] && [[ ! " ${args[@]} " =~ " --cleanup " ]] && [[ ! " ${args[@]} " =~ " --export " ]]; then
            args=("--mode" "once" "${args[@]}")
        fi
        $PYTHON_CMD -m ThreatSync.main "${args[@]}"
    fi
}

# 主逻辑
main() {
    show_banner
    check_dependencies
    
    if [ $# -eq 0 ]; then
        start_interactive
    else
        parse_args "$@"
    fi
}

# 错误处理
trap 'echo -e "\n${YELLOW}程序被中断${NC}"; exit 130' INT

# 执行主函数
main "$@"

echo ""
echo -e "${NC}程序执行完成${NC}"
