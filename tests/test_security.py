#!/usr/bin/env python3
"""
测试配置安全性和敏感信息处理
"""
import sys
import os
from pathlib import Path

# 添加项目根目录到sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.utils.config import ConfigManager
from src.utils import logger

def test_config_security():
    """测试配置安全性"""
    logger.info("=== 配置安全性测试 ===")
    
    try:
        # 初始化配置管理器
        config_manager = ConfigManager()
        
        # 检查配置文件路径
        logger.info(f"主配置文件: {config_manager.config_path}")
        logger.info(f"本地配置文件: {config_manager.local_config_path}")
        
        # 检查文件是否存在
        main_config_exists = config_manager.config_path.exists()
        local_config_exists = config_manager.local_config_path.exists()
        
        logger.info(f"主配置文件存在: {'✅' if main_config_exists else '❌'}")
        logger.info(f"本地配置文件存在: {'✅' if local_config_exists else '⚠️  未设置'}")
        
        # 检查API配置
        github_config = config_manager.get_api_config('github')
        nvd_config = config_manager.get_api_config('nvd')
        
        github_token = github_config.get('token', '')
        nvd_api_key = nvd_config.get('api_key', '')
        
        logger.info("\\n=== API密钥状态 ===")
        logger.info(f"GitHub Token: {'✅ 已设置' if github_token else '⚠️  未设置'}")
        logger.info(f"NVD API Key: {'✅ 已设置' if nvd_api_key else '⚠️  未设置'}")
        
        # 检查环境变量
        env_github_token = os.getenv('GITHUB_TOKEN')
        env_nvd_key = os.getenv('NVD_API_KEY')
        
        logger.info("\\n=== 环境变量状态 ===")
        logger.info(f"GITHUB_TOKEN: {'✅ 已设置' if env_github_token else '⚠️  未设置'}")
        logger.info(f"NVD_API_KEY: {'✅ 已设置' if env_nvd_key else '⚠️  未设置'}")
        
        # 安全检查：确保敏感信息不会被意外记录
        logger.info("\\n=== 安全性检查 ===")
        
        # 检查token长度而不显示内容
        if github_token:
            logger.info(f"GitHub Token长度: {len(github_token)} 字符")
            if len(github_token) < 10:
                logger.warning("GitHub Token似乎过短，请检查是否正确设置")
        
        if nvd_api_key:
            logger.info(f"NVD API Key长度: {len(nvd_api_key)} 字符")
            if len(nvd_api_key) < 10:
                logger.warning("NVD API Key似乎过短，请检查是否正确设置")
        
        return True
        
    except Exception as e:
        logger.error(f"配置测试失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_gitignore_effectiveness():
    """测试.gitignore的有效性"""
    logger.info("\\n=== .gitignore有效性测试 ===")
    
    gitignore_path = Path("../.gitignore")
    if not gitignore_path.exists():
        logger.error("❌ .gitignore文件不存在")
        return False
    
    with open(gitignore_path, 'r', encoding='utf-8') as f:
        gitignore_content = f.read()
    
    # 检查关键排除项
    required_excludes = [
        'config/config.local.yaml',
        'data/',
        'logs/',
        '*.json',
        '*.db',
        '.env'
    ]
    
    missing_excludes = []
    for exclude in required_excludes:
        if exclude not in gitignore_content:
            missing_excludes.append(exclude)
    
    if missing_excludes:
        logger.warning(f"⚠️  .gitignore缺少以下排除项: {missing_excludes}")
    else:
        logger.info("✅ .gitignore包含所有必要的排除项")
    
    return len(missing_excludes) == 0

def test_data_directory_protection():
    """测试数据目录保护"""
    logger.info("\\n=== 数据目录保护测试 ===")
    
    data_dir = Path("../data")
    if not data_dir.exists():
        logger.warning("⚠️  data目录不存在")
        return True
    
    # 检查.gitkeep文件
    gitkeep_file = data_dir / ".gitkeep"
    if gitkeep_file.exists():
        logger.info("✅ data/.gitkeep文件存在")
    else:
        logger.warning("⚠️  data/.gitkeep文件不存在")
    
    # 检查是否有敏感文件
    sensitive_files = list(data_dir.rglob("*.json")) + list(data_dir.rglob("*.db"))
    if sensitive_files:
        logger.info(f"📊 发现 {len(sensitive_files)} 个数据文件（这些文件会被.gitignore排除）")
        # 只显示前几个文件名，不显示内容
        for i, file in enumerate(sensitive_files[:3]):
            relative_path = file.relative_to(data_dir)
            logger.info(f"  - {relative_path}")
        if len(sensitive_files) > 3:
            logger.info(f"  - ... 还有 {len(sensitive_files) - 3} 个文件")
    else:
        logger.info("ℹ️  未发现数据文件")
    
    return True

def create_local_config_template():
    """创建本地配置模板"""
    logger.info("\\n=== 创建本地配置模板 ===")
    
    local_config_path = Path("../config/config.local.yaml")
    if local_config_path.exists():
        logger.info("ℹ️  config.local.yaml已存在，跳过创建")
        return True
    
    try:
        # 从example复制
        example_path = Path("../config/config.example.yaml")
        if example_path.exists():
            import shutil
            shutil.copy(example_path, local_config_path)
            logger.info(f"✅ 已创建本地配置模板: {local_config_path}")
            logger.info("🔧 请编辑此文件并填入真实的API密钥")
            return True
        else:
            logger.warning("⚠️  config.example.yaml不存在，无法创建模板")
            return False
            
    except Exception as e:
        logger.error(f"创建本地配置模板失败: {str(e)}")
        return False

if __name__ == "__main__":
    logger.info("=== ThreatSync 安全配置测试 ===")
    
    # 运行所有测试
    config_ok = test_config_security()
    gitignore_ok = test_gitignore_effectiveness()
    data_ok = test_data_directory_protection()
    
    # 尝试创建本地配置模板
    create_local_config_template()
    
    # 总结
    logger.info("\\n=== 安全配置总结 ===")
    if config_ok and gitignore_ok and data_ok:
        logger.info("✅ 安全配置检查通过")
        logger.info("\\n📝 后续步骤:")
        logger.info("1. 编辑 config/config.local.yaml 并设置真实的API密钥")
        logger.info("2. 或者设置环境变量 GITHUB_TOKEN 和 NVD_API_KEY")
        logger.info("3. 确保不要将 config.local.yaml 提交到git")
    else:
        logger.error("❌ 安全配置存在问题，请检查上述输出")
        sys.exit(1)
