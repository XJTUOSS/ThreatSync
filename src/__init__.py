"""
ThreatSync - 威胁情报采集工具
"""
from .main import ThreatSyncEngine, main
from .database import DatabaseManager
from .models.vulnerability import VulnerabilityData, CollectionResult
from .utils import ConfigManager, logger

__version__ = "1.0.0"
__author__ = "ThreatSync Team"

__all__ = [
    'ThreatSyncEngine',
    'main',
    'DatabaseManager',
    'VulnerabilityData',
    'CollectionResult',
    'ConfigManager',
    'logger'
]
