"""Local-first inventory foundation for Cyber Scout LAN Observer."""

from .config import CyberScoutConfig, ConfigManager
from .database import InventoryStore
from .discovery import PassiveDiscoveryManager
from .models import Observation

__all__ = ["ConfigManager", "CyberScoutConfig", "InventoryStore", "Observation", "PassiveDiscoveryManager"]
__version__ = "1.5.0"
