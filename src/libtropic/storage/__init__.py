"""
Storage operations module for libtropic.

Provides data storage (R-Memory) and configuration (R-Config, I-Config) access.
"""

from .config import Configuration
from .memory import DataMemory

__all__ = [
    "DataMemory",
    "Configuration",
]
