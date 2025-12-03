"""
Storage operations module for libtropic.

Provides data storage (R-Memory) and configuration (R-Config, I-Config) access.
"""

from .memory import DataMemory
from .config import Configuration

__all__ = [
    "DataMemory",
    "Configuration",
]
