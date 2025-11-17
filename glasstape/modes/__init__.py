"""
GlassTape Modes - Pluggable Architecture
========================================

Mode-specific implementations that share the same core engine.
"""

from .local import LocalEngine

__all__ = ["LocalEngine"]