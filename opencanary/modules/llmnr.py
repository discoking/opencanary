"""LLMNR canary.

The implementation lives in nameres.py so NBT-NS and mDNS share the same
lookup, allowlist, and alert path. This module remains the import path used
by opencanary.tac.
"""

from opencanary.modules.nameres import CanaryLLMNR

__all__ = ["CanaryLLMNR"]
