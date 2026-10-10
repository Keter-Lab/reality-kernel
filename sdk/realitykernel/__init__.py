"""
Reality Kernel Python Client SDK
Deterministic cryptographic intent-verification barrier for autonomous AI agents.
"""

from .client import RealityKernel, Verdict
from .exceptions import (
    ActionBlocked,
    ActionNeedsReview,
    InsufficientCreditsError,
    RateLimitExceededError,
    RealityKernelError,
    SignatureVerificationError,
)

__version__ = "0.7.1"
__all__ = [
    "RealityKernel",
    "Verdict",
    "RealityKernelError",
    "ActionBlocked",
    "ActionNeedsReview",
    "SignatureVerificationError",
    "InsufficientCreditsError",
    "RateLimitExceededError",
]
