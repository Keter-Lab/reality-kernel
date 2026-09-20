"""
Reality Kernel Python Client SDK
Deterministic cryptographic intent-verification barrier for autonomous AI agents.
"""

from realitykernel.client import RealityKernel, Verdict
from realitykernel.exceptions import (
    ActionBlocked,
    ActionNeedsReview,
    InsufficientCreditsError,
    RateLimitExceededError,
    RealityKernelError,
    SignatureVerificationError,
)

__version__ = "0.7.0"
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
