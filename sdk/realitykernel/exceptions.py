"""
Reality Kernel SDK Exceptions
"""

class RealityKernelError(Exception):
    """Base exception for all Reality Kernel SDK errors."""
    pass


class ActionBlocked(RealityKernelError):
    """Raised when an action is deterministically blocked due to intent divergence or policy breach."""
    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(
            f"Action BLOCKED (confidence: {verdict.confidence * 100:.1f}%, proof: {verdict.proof_hash[:12]}...): "
            f"{', '.join(verdict.evidence) if verdict.evidence else 'Intent divergence detected.'}"
        )


class ActionNeedsReview(RealityKernelError):
    """Raised when an action requires human operator review before execution."""
    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(
            f"Action flagged WARN for human review (action_id: {verdict.action_id}, "
            f"confidence: {verdict.confidence * 100:.1f}%)."
        )


class SignatureVerificationError(RealityKernelError):
    """Raised when cryptographic Ed25519 signature verification fails."""
    pass


class InsufficientCreditsError(RealityKernelError):
    """Raised when the API key has exhausted available execution credits."""
    pass


class RateLimitExceededError(RealityKernelError):
    """Raised when the per-key rate limit is exceeded."""
    pass
