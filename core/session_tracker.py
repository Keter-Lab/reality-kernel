"""
Session Accumulator
===================
Tracks multi-step agent actions over a given session to detect
"slow drip" exfiltration chains or reconnaissance loops.
"""
import time
import re
import json

def update_and_check_session(
    session_id: str,
    command: str,
    sb_client,
    sb_url: str,
    sb_headers: dict
) -> tuple[bool, list[str]]:
    """
    Updates the remote session state and returns whether the new state
    violates a chained rule.
    
    Returns: (is_escalated, evidence_list)
    """
    if not session_id or not sb_url:
        return False, []
        
    url = f"{sb_url}/session_states?session_id=eq.{session_id}&select=*"
    
    state = {
        "session_id": session_id,
        "cumulative_reads": 0,
        "cumulative_sensitive": 0,
        "network_egress_count": 0,
        "last_activity": time.time(),
        "recent_commands": []
    }
    
    try:
        r = sb_client.get(url, headers=sb_headers)
        if r.status_code == 200 and r.json():
            state.update(r.json()[0])
            # Apply time-window decay based on last activity
            current_time = time.time()
            hours_passed = (current_time - state.get("last_activity", current_time)) / 3600.0
            
            if hours_passed >= 6:
                # Older than 6 hours: 0% weight (reset)
                state["cumulative_reads"] = 0
                state["cumulative_sensitive"] = 0
                state["network_egress_count"] = 0
            elif hours_passed >= 1:
                # Older than 1 hour: 50% weight
                state["cumulative_reads"] = max(0, int(state["cumulative_reads"] * 0.5))
                state["cumulative_sensitive"] = max(0, int(state["cumulative_sensitive"] * 0.5))
                state["network_egress_count"] = max(0, int(state["network_egress_count"] * 0.5))
    except Exception:
        # Silently fail if Supabase session_states table isn't ready
        return False, []
        
    # Analyze current command
    cmd_lower = command.lower()
    
    is_read = any(re.search(fr'\b{w}\b', cmd_lower) for w in ['cat', 'ls', 'head', 'tail', 'grep', 'find'])
    is_sensitive = any(w in cmd_lower for w in ['.env', '/etc/passwd', '/etc/shadow', 'id_rsa', 'secret', 'credential', 'token', 'base64'])
    is_network = any(re.search(fr'\b{w}\b', cmd_lower) for w in ['curl', 'wget', 'nc', 'scp', 'rsync', 'ssh', 'telnet', 'ftp', 'sftp'])
    
    if is_read:
        state["cumulative_reads"] += 1
    if is_sensitive:
        state["cumulative_sensitive"] += 1
    if is_network:
        # Check if network is internal/whitelisted vs external
        # Internal IPs: 10.*, 172.16-31.*, 192.168.*, 127.*, localhost
        internal_pat = r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|localhost)'
        if not re.search(internal_pat, cmd_lower):
            state["network_egress_count"] += 1
            
    state["recent_commands"].append(command[:100])
    state["recent_commands"] = state["recent_commands"][-10:] # Keep last 10
    state["last_activity"] = time.time()
    
    # Upsert back to Supabase
    # ⚠️  RACE CONDITION NOTE (VULN-004): This is a non-atomic read-modify-write.
    # Under concurrent requests for the same session_id, counters may be under-counted
    # because two workers can read the same state, both increment, and one overwrites the other.
    # FIX: Replace with a Supabase RPC using SELECT ... FOR UPDATE to atomically lock the row.
    try:
        upsert_url = f"{sb_url}/session_states"
        headers = {**sb_headers, "Prefer": "resolution=merge-duplicates"}
        r_upsert = sb_client.post(upsert_url, headers=headers, json=state)
        if r_upsert.status_code not in (200, 201, 204):
            import logging as _log
            _log.getLogger("rk_session").warning(
                "session upsert returned non-200: %s — state may be stale", r_upsert.status_code
            )
    except Exception as _e:
        import logging as _log
        _log.getLogger("rk_session").warning("session upsert failed (non-fatal): %s", _e)
        
    # Evaluate escalation rules
    evidence = []
    
    if state["cumulative_sensitive"] >= 3:
        evidence.append(f"Session Rule: High volume of sensitive reads ({state['cumulative_sensitive']}) within session")
        
    if state["cumulative_reads"] >= 10:
        evidence.append(f"Session Rule: Reconnaissance pattern detected ({state['cumulative_reads']} reads)")
        
    if is_network and state["network_egress_count"] > 0 and state["cumulative_sensitive"] > 0:
        evidence.append("Session Rule: Network egress attempted following sensitive reads (Slow-Drip Exfiltration Chain)")
        
    return bool(evidence), evidence
