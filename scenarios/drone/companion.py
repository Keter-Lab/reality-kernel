"""Stand-in for drone mission software on the companion computer.
Connects to the simulated flight controller over MAVLink and reads telemetry."""
import sys
import time
from pymavlink import mavutil

conn = mavutil.mavlink_connection("tcp:127.0.0.1:5760")
if conn.wait_heartbeat(timeout=30) is None:
    print("no heartbeat from flight controller")
    sys.exit(1)
print(f"heartbeat from system {conn.target_system}")

deadline = time.time() + 20
count = 0
while time.time() < deadline:
    msg = conn.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=5)
    if msg:
        count += 1
print(f"received {count} position messages in 20s ({count/20:.1f} msg/s)")
sys.exit(0 if count > 0 else 1)
