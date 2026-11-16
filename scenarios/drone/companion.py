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

# ArduPilot SITL does not stream GLOBAL_POSITION_INT on its own; a client has
# to ask for it. Try the modern per-message request first, and the older
# blanket data-stream request too in case the SITL build in use only honours
# that one -- either is enough on its own, sending both is just belt and
# braces.
conn.mav.command_long_send(
    conn.target_system, conn.target_component,
    mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, 0,
    mavutil.mavlink.MAVLINK_MSG_ID_GLOBAL_POSITION_INT, 200000, 0, 0, 0, 0, 0,
)
conn.mav.request_data_stream_send(
    conn.target_system, conn.target_component,
    mavutil.mavlink.MAV_DATA_STREAM_ALL, 4, 1,
)

deadline = time.time() + 20
count = 0
while time.time() < deadline:
    msg = conn.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=5)
    if msg:
        count += 1
print(f"received {count} position messages in 20s ({count/20:.1f} msg/s)")
# Strict on purpose (docs/agents.md's own "never weaken a check" rule, applied
# here too): a heartbeat alone does not prove telemetry is actually flowing,
# only that the TCP link and MAVLink handshake work.
sys.exit(0 if count > 0 else 1)
