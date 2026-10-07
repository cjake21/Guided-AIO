from pymavlink import mavutil
import time
import serial

m = mavutil.mavlink_connection("/dev/ttyACM0", baud=115200)

print("Waiting for heartbeat...")
m.wait_heartbeat(timeout=10)
print("Connected:", m.target_system, m.target_component)
print()

wanted = {
    "ATTITUDE",
    "GPS_RAW_INT",
    "GPS2_RAW",
    "GLOBAL_POSITION_INT",
}

seen = set()
deadline = time.time() + 15

while time.time() < deadline and seen != wanted:
    msg = m.recv_match(type=list(wanted), blocking=True, timeout=1)
    if msg is None:
        continue

    name = msg.get_type()
    if name in seen:
        continue

    seen.add(name)
    print(f"\n--- {name} ---")

    if name == "ATTITUDE":
        print("roll:", msg.roll)
        print("pitch:", msg.pitch)
        print("yaw:", msg.yaw)

    elif name == "GPS_RAW_INT":
        print("fix_type:", msg.fix_type)
        print("satellites:", msg.satellites_visible)
        print("lat:", msg.lat / 1e7)
        print("lon:", msg.lon / 1e7)
        print("hdop:", msg.eph / 100.0)

    elif name == "GPS2_RAW":
        print("fix_type:", msg.fix_type)
        print("satellites:", msg.satellites_visible)
        print("lat:", msg.lat / 1e7)
        print("lon:", msg.lon / 1e7)
        print("hdop:", msg.eph / 100.0)

    elif name == "GLOBAL_POSITION_INT":
        print("lat:", msg.lat / 1e7)
        print("lon:", msg.lon / 1e7)
        print("alt_m:", msg.alt / 1000.0)
        print("relative_alt_m:", msg.relative_alt / 1000.0)
        print("vx:", msg.vx)
        print("vy:", msg.vy)
        print("vz:", msg.vz)

print("\nSeen:", ", ".join(sorted(seen)))
print("Missing:", ", ".join(sorted(wanted - seen)) or "none")

m.close()