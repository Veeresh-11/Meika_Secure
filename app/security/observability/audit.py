from datetime import datetime, timezone

def emit_audit(event_type: str, data: dict):
    record = {
        "event": event_type,
        "data": data,
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }
    print(record)  # replace with SIEM later
