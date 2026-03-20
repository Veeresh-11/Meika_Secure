from datetime import datetime

def emit_audit(event_type: str, data: dict):
    record = {
        "event": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
    }
    print(record)  # replace with SIEM later
