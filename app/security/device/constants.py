"""
Device lifecycle and trust constants.

These constants are shared by:

    • DeviceService
    • Device Trust Engine
    • Session Guardian
    • MIS
"""

#
# Device Lifecycle
#

DEVICE_STATE_ACTIVE = "ACTIVE"

DEVICE_STATE_SUSPENDED = "SUSPENDED"

DEVICE_STATE_QUARANTINED = "QUARANTINED"

DEVICE_STATE_REVOKED = "REVOKED"


#
# Trust Levels
#

TRUST_UNKNOWN = "UNKNOWN"

TRUST_LOW = "LOW"

TRUST_MEDIUM = "MEDIUM"

TRUST_HIGH = "HIGH"

TRUST_CRITICAL = "CRITICAL"