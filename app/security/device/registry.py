class DeviceRegistry:
    """
    Evaluates whether a device is known and registered.
    No allowlists, no trust — evaluation only.
    """

    def __init__(self):
        self._registered_devices = {}

    def register(self, device_id: str, principal_id: str):
        self._registered_devices[device_id] = principal_id

    def is_registered(self, device_id: str, principal_id: str) -> bool:
        return self._registered_devices.get(device_id) == principal_id
