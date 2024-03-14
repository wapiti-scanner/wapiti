from wapitiCore.attack.attack import Attack

MSG_TECHNO_VERSIONED = "{0} {1} detected"


class NetworkDeviceCommon(Attack):
    """Base class for detecting version."""
    name = "network_device"
