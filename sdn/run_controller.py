"""Launch OS-Ken's OpenFlow handler and the project controller app."""

import logging
from os_ken.base.app_manager import AppManager


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    print("Starting Secure Messaging SDN Controller...", flush=True)
    AppManager.run_apps([
        "os_ken.controller.ofp_handler",
        "sdn_controller",
    ])
