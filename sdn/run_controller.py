"""Start the OpenFlow policy. Run from sdn/: .venv-sdn/bin/python run_controller.py"""

import logging

from os_ken.base.app_manager import AppManager


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    AppManager.run_apps(["os_ken.controller.ofp_handler", "sdn_controller"])


if __name__ == "__main__":
    main()