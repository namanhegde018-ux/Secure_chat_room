from os_ken.base.app_manager import AppManager

if __name__ == "__main__":

    print("Starting Secure Messaging SDN Controller...")

    AppManager.run_apps([
        "sdn_controller"
    ])
