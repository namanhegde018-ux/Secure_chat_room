"""Network facts for the lab. Contains no client identities."""

OPENFLOW_HOST = "127.0.0.1"
OPENFLOW_PORT = 6653
BRIDGE = "s1"

SERVER_NODE = "server"
SERVER_IP = "10.0.0.1"
SIGNAL_PORT = 9000

DEFAULT_CLIENTS = 3
MAX_CLIENTS = 20
POLICY_COOKIE = 0x534D000000000001


def _check(index: int) -> None:
    if not 1 <= index <= MAX_CLIENTS:
        raise ValueError(f"client index must be 1..{MAX_CLIENTS}, got {index}")


def client_node(index: int) -> str:
    _check(index)
    return f"h{index}"


def client_ip(index: int) -> str:
    _check(index)
    return f"10.0.0.{10 + index}"