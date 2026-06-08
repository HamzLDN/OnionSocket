from src.server.exit_server import ExitServer


class ExitNode(ExitServer):
    """Core onion exit — registers with the directory and terminates circuits."""

    def __init__(self, *args, register=True, **kwargs):
        super().__init__(
            *args,
            register=register,
            is_exit_node=True,
            **kwargs,
        )
