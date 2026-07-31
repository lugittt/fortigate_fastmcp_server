"""Package entry point so ``python -m fortigate_mcp`` runs the server.

Equivalent to ``python -m fortigate_mcp.server`` and the ``fortigate-mcp``
console script. Run it from the project root so ``.env`` is picked up.
"""

from .server import main

if __name__ == "__main__":
    main()
