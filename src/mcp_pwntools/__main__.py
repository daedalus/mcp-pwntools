"""Main entry point for mcp-pwntools."""

from mcp_pwntools import mcp


def main() -> int:
    """Run the MCP server."""
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
