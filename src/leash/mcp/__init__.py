"""Local MCP support: a stdio proxy that checks every MCP tool call against
your Leash policies, pins tool descriptions, and wraps MCP client configs.

Nothing is hosted: the MCP client (Claude Desktop, VS Code, Windsurf, ...)
starts ``leash mcp run -- <server command>`` instead of the server itself,
and Leash starts the real server as its child.
"""
