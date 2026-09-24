"""Read-only inspection of the MCP servers a user has configured.

This is the one part of GuardBench that looks at servers outside the lab, and it is deliberately
narrow: it starts (stdio) or contacts (HTTP) only the servers named in the user's own MCP client
config, requests ``tools/list``, and disconnects. It never calls a tool, reads a resource, or
fetches a prompt. Everything it learns goes through the same deterministic analyzers the
benchmark uses (:mod:`guardbench.analysis`), and fingerprints can be pinned to catch rug pulls.
"""
