"""Policy YAML loading, validation, hot reload, and diff logging.

SECURITY: Uses yaml.safe_load() exclusively. Never use yaml.load().
Uses aiofiles for non-blocking file I/O.
"""
