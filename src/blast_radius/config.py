import os

from dotenv import load_dotenv

load_dotenv()

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_USERNAME = os.getenv("FALKORDB_USERNAME") or None
FALKORDB_PASSWORD = os.getenv("FALKORDB_PASSWORD") or None
GRAPH_NAME = os.getenv("GRAPH_NAME", "blast_radius")

CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5")
