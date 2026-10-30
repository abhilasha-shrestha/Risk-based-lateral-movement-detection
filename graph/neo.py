"""Neo4j driver helper."""
from __future__ import annotations
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "etl"))
from common import load_env  # noqa: E402


def get_driver():
    from neo4j import GraphDatabase
    load_env()
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    pwd = os.environ.get("NEO4J_PASSWORD", "neo4j_pass")
    return GraphDatabase.driver(uri, auth=(user, pwd))
