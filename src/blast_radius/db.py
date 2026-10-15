from functools import cache

from falkordb import FalkorDB, Graph

from blast_radius import config


@cache
def connect() -> FalkorDB:
    # one client (and connection pool) per process: a hosted FalkorDB is a network hop away
    return FalkorDB(
        host=config.FALKORDB_HOST,
        port=config.FALKORDB_PORT,
        username=config.FALKORDB_USERNAME,
        password=config.FALKORDB_PASSWORD,
        ssl=config.FALKORDB_SSL,
    )


def graph(name: str | None = None) -> Graph:
    return connect().select_graph(name or config.GRAPH_NAME)
