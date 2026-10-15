from falkordb import FalkorDB, Graph

from blast_radius import config


def connect() -> FalkorDB:
    return FalkorDB(
        host=config.FALKORDB_HOST,
        port=config.FALKORDB_PORT,
        username=config.FALKORDB_USERNAME,
        password=config.FALKORDB_PASSWORD,
    )


def graph(name: str | None = None) -> Graph:
    return connect().select_graph(name or config.GRAPH_NAME)
