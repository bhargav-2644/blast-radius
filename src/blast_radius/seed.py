"""Build the graph on first start if it is missing (used by the container entrypoint).

Rebuilding is cheap (~2 s from the committed OSV snapshot), but an existing graph is left alone so
decisions recorded in a running demo survive restarts.
"""
from blast_radius.db import graph
from blast_radius.ingest.load import build


def main():
    try:
        count = graph().ro_query("MATCH (s:Service) RETURN count(s)").result_set[0][0]
    except Exception:  # graph does not exist yet
        count = 0
    if count:
        print(f"graph already loaded ({count} services)")
    else:
        print("building graph…", build())


if __name__ == "__main__":
    main()
