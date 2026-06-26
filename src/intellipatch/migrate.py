"""One-shot schema creation, run once before the api service starts.

Only one service in this project touches Postgres, so the schema race
that bit PulsePay and PNWater (multiple services calling init_db()
independently) can't happen here -- kept as its own step anyway for
consistency with those sibling projects and because it's the right
default regardless of how many services there are today.
"""

import logging

from intellipatch.storage.db import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    init_db()
    logger.info("schema migration complete")


if __name__ == "__main__":
    main()
