"""Local operator clearance after independently confirming provider termination."""

import argparse
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from arbiter.config import DatabaseSettings
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.operator import operator_engine


def main() -> None:
    parser = argparse.ArgumentParser(description="Clear quarantined unknown capacity")
    parser.add_argument("--tenant", type=UUID, required=True)
    parser.add_argument("--request", type=UUID, required=True)
    parser.add_argument(
        "--provider-stopped",
        action="store_true",
        required=True,
        help="Attest that Ollama has no running work for this request",
    )
    args = parser.parse_args()
    engine = operator_engine(DatabaseSettings())
    try:
        changed = clear_unknown(engine, args.tenant, args.request)
    except (SQLAlchemyError, RuntimeError):
        raise SystemExit("operator clearance unavailable") from None
    finally:
        engine.dispose()
    print("unknown capacity clearance recorded" if changed else "already cleared")


if __name__ == "__main__":
    main()
