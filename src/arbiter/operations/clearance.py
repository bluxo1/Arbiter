"""Local operator clearance after independently confirming provider termination."""

from typing import Never
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from arbiter.config import DatabaseSettings
from arbiter.observability import configure_logging
from arbiter.operations.provision import OperatorParser
from arbiter.persistence.maintenance import clear_unknown
from arbiter.persistence.operator import operator_engine


class ClearanceParser(OperatorParser):
    def error(self, message: str) -> Never:
        # Retain argparse's exit status without echoing rejected operator input.
        self.exit(2, "operator clearance failed (invalid arguments)\n")


def main() -> None:
    configure_logging()
    parser = ClearanceParser(description="Clear quarantined unknown capacity")
    parser.add_argument("--tenant", type=UUID, required=True)
    parser.add_argument("--request", type=UUID, required=True)
    parser.add_argument(
        "--provider-stopped",
        action="store_true",
        required=True,
        help="Attest that Ollama has no running work for this request",
    )
    args = parser.parse_args()
    try:
        engine = operator_engine(DatabaseSettings())
    except Exception:
        raise SystemExit("operator clearance unavailable") from None
    try:
        changed = clear_unknown(engine, args.tenant, args.request)
    except (SQLAlchemyError, RuntimeError):
        raise SystemExit("operator clearance unavailable") from None
    finally:
        engine.dispose()
    print("unknown capacity clearance recorded" if changed else "already cleared")


if __name__ == "__main__":
    main()
