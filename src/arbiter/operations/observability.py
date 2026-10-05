"""Read the API process's private, content-free metrics via docker compose exec."""

import json

from arbiter.observability import read_metrics


def main() -> None:
    try:
        report = read_metrics()
    except Exception:
        raise SystemExit("operational metrics unavailable") from None
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
