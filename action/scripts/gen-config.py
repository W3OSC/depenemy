"""Generate a .depenemy.yml config from approved registries input passed on argv."""
import json
import sys


def parse_registries(raw: str) -> list[str]:
    raw = raw.strip()
    if raw.startswith("["):
        try:
            result = json.loads(raw)
            if isinstance(result, list):
                return [str(r).strip() for r in result if r]
        except json.JSONDecodeError:
            pass
    return [r.strip() for r in raw.split(",") if r.strip()]


def main() -> None:
    registries_raw = sys.argv[1] if len(sys.argv) > 1 else "registry.npmjs.org"
    registries = parse_registries(registries_raw)

    lines = ["approved_registries:"]
    for reg in registries:
        lines.append(f"  - {reg}")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
