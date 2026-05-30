import argparse
import json
from pathlib import Path

from .experiments import demo, evaluate


def main():
    parser = argparse.ArgumentParser(description="Local MAC capability and atomic effect experiments")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("demo", "evaluate"):
        sub.add_parser(command).add_argument("--output", type=Path)
    args = parser.parse_args()
    report = demo() if args.command == "demo" else evaluate()
    value = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(value)
    else:
        print(value, end="")


if __name__ == "__main__":
    main()
