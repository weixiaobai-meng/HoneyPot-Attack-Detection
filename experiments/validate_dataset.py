"""Validate a scenario dataset manifest without training a model."""

import argparse
import json

from experiments.dataset import ScenarioDataset


def main():
    parser = argparse.ArgumentParser(description="Validate graph dataset provenance and split isolation")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--allow-missing-splits", action="store_true")
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="relax formal size, raw-alert and double-annotation requirements",
    )
    args = parser.parse_args()
    dataset = ScenarioDataset(
        args.manifest,
        require_complete_labels=True,
        require_double_annotation=not args.smoke_test,
        require_raw_alerts=not args.smoke_test,
        minimum_split_counts=None if args.smoke_test else {"train": 6, "validation": 2, "test": 2},
    )
    report = dataset.validate(require_all_splits=not args.allow_missing_splits)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["valid"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
