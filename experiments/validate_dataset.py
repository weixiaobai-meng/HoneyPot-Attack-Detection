"""Validate a scenario dataset manifest without training a model."""

import argparse
import json

from experiments.dataset import ScenarioDataset


def main():
    parser = argparse.ArgumentParser(description="Validate graph dataset provenance and split isolation")
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    dataset = ScenarioDataset(
        args.manifest,
        require_complete_labels=True,
        require_double_annotation=True,
        require_raw_alerts=True,
        minimum_split_counts={"train": 6, "validation": 2, "test": 2},
    )
    report = dataset.validate(require_all_splits=True)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["valid"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
