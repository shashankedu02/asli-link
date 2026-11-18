"""The evaluation harness is part of the product: its inputs and recorded results must stay reproducible."""

import csv
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cases_file_matches_the_generator():
    build = _load("build_cases", "eval/build_cases.py")
    fresh = build.build()
    committed = list(csv.DictReader((ROOT / "eval/cases.csv").open(encoding="utf-8")))
    assert fresh == committed, "eval/cases.csv is stale: run python eval/build_cases.py"


def test_every_case_has_a_known_truth_and_provenance():
    rows = list(csv.DictReader((ROOT / "eval/cases.csv").open(encoding="utf-8")))
    assert {r["truth"] for r in rows} <= {"official", "impostor", "benign", "hidden", "out_of_scope"}
    assert {r["provenance"] for r in rows} <= {"registry_official", "synthetic_impostor", "handwritten"}
    assert len({r["id"] for r in rows}) == len(rows)


def test_recorded_results_are_current():
    done = subprocess.run(
        [sys.executable, str(ROOT / "scripts/evaluate.py"), "--check"], capture_output=True, text=True
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_no_impostor_is_ever_judged_official():
    """The one safety invariant: a case whose truth is impostor or unbranded phishing must never come back official."""
    evaluate = _load("evaluate", "scripts/evaluate.py")
    summary = evaluate.summarise(evaluate.run())
    assert summary["impostor_judged_official"] == 0


def test_wilson_interval_is_sane():
    evaluate = _load("evaluate2", "scripts/evaluate.py")
    lo, hi = evaluate.wilson(5, 5)
    assert 0.5 < lo < 1.0 and hi == 1.0
    assert evaluate.wilson(0, 0) == (0.0, 0.0)
    lo, hi = evaluate.wilson(50, 100)
    assert lo < 0.5 < hi
