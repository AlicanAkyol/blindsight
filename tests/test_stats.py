"""Guards for the evaluator statistics. Run: uv run python tests/test_stats.py

These numbers are checked against scipy/statsmodels (see comments) so a
refactor cannot silently change a reported p-value or interval.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "evaluator"))
from evaluate import mcnemar_exact, wilson  # noqa: E402


def approx(a, b, tol=0.02):
    return abs(a - b) <= tol


def test_mcnemar():
    # 5 discordant / 0: the symbol experiment's persistence result.
    # scipy.stats: binomtest(0, 5, 0.5, 'two-sided').pvalue == 0.0625
    assert approx(mcnemar_exact(5, 0), 0.0625), mcnemar_exact(5, 0)
    assert mcnemar_exact(0, 0) == 1.0
    assert approx(mcnemar_exact(1, 0), 1.0)          # 2*C(1,0)/2 = 1.0
    assert approx(mcnemar_exact(10, 0), 0.00195)     # 2/1024
    assert approx(mcnemar_exact(3, 3), 1.0)          # symmetric, clamps to 1
    print("mcnemar_exact ok")


def test_wilson():
    # statsmodels proportion_confint(k, n, method='wilson'), as percentages
    lo, hi = wilson(1, 3)
    assert approx(lo, 6.1) and approx(hi, 79.2), (lo, hi)
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and approx(hi, 27.8), (lo, hi)  # lower clamped to 0
    lo, hi = wilson(10, 10)
    assert approx(lo, 72.2) and hi == 100.0, (lo, hi)  # upper clamped to 100
    assert wilson(0, 0) == (None, None)
    print("wilson ok")


if __name__ == "__main__":
    test_mcnemar()
    test_wilson()
    print("all stats tests passed")
