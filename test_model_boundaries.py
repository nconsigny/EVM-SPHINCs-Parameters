"""Exact small-domain checks of integer helpers; no full Sage search required."""
import ast
import itertools
import math
from pathlib import Path
import unittest


def helpers():
    nodes = ast.parse(Path(__file__).with_name('costs.sage').read_text()).body
    names = {'compute_nu', 'normalize_calldata_model', 'calldata_token_counts',
             'calldata_standard_gas', 'calldata_floor_gas', 'compute_total_verify_gas'}
    ns = {'binomial': math.comb, 'ceil': math.ceil, 'DEFAULT_CALLDATA_MODEL': '7623',
          'GAS_CALLDATA_STANDARD_ZERO': 4, 'GAS_CALLDATA_STANDARD_NONZERO': 16,
          'GAS_CALLDATA_7623_FLOOR_PER_TOKEN': 10}
    for node in nodes:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            exec(compile(ast.Module(body=[node], type_ignores=[]), 'costs.sage', 'exec'), ns)
    return ns


class BoundaryTests(unittest.TestCase):
    def test_digit_counts_match_enumeration(self):
        nu = helpers()['compute_nu']
        for length, base in [(1, 2), (2, 4), (3, 3)]:
            for total in range(length * (base - 1) + 1):
                expected = sum(sum(x) == total for x in itertools.product(range(base), repeat=length))
                self.assertEqual(nu(length, total, base), expected)

    def test_impossible_digit_sum_rejected(self):
        with self.assertRaises(ValueError):
            helpers()['compute_nu'](2, 7, 4)

    def test_negative_size_rejected(self):
        with self.assertRaises(ValueError):
            helpers()['compute_total_verify_gas'](-1, 0)

    def test_valid_floor_and_execution_paths(self):
        gas = helpers()['compute_total_verify_gas']
        self.assertEqual(gas(100, 0)['total_verify_gas'], 4000)
        self.assertEqual(gas(100, 10000)['total_verify_gas'], 11600)


if __name__ == '__main__':
    unittest.main()
