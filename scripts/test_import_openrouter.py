"""Hermetic tests for OpenRouter money and tier conversion."""
from pathlib import Path
import runpy
import unittest

convert = runpy.run_path(str(Path(__file__).with_name('import-openrouter-models.py')))['billing_entry']


class PricingConversion(unittest.TestCase):
    def card(self, **rates):
        pricing = {'prompt': '0.00000015', 'completion': '0.0000006', **rates}
        return convert({'id': 'test/model', 'pricing': pricing})

    def test_exact_rates_and_missing_cache_are_distinct_from_free(self):
        entry, reason = self.card()
        self.assertIsNone(reason)
        self.assertEqual(entry['tiers'][0]['input_nanodollars_per_token'], 150)
        self.assertTrue(entry['cached_input_unpriced'])
        free, _ = self.card(input_cache_read='0', input_cache_write='0')
        self.assertNotIn('cached_input_unpriced', free)
        self.assertNotIn('cache_write_unpriced', free)

    def test_dynamic_and_fractional_primary_rates_are_not_rounded(self):
        for prompt in ['-1', '0.0000000001', 'NaN', '18446744074']:
            with self.subTest(prompt=prompt):
                entry, reason = self.card(prompt=prompt)
                self.assertIsNone(entry)
                self.assertIsNotNone(reason)

    def test_fractional_cache_rate_remains_unpriced(self):
        entry, _ = self.card(input_cache_read='0.0000000001')
        self.assertTrue(entry['cached_input_unpriced'])

    def test_tier_minimum_converts_to_inclusive_previous_ceiling(self):
        entry, reason = self.card(overrides=[{'min_prompt_tokens': 100000, 'prompt': '0.000003'}])
        self.assertIsNone(reason)
        self.assertEqual(entry['tiers'][0]['up_to'], 99999)
        self.assertEqual(entry['tiers'][1]['input_nanodollars_per_token'], 3000)
        self.assertNotIn('up_to', entry['tiers'][1])

    def test_distinct_cache_lifetimes_are_not_charged_at_the_wrong_rate(self):
        entry, reason = self.card(input_cache_write='0.000001', input_cache_write_1h='0.000002')
        self.assertIsNone(reason)
        self.assertTrue(entry['cache_write_unpriced'])

    def test_duplicate_and_reversed_thresholds_are_rejected(self):
        for thresholds in [[10, 10], [20, 10]]:
            entry, reason = self.card(overrides=[{'min_prompt_tokens': value} for value in thresholds])
            self.assertIsNone(entry)
            self.assertIsNotNone(reason)


if __name__ == '__main__':
    unittest.main()
