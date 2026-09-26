"""Positive-only long participation history through the ordinary consumer.

Uses existing synthetic fixture adapters. Does not claim live native verification.
"""
import copy
import unittest
from scripts import generate_reputation_participation_vectors as g
from tests import test_reputation_participation_vectors as consumer


class LargeParticipationHistoryTests(unittest.TestCase):
    def test_1500_replacements_remain_countable_at_consumer(self):
        data = g.one_sided_input()
        admission = data['participationEvidence']['admission']
        root = 'fixture-long-positive-0'
        history = [g.admission_receipt(
            admission, transaction=f'fixture-long-positive-{i}',
            replacement_transaction=f'fixture-long-positive-{i + 1}',
            native_order=i + 1, state='replaced', lineage_root_transaction=root,
        ) for i in range(1500)]
        final = g.admission_receipt(
            admission, transaction='fixture-long-positive-1500',
            native_order=1501, lineage_root_transaction=root,
        )
        history.append(final)
        data['participationEvidence']['admissionReceipt'] = copy.deepcopy(final)
        data['participationEvidence']['admissionReceiptHistory'] = history
        expected = {'expected': 'pass', 'want': {
            'reputationDisposition': 'admitted', 'oneSidedBlame': True,
            'ratingCounted': False, 'currentWindowCountable': True,
        }}
        vector = {
            'input': data,
            'trustedContext': g.profile_context(data['bundle']['parties']),
        }
        self.assertEqual(expected, consumer.evaluate(vector))
        data['participationEvidence']['admissionReceiptHistory'] = list(reversed(history))
        self.assertEqual(expected, consumer.evaluate(vector))
        self.assertEqual(1501, len(history))


if __name__ == '__main__':
    unittest.main()
