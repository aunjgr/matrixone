import copy
import json
import os
from pathlib import Path
import sys
import unittest

payload=Path(os.environ['CUTOVER_PAYLOAD'])
sys.path.insert(0,str(payload/'source/current'))
import sirius_acceptance as acceptance


def load(name):return json.loads((payload/name).read_text())
def rows(name):return [json.loads(line) for line in (payload/name).read_text().splitlines()]


class PayloadTest(unittest.TestCase):
    def inputs(self):
        return [load('timing/campaign.json'),rows('timing/runs.jsonl'),
                load('resource/campaign.json'),rows('resource/runs.jsonl'),
                load('allocations.json'),load('lifecycle.json'),
                load('sanitizer.json'),load('numeric-baselines.json')]

    def test_a_missing_resource_profile_cannot_pass(self):
        values=self.inputs();values[4]=values[4][:-1]
        with self.assertRaisesRegex(acceptance.campaign.CampaignError,'profile coverage'):
            acceptance.validate(*values)

    def test_a_different_current_head_cannot_pass(self):
        values=self.inputs();values[2]['provenance']['matrixone_revision']='0'*40
        with self.assertRaisesRegex(acceptance.campaign.CampaignError,'semantic inputs'):
            acceptance.validate(*values)


if __name__=='__main__':unittest.main()
