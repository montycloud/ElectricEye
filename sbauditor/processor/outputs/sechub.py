import itertools

import boto3
from processor.outputs.output_base import SecurityBotOutput
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

@SecurityBotOutput
class SecHubProvider(object):
    __provider__ = "sechub"

    def write_findings(self, findings: list, **kwargs):
        print(f"Writing {len(findings)} results to SecurityHub")
        if findings:
            # print("findings written")
            # print(findings)
            sechub_client = boto3.client("securityhub")
            for i in range(0, len(findings), 100):
                response=sechub_client.batch_import_findings(Findings=findings[i : i + 100])
                failed_count=response.get('FailedCount')
                success_count = response.get('SuccessCount')
                failed_findings = response.get('FailedFindings')
                print("Failed Count")
                print(failed_count)
                print("Success Count")
                print(success_count)
                print("Failed Findings")
                print(failed_findings)
        return
