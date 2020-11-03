import itertools

import boto3
from processor.outputs.output_base import SecurityBotOutput


@SecurityBotOutput
class SecHubProvider(object):
    __provider__ = "sechub"

    def write_findings(self, findings: list, **kwargs):
        print(f"Writing {len(findings)} results to SecurityHub")
        if findings:
            sechub_client = boto3.client("securityhub")
            for i in range(0, len(findings), 100):
                sechub_client.batch_import_findings(Findings=findings[i : i + 100])
        return
