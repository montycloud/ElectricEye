import getopt
import os
import sys

import boto3
import click

from insights import create_sechub_insights
from sbauditor import SBAuditor
from processor.main import get_providers, process_findings


def print_checks():
    app = SBAuditor(name="AWS Auditor")
    app.load_plugins()
    app.print_checks_md()


def run_auditor(auditor_name=None, check_name=None, delay=0, outputs=None, output_file=""):
    if not outputs:
        outputs = ["sechub"]
    app = SBAuditor(name="AWS Auditor")
    app.load_plugins(plugin_name=auditor_name)
    findings = list(app.run_checks(requested_check_name=check_name, delay=delay))
    result = process_findings(findings=findings, outputs=outputs, output_file=output_file)
    print(f"Done.")


@click.command()
@click.option("-p", "--profile-name", default="", help="User profile to use")
@click.option(
    "-a", "--auditor-name", default="", help="Auditor to test defaulting to all auditors"
)
@click.option("-c", "--check-name", default="", help="Check to test defaulting to all checks")
@click.option("-d", "--delay", default=0, help="Delay between auditors defaulting to 0")
@click.option(
    "-o",
    "--outputs",
    multiple=True,
    default=(["sechub"]),
    show_default=True,
    help="Outputs for findings",
)
@click.option("--output-file", default="output", show_default=True, help="File to output findings")
@click.option("--list-options", is_flag=True, help="List output options")
@click.option("--list-checks", is_flag=True, help="List all checks")
@click.option(
    "--create-insights",
    is_flag=True,
    help="Create SecurityHub insights for SecurityBot.  This only needs to be done once per SecurityHub instance",
)
def main(
    profile_name,
    auditor_name,
    check_name,
    delay,
    outputs,
    output_file,
    list_options,
    list_checks,
    create_insights,
):
    if list_options:
        print(get_providers())
        sys.exit(2)

    if list_checks:
        print_checks()
        sys.exit(2)

    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    if create_insights:
        create_sechub_insights()
        sys.exit(2)

    run_auditor(
        auditor_name=auditor_name,
        check_name=check_name,
        delay=delay,
        outputs=outputs,
        output_file=output_file,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
