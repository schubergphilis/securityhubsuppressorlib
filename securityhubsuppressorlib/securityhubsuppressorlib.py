#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: securityhubsuppressorlib.py
#
# Copyright 2022 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for securityhubsuppressorlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import boto3
import jmespath
import os
import yaml
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.data_classes import DynamoDBStreamEvent
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent
from aws_lambda_powertools.utilities.data_classes.dynamo_db_stream_event import DynamoDBRecordEventName
from aws_lambda_powertools.utilities.typing import LambdaContext
from datetime import datetime
from parser import ParserError
from re import search
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
from yamllint import linter
from yamllint.config import YamlLintConfig

from .entities import Finding
from .entities import Rule

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schuberpghilis.com>'''
__docformat__ = '''google'''
__date__ = '''05-05-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schuberpghilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''securityhubsuppressorlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

DYNAMODB_TABLE_NAME = os.environ['DYNAMODB_TABLE_NAME']

"""
Securityhub Stream processor handles SecurityHub events through
EventBridge and triggers when a finding is not passing the compliance
checks.
"""

VALID_STATUSES = ['FAILED', 'HIGH']


class Suppressor:
    """Suppresses findings on security hub.

    Suppresses a single finding if a suppression rule from the provided suppression list can be matched.
    """

    def __init__(self) -> None:
        self._security_hub_client = boto3.client('securityhub')
        self._dynamodb_resource = boto3.resource('dynamodb')

    def find_rule_by_resource_id(self, resource_id) -> Union[Rule, None]:
        # find_rule_by_resource_id(id) -> Rule

        """
        Finds a rule that matches with the finding within the list of
        suppression rules. Suppression rules can be matched by a regular
        expression on the resource id that the finding applies on.
        """

        for rule in self.rules:
            match = next((arn for arn in rule.arns if search(rule, resource_id)), None)
            if match:
                return rule
        return None

    def get_rule_by_id(self, rule_id) -> Union[Rule, None]:
        # get_rule_by_id(id) -> Rule
        return next((rule for rule in self.rules if rule.id == rule_id, None)


    enable_product(**product_info) -> Boolean
    list_enabled_products() -> [Product]

    def get_findings_by_rule_id(self, rule_id) -> List[dict]:
        # get_findings_by_rule_id(id) -> [Findings]
        """
        Retrieve all findings for a specific control.
        """
        paginator = self.security_hub_client.get_paginator('get_findings')
        findings_pages = paginator.paginate(
            Filters={
                'ProductFields': [
                    {'Key': 'RuleId', 'Value': rule_id, 'Comparison': 'EQUALS'},
                    {'Key': 'ControlId', 'Value': rule_id, 'Comparison': 'EQUALS'}
                ],
                'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}],
            }
        )
        return [findings_page.get('Findings') for findings_page in findings_pages]

    @staticmethod
    def get_finding_details(finding_event: Dict[str, Any], product_name: str) -> Tuple[None, None]:
        # get_finding_details(**finding_info) -> Finding
        """
        Get finding details based on the name of the product. Since Security Hub aggregates finding
        from various services, the way to retrieve information could differ per integrated service.
        There's a configuration per service that defines how required fields should be extracted
        from a finding.
        """

        key, status = None, None
        yaml_config = get_file_contents(PRODUCT_CONFIG_FILE)
        if not yaml_config.get(product_name):
            logger.warning('No YAML configuration for product %s', product_name)
            return key, status
        key = jmespath.search(yaml_config.get(product_name, {}).get('key'), finding_event)
        status = jmespath.search(yaml_config.get(product_name, {}).get('status'), finding_event)
        return key, status

    @property
    def rules(self) -> list:
        # get_suppression_rules() -> [Rule]
        """
        Collect suppression rule entries from DynamoDB, skipping
        invalid entries and caching the list of entries when handling
        multiple findings. A single control can have have multiple suppression
        rules.
        """

        if not self.hash_key:
            logger.info('Invalid hash key: %s', self.hash_key)
            return self._entries
        if not self._entries:
            logger.info(
                'Fetching suppression list from table %s, hash key: %s',
                DYNAMODB_TABLE_NAME,
                self.hash_key)

            rules = self.table.get_item(Key={"controlId": self.hash_key})
            for rule in rules.get('Item', {}).get('data', {}):
                self._entries.append(
                    Rule(action=rule.get('action'),
                         rules=rule.get('rules'),
                         notes=rule.get('notes'),
                         dry_run=rule.get('dry_run', False))
                )
        return self._entries

    @staticmethod
    def validate_finding(finding_event: Dict[str, Any]) -> Union[bool, Finding]:
        # validate_finding(**finding_info) -> Boolean
        """
        Validate a finding by checking whether required fields are there.
        Returns a finding object if successfully validated.
        """

        product_arn = finding_event.get('ProductArn', '')
        if not product_arn:
            raise ValueError('Error: no product_arn found')

        finding_id = finding_event.get('Id', '')
        if not finding_id:
            raise ValueError('Error: no finding_id found')

        product_details = finding_event.get('ProductFields', {})
        if not product_details:
            raise ValueError('Error: no product fields found')

        product_name = product_details.get('aws/securityhub/ProductName', '')
        if not product_name:
            raise ValueError('Error: no product name found')

        return Finding(product_arn=product_arn, finding_id=finding_id, product_name=product_name)

    def suppress_finding(self) -> bool:
        # suppress_finding(**finding_info) -> Boolean
        """
        Suppresses a finding if a matched rule was found that contains a note. The
        dry-run option will prevent actual suppression if enabled.
        """

        if not self.rule:
            logger.info('Skipping finding %s, not in the suppression list', self.resource_id)
            return False

        if not self.rule.notes:
            logger.error('Error: valid notes must be added to the suppression rule')
            return False

        if self.rule.dry_run:
            action_output = 'DRY RUN - Would'
        else:
            action_output = 'Will'

        logger.info(
            '%s perform Suppression on finding %s, matched rule: %s, action: %s',
            action_output,
            self.finding.finding_id,
            self.matched_rule,
            self.rule.action
        )

        self.suppressed_findings.append(self.finding.finding_id)
        now = datetime.now()

        if self.rule.dry_run:
            return True

        return self._security_hub_client.batch_update_findings(
            FindingIdentifiers=[{
                'Id': self.finding.finding_id,
                'ProductArn': self.finding.product_arn
            }],
            Workflow={'Status': self.rule.action},
            Note={
                'Text': f'{self.rule.notes} - '
                        f'By Security Hub Suppressor at {now.strftime("%Y-%m-%d %H:%M:%S")}',
                'UpdatedBy': 'landingzone'
            }
        )

    create_rule(**rule_info) -> Boolean

    def validate_event(event: EventBridgeEvent):
        """
        Validate whether the event is valid by checking whether it matches:
          - a valid status
          - the existance of a hash key; it the identifying property for suppression rules.
          - workflow status; already suppressed items can not be suppressed a second time.
        """

        for event_entries in event.detail.get('findings', []):
            finding = Suppressor.validate_finding(event_entries)
            hash_key, status = Suppressor.get_finding_details(event_entries, finding.product_name)

            if status not in VALID_STATUSES:
                raise ValueError(f'Suppression skipped: status {status} not in {VALID_STATUSES}')

            if not hash_key:
                raise ValueError(f'Suppression skipped: no hash_key found for {finding.product_name}')

            workflow_status = event_entries.get('Workflow', {}).get('Status', {})
            if workflow_status == "SUPPRESSED":
                raise ValueError(f'Suppression skipped: workflow status is {workflow_status}')
        return True

def get_file_contents(file_name: str) -> Any:
    """
    Read and parse a yaml file in a safe way.
    """

    try:
        with open(file_name, 'r', encoding='utf-8') as file_handle:
            file_contents = yaml.load(file_handle.read().strip(), Loader=yaml.SafeLoader)
    except IOError as error:
        logger.error('Unable to read %s', file_name)
        raise error
    except (ValueError, ParserError, UnicodeDecodeError) as error:
        logger.error('Unable to parse file %s as yaml, error: %s', file_name, error)
        raise error
    return file_contents


def run_yaml_lint(file_name: str) -> bool:
    """
    Lint a yaml file.
    """

    conf = YamlLintConfig('extends: default')
    with open(file_name, 'r', encoding='utf-8') as file_handle:
        yaml_linting_result = linter.run(file_handle, conf)
    success = True
    for line in yaml_linting_result:
        if line.level == 'warning':
            print(f'\tWARNING: {line}')
        if line.level == 'error':
            print(f'\tERROR: {line}')
            success = False
    return success




def _parse_fields(event):
    """
    Extract fields containing required working info from the event.
    """

    finding, resource_id, hash_key = None, None, None
    for event_entries in event.get('detail').get('findings', []):
        finding = Suppressor.validate_finding(event_entries)
        hash_key, _status = Suppressor.get_finding_details(event_entries, finding.product_name)
        resource_id = [resource.get('Id') for resource in event_entries.get('Resources', [])].pop()
    return finding, resource_id, hash_key


def run_suppressor(event, securityhub_client=None):
    """
    Execute the suppressor on a combination of finding and
    suppression list.
    """

    finding, resource_id, hash_key = _parse_fields(event)
    suppression_list = get_suppression_list(hash_key)
    suppressor = Suppressor(
        finding=finding,
        resource_id=resource_id,
        suppression_list=suppression_list,
        securityhub_client=securityhub_client)

    suppressor.suppress_finding()
    return suppressor




def main(event: Dict[str, Any], _context: LambdaContext):
    """
    Lambda entrypoint. Take a EventBridge event, validate it and
    run it through the suppressor.
    """

    event: EventBridgeEvent = EventBridgeEvent(event)
    validate_event(event)

    suppressor = run_suppressor(event)
    logger.info('Total findings processed: %i', len(suppressor.suppressed_findings))
    return len(suppressor.suppressed_findings)


"""
Securityhub Stream processor handles DynamoDB stream events and
triggers when a suppression rule is added, removed or changed.
"""



def process_findings(findings_list: List) -> int:
    """
    Process any matched findings by running the suppressor
    on them.
    """

    suppressed_findings = []
    for finding in findings_list:
        suppressor = run_suppressor({'detail': {'findings': [finding]}})
        suppressed_findings.extend(suppressor.suppressed_findings)
    return len(suppressed_findings)


def process_stream_event(event: Dict[str, Any], securityhub_client) -> int:
    """
    Process a DynamoDB event stream, retrieve matching findings and pass
    them on to the findings processor.
    """

    suppressed_findings = 0
    event: DynamoDBStreamEvent = DynamoDBStreamEvent(event)
    for record in event.records:
        if record.event_name == DynamoDBRecordEventName.REMOVE:
            continue

        control_id = record.dynamodb.keys.get('controlId', {}).s_value
        findings_list = get_findings(control_id, securityhub_client)
        if not findings_list:
            logger.warning('Could not find any findings with controlId %s', control_id)
            continue
        suppressed_findings += process_findings(findings_list)
    return suppressed_findings


def main(event: Dict[str, Any], _context) -> None:
    """
    Lambda entrypoint. Take a DynamoDB event stream as event source
    and pass it on to the processor.
    """

    securityhub_client = boto3.client('securityhub')  # pragma: no cover
    total_suppressions = process_stream_event(event, securityhub_client)
    logger.info('Total findings suppressed: %i', total_suppressions)
