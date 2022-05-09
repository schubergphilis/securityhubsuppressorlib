#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: entities
#.py
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
Main code for entities.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
from dataclasses import dataclass
from re import search
from typing import List
from typing import Optional

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
LOGGER_BASENAME = '''entities'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


@dataclass
class Rule:
    """A Security hub finding suppression rule.

    The dry_run options will skip actual suppression of findings."""

    id: str
    action: str
    dry_run: bool
    notes: str
    arns: List[str]
    control_id: str

    def is_resource_in_rule(self, resource_id):
        return bool(next((arn for arn in self.arns if search(arn, resource_id)), None))

@dataclass
class Finding:
    """A security hub finding."""

    id: str
    product_arn: str
    product_name: str


# @dataclass
# class Product:
#     """"""

# Inspector:
#     key: ProductFields."attributes/BENCHMARK_RULE_ID"
#     status: FindingProviderFields.Severity.Label
# Firewall Manager:
#     key: ProductFields."aws/securityhub/ProductName"
#     status: Compliance.Status
# Security Hub:
#     key: ProductFields.ControlId || ProductFields.RuleId
#     status: Compliance.Status
