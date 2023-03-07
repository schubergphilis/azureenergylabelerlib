#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: labels.py
#
# Copyright 2022 Sayantan Khanra
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
Main code for labels.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
from dataclasses import dataclass

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''22-04-2022'''
__copyright__ = '''Copyright 2022, Sayantan Khanra'''
__credits__ = ["Sayantan Khanra"]
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra'''
__email__ = '''<skhanra@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''labels'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


@dataclass
class AggregateEnergyLabel:
    """Models an energy label averaging multiple subscription labels."""

    label: str
    best_label: str
    worst_label: str


@dataclass
class AggregateSubscriptionEnergyLabel(AggregateEnergyLabel):
    """Models the landing zone energy label."""

    subscriptions_measured: str


@dataclass
class TenantEnergyLabel(AggregateEnergyLabel):
    """Models the landing zone energy label."""

    coverage: str


@dataclass
class ResourceGroupEnergyLabel:
    """Models the resource group energy label."""

    label: str = "F"
    number_of_high_findings: int = 9999
    number_of_medium_findings: int = 9999
    number_of_low_findings: int = 9999
    max_days_open: int = 9999


@dataclass
class SubscriptionEnergyLabel:
    """Models the subscription energy label."""

    label: str = "F"
    number_of_high_findings: int = 9999
    number_of_medium_findings: int = 9999
    number_of_low_findings: int = 9999
    max_days_open: int = 9999
