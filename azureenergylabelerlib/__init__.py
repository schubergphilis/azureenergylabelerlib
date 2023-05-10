#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: __init__.py
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
azureenergylabelerlib package.

Import all parts from azureenergylabelerlib here

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html
"""
from ._version import __version__
from .azureenergylabelerlib import AzureEnergyLabeler, Tenant, DefenderForCloud
from .azureenergylabelerlibexceptions import (InvalidFrameworks,
                                              InvalidSubscriptionListProvided,
                                              MutuallyExclusiveArguments,
                                              SubscriptionNotPartOfTenant)

from .configuration import (TENANT_THRESHOLDS,
                            SUBSCRIPTION_THRESHOLDS,
                            RESOURCE_GROUP_THRESHOLDS,
                            DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS,
                            FILE_EXPORT_TYPES,
                            DATA_EXPORT_TYPES,
                            SUBSCRIPTION_METRIC_EXPORT_TYPES,
                            RESOURCE_GROUP_METRIC_EXPORT_TYPES,
                            TENANT_METRIC_EXPORT_TYPES,
                            ALL_SUBSCRIPTION_EXPORT_DATA,
                            ALL_TENANT_EXPORT_TYPES,
                            FINDING_FILTERING_STATES
                            )

from .entities import Subscription, DataExporter
from .validations import (validate_subscription_ids,
                          are_valid_subscription_ids,
                          is_valid_subscription_id,
                          validate_allowed_denied_subscription_ids,
                          DestinationPath)

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''22-04-2022'''
__copyright__ = '''Copyright 2022, Sayantan Khanra'''
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra'''
__email__ = '''<skhanra@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is to 'use' the module(s), so lint doesn't complain
assert __version__

assert AzureEnergyLabeler
assert Tenant
assert DefenderForCloud

assert InvalidFrameworks
assert InvalidSubscriptionListProvided
assert MutuallyExclusiveArguments
assert SubscriptionNotPartOfTenant

assert TENANT_THRESHOLDS
assert SUBSCRIPTION_THRESHOLDS
assert RESOURCE_GROUP_THRESHOLDS
assert DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS
assert FILE_EXPORT_TYPES
assert DATA_EXPORT_TYPES
assert ALL_TENANT_EXPORT_TYPES
assert ALL_SUBSCRIPTION_EXPORT_DATA
assert TENANT_METRIC_EXPORT_TYPES
assert SUBSCRIPTION_METRIC_EXPORT_TYPES
assert RESOURCE_GROUP_METRIC_EXPORT_TYPES
assert FINDING_FILTERING_STATES

assert Subscription
assert DataExporter

assert validate_subscription_ids
assert are_valid_subscription_ids
assert validate_allowed_denied_subscription_ids
assert is_valid_subscription_id
assert DestinationPath
