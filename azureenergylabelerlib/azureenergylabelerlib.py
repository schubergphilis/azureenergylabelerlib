#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: azureenergylabelerlib.py
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
Main code for azureenergylabelerlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""
import logging
from cachetools import cached, TTLCache
from azure.identity import ClientSecretCredential
from .configuration import (TENANT_THRESHOLDS,
                            RESOURCE_GROUP_THRESHOLDS,
                            SUBSCRIPTION_THRESHOLDS,
                            DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS)
from .entities import DefenderForCloud, Tenant
from .schemas import (resource_group_thresholds_schema,
                      subscription_thresholds_schema,
                      tenant_thresholds_schema)

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''22-04-2022'''
__copyright__ = '''Copyright 2022, Sayantan Khanra'''
__credits__ = ["Sayantan Khanra"]
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra'''
__email__ = '''<skhanra@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


# This is the main prefix used for logging
LOGGER_BASENAME = '''azureenergylabelerlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

class EnergyLabeler:
    """Labeling subscriptions based on findings and label configurations."""
    def __init__(self,
                tenant_id,
                client_id,
                client_secret,
                frameworks=DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS,
                tenant_thresholds=TENANT_THRESHOLDS,
                resource_group_thresholds=RESOURCE_GROUP_THRESHOLDS,
                subscription_thresholds=SUBSCRIPTION_THRESHOLDS,
                allowed_subscription_ids=None,
                denied_subscription_ids=None,
                ):
       self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
       self._tenant_id = tenant_id
       self._client_id = client_id
       self.resource_group_thresholds = resource_group_thresholds_schema.validate(resource_group_thresholds)
       self.tenant_thresholds = tenant_thresholds_schema.validate(tenant_thresholds)
       self.subscription_thresolds = subscription_thresholds_schema.validate(subscription_thresholds)
       self.tenant_credentials = ClientSecretCredential(tenant_id, client_id, client_secret)
       self.allowed_subscription_ids = allowed_subscription_ids
       self.denied_subscription_ids = denied_subscription_ids
       self._tenant = Tenant(credential=self.tenant_credentials,
                             id=self._tenant_id,
                             thresholds=self.tenant_thresholds,
                             subscription_thresholds=self.subscription_thresolds,
                             resource_group_thresholds=self.resource_group_thresholds,
                             allowed_subscription_ids=self.allowed_subscription_ids,
                             denied_subscription_ids=self.denied_subscription_ids)
       self._defender_for_cloud = self._initialize_defender_for_cloud(credential=self.tenant_credentials)
       self._frameworks = DefenderForCloud.validate_frameworks(frameworks)
       self._tenant_energy_label = None
       self._labeled_subscriptions_energy_label = None
       self._tenant_labeled_subscriptions = None

    def _initialize_defender_for_cloud(self, credential):
        """Initialize defender for cloud."""
        subscription_list = [subscription.subscription_id for subscription in
                             self._tenant.subscriptions]
        return DefenderForCloud(credential, subscription_list)

    @property
    @cached(cache=TTLCache(maxsize=150000, ttl=120))
    def defender_for_cloud_findings(self):
        """Defender for cloud findings."""
        return self._defender_for_cloud.get_findings(frameworks=self._frameworks)

    @property
    def matching_frameworks(self):
        """The frameworks provided to match the findings of."""
        return self._frameworks

    @property
    def defender_for_cloud(self):
        """Defender for cloud."""
        return self._defender_for_cloud

    @property
    def tenant(self):
        """Tenant."""
        return self._tenant

    @property
    def tenant_energy_label(self):
        """Energy label of the Azure Tenant."""
        if self._tenant_energy_label is None:
            self._logger.debug(f'Tenant subscriptions labeled are {len(self._tenant.subscriptions_to_be_labeled)}')
            self._tenant_energy_label = self._tenant.get_energy_label(self.defender_for_cloud_findings)
        return self._tenant_energy_label

    @property
    def labeled_subscriptions_energy_label(self):
        """Energy label of the labeled subscriptions."""
        if self._labeled_subscriptions_energy_label is None:
            self._labeled_subscriptions_energy_label = self._tenant.get_energy_label_of_targeted_subscriptions(
                self.defender_for_cloud_findings)
        return self._labeled_subscriptions_energy_label

    @property
    def tenant_labeled_subscriptions(self):
        """The tenant labeled subscription objects."""
        if self._tenant_labeled_subscriptions is None:
            self._tenant_labeled_subscriptions = self._tenant.get_labeled_targeted_subscriptions(
                self.defender_for_cloud_findings)
        return self._tenant_labeled_subscriptions
