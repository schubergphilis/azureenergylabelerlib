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
   https://google.github.io/styleguide/pyguide.html

"""
import logging
from cachetools import cached, TTLCache

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from .azureenergylabelerlibexceptions import InvalidCredentials
from .configuration import (TENANT_THRESHOLDS,
                            RESOURCE_GROUP_THRESHOLDS,
                            SUBSCRIPTION_THRESHOLDS,
                            DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS,
                            FINDING_FILTERING_STATES)
from .entities import DefenderForCloud, Tenant, FindingParserLabeler
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


class AzureEnergyLabeler:  # pylint: disable=too-many-arguments
    """Labeling subscriptions based on findings and label configurations.

    Parameters
    ----------
    tenant_id : str
        Azure Tenant ID to collect energy label, for example: `18d9dec0-d762-11ec-9cb5-00155da09878`.
    frameworks : set[str]
        Frameworks taken into account when generating the energy label. Defaults to :data:`~azureenergylabelerlib.configuration.DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS`
    tenant_thresholds : list[dict[str, Any]]
        Defines percentage thresholds mapping to energy labels for the tenant. Defaults to :data:`~azureenergylabelerlib.configuration.TENANT_THRESHOLDS`
    resource_group_thresholds : list[dict[str, Any]]
        Defines percentage thresholds mapping to energy labels for resource groups. Defaults to :data:`~azureenergylabelerlib.configuration.RESOURCE_GROUP_THRESHOLDS`
    subscription_thresholds : list[dict[str, Any]]
        Defines percentage thresholds mapping to energy labels for resource groups. Defaults to :data:`~azureenergylabelerlib.configuration.SUBSCRIPTION_THRESHOLDS`
    credentials : Any
        One of :py:class:`~azure.identity` Credential object containing the credentials used to access the Azure API.
        If not supplied, the library will create a :py:class:`~azure.identity.DefaultAzureCredential`
        and attempt to authenticate in the following order:
        1. A service principal configured by environment variables. See :class:`~azure.identity.EnvironmentCredential`
            for more details.
        2. An Azure managed identity. See :class:`~azure.identity.ManagedIdentityCredential` for more details.
        3. On Windows only: a user who has signed in with a Microsoft application, such as Visual Studio. If multiple
            identities are in the cache, then the value of  the environment variable ``AZURE_USERNAME`` is used to select
            which identity to use. See :class:`~azure.identity.SharedTokenCacheCredential` for more details.
        4. The user currently signed in to Visual Studio Code.
        5. The identity currently logged in to the Azure CLI.
        6. The identity currently logged in to Azure PowerShell.
    allowed_subscription_ids : Any
        Inclusion list of subscripitions to be evaluated
    denied_subscription_ids : Any
        Exclude list of subscriptions to be evaluated
    denied_resource_group_names : List
        List of resource group names to be excluded

    """

    # pylint: disable=dangerous-default-value
    def __init__(self,
                 tenant_id,
                 frameworks=DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS,
                 tenant_thresholds=TENANT_THRESHOLDS,
                 resource_group_thresholds=RESOURCE_GROUP_THRESHOLDS,
                 subscription_thresholds=SUBSCRIPTION_THRESHOLDS,
                 credentials=None,
                 allowed_subscription_ids=None,
                 denied_subscription_ids=None,
                 denied_resource_group_names=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._tenant_id = tenant_id
        self.resource_group_thresholds = resource_group_thresholds_schema.validate(resource_group_thresholds)
        self.tenant_thresholds = tenant_thresholds_schema.validate(tenant_thresholds)
        self.subscription_thresholds = subscription_thresholds_schema.validate(subscription_thresholds)
        self.tenant_credentials = self._fetch_credentials(credentials)
        self.allowed_subscription_ids = allowed_subscription_ids
        self.denied_subscription_ids = denied_subscription_ids
        self.denied_resource_group_names = denied_resource_group_names
        self._tenant = Tenant(credential=self.tenant_credentials,
                              tenant_id=self._tenant_id,
                              thresholds=self.tenant_thresholds,
                              subscription_thresholds=self.subscription_thresholds,
                              resource_group_thresholds=self.resource_group_thresholds,
                              allowed_subscription_ids=self.allowed_subscription_ids,
                              denied_subscription_ids=self.denied_subscription_ids,
                              denied_resource_group_names=self.denied_resource_group_names)
        self._defender_for_cloud = self._initialize_defender_for_cloud(credential=self.tenant_credentials)
        self._frameworks = DefenderForCloud.validate_frameworks(frameworks)
        self._tenant_energy_label = None
        self._labeled_subscriptions_energy_label = None
        self._tenant_labeled_subscriptions = None

    def _fetch_credentials(self, credentials=None):
        credentials = credentials if credentials else DefaultAzureCredential()
        try:
            subscription_client = SubscriptionClient(credentials)
            subscriptions = [subscription.display_name for subscription in subscription_client.subscriptions.list()]
            self._logger.info(f'Credentials valid for: {subscriptions}')
        except ClientAuthenticationError as error:
            raise InvalidCredentials(error) from None

        return credentials

    def _initialize_defender_for_cloud(self, credential):
        """Initialize defender for cloud."""
        subscription_list = [subscription.subscription_id for subscription in
                             self._tenant.subscriptions]
        return DefenderForCloud(credential, subscription_list)

    @property
    @cached(cache=TTLCache(maxsize=150000, ttl=120))
    def defender_for_cloud_findings(self):
        """Defender for cloud findings.

        The self.denied_resource_group_names is turned into lowercase since the,
        <azure.mgmt.resourcegraph.models._models_py3.QueryResponse object has the resource group in lowercase.

        """
        filtered_findings = [finding for finding in self._defender_for_cloud.get_findings(frameworks=self._frameworks)
                             if finding.resource_group not in [rg.lower() for rg in self.denied_resource_group_names]]
        return filtered_findings

    @property
    def filtered_defender_for_cloud_findings(self):
        """Filtered defender for cloud findings."""
        not_skipped_findings = FindingParserLabeler.get_not_skipped_findings(self.defender_for_cloud_findings)
        return FindingParserLabeler.exclude_findings_by_state(not_skipped_findings, FINDING_FILTERING_STATES)

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
