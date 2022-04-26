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
from collections import Counter
from cachetools import cached, TTLCache
from pandas.core.frame import DataFrame
import pandas as pd
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
import azure.mgmt.resourcegraph as arg
from .configuration import (TENANT_THRESHOLDS,
                            SUBSCRIPTION_FINDINGS_THRESHOLDS,
                            SUBSCRIPTION_RESOURCE_GROUP_THRESHOLDS,
                            RESOURCE_GROUP_THRESHOLDS,
                            FINDINGS_QUERY_STRING)
from .validations import validate_allowed_denied_subscription_ids
from .azureenergylabelerlibexceptions import (SubscriptionNotPartOfTenant,
                                              InvalidFrameworks)
from .labels import (ResourceGroupEnergyLabel,
                     SubscriptionEnergyLabelBasedOnResourceGroups,
                     SubscriptionEnergyLabelBasedOnFindings,
                     SubscriptionEnergyLabelAggregated)

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''22-04-2022'''
__copyright__ = '''Copyright 2022, Sayantan Khanra'''
__credits__ = ["Sayantan Khanra"]
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra'''
__email__ = '''<skhanra@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''entities'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class DefenderForCloud:

    frameworks = {'Azure Security Benchmark', 'SOC TSP', 'Azure CIS 1.1.0'}

    def __init__(self,
                 credential,
                 subscription_list
                 ):
        self._credential = credential
        self.subscription_list = subscription_list

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @staticmethod
    def validate_frameworks(frameworks):
        """Validates provided frameworks.
        Args:
            frameworks: One or more of the frameworks to validate according to an accepted list.
        Returns:
            True if frameworks are valid False otherwise.
        """
        if not isinstance(frameworks, (list, tuple, set)):
            frameworks = [frameworks]
        if set(frameworks).issubset(DefenderForCloud.frameworks):
            return frameworks
        raise InvalidFrameworks(frameworks)

    def get_findings(self, frameworks):
        """Filters provided findings by the provided frameworks.
        Args:
            frameworks: The frameworks to filter for
        Returns:
            findings (list(Findings)): A list of findings matching the provided frameworks
        """
        finding_details_list = []
        arg_client = arg.ResourceGraphClient(self._credential)
        arg_query_options = arg.models.QueryRequestOptions(result_format="objectArray")
        frameworks = DefenderForCloud.validate_frameworks(frameworks)
        for framework in frameworks:
            arg_query = arg.models.QueryRequest(subscriptions=self.subscription_list,
                                                query=FINDINGS_QUERY_STRING.format(framework=framework),
                                                options=arg_query_options)
            finding_data = arg_client.resources(arg_query).data
            for finding_details in finding_data:
                finding_details_list.append(Finding(finding_details))
        return finding_details_list


class Tenant:
    """Models the Azure tenant and retrieves subscrptions from it."""
    def __init__(self,
                 credential,
                 id,
                 thresholds=TENANT_THRESHOLDS,
                 subscription_thresholds=SUBSCRIPTION_FINDINGS_THRESHOLDS,
                 resource_group_thresholds=RESOURCE_GROUP_THRESHOLDS,
                 allowed_subscription_ids=None,
                 denied_subscription_ids=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.id = id
        self.credential = credential
        self.thresholds = thresholds
        self.subscription_thresholds = subscription_thresholds
        self.resource_group_thresholds = resource_group_thresholds
        subscription_ids = [subscription.id for subscription in self.subscriptions]
        allowed_subscription_ids, denied_subscription_ids = validate_allowed_denied_subscription_ids(allowed_subscription_ids,
                                                                                      denied_subscription_ids)
        self.allowed_subscription_ids = self._validate_tenant_subscription_ids(allowed_subscription_ids, subscription_ids)
        self.denied_subscription_ids = self._validate_tenant_subscription_ids(denied_subscription_ids, subscription_ids)
        self._subscriptions_to_be_labeled = None
        self._targeted_subscriptions_energy_label = None

    @staticmethod
    def _validate_tenant_subscription_ids(subscription_ids, tenant_account_ids):
        """Validates that a provided list of valid Azure subscription ids are actually part of the landing zone.
        Args:
            subscription_ids: A list of valid Azure subscription ids.
            tenant_account_ids: All the tenant subscription ids.
        Returns:
            subscription_ids (list): A list of subscription ids that are part of the tenant.
        Raises:
            SubscriptionNotPartOfTenant: If subscription ids are not part of the current tenant.
        """
        subscriptions_not_in_tenant = set(subscription_ids) - set(tenant_account_ids)
        if subscriptions_not_in_tenant:
            raise SubscriptionNotPartOfTenant(f'The following subscription ids provided are not part of the tenant :'
                                              f' {subscriptions_not_in_tenant}')
        return subscription_ids

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def subscriptions(self):
        """Subscriptions of the Tenant
        Returns:
            List of subscriptions retrieved
        """
        subscription_client = SubscriptionClient(self.credential)
        return [Subscription(self.credential, subscription_detail) for subscription_detail in subscription_client.subscriptions.list()]

    def get_allowed_subscriptions(self):
        """Retrieves allowed subscriptions based on an allow list.
        Returns:
            The list of subscriptions based on the allowed list.
        """
        return [subscription for subscription in self.subscriptions if subscription.id in self.allowed_subscriotions_ids]

    def get_denied_subscriptions(self):
        """Retrieves denied subscriptions based on an denied list.
        Returns:
            The list of subscriptions based on the denied list.
        """
        return [subscription for subscription in self.subscriptions if subscription.id in self.denied_subscription_ids]


class Subscription:
    """Models the Azure subscription that can label itself."""

    def __init__(self,
                 credential,
                 data
                 ):
        self._credential = credential
        self._data = data
        self._subscription_resource_group_thresholds = SUBSCRIPTION_RESOURCE_GROUP_THRESHOLDS
        self._findings_thresholds = SUBSCRIPTION_FINDINGS_THRESHOLDS

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def id(self):
        """id."""
        return self._data.id

    @property
    def subscription_id(self):
        """subscription id."""
        return self._data.subscription_id

    @property
    def display_name(self):
        """display_name."""
        return self._data.display_name

    @property
    def tenant_id(self):
        """tenant id."""
        return self._data.tenant_id

    @property
    def state(self):
        """state of the subscription."""
        return self._data.state

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def resource_groups(self):
        resource_group_client = ResourceManagementClient(self._credential,
                                                         self.subscription_id)
        return [ResourceGroup(resource_group_detail) for resource_group_detail in
                resource_group_client.resource_groups.list()]

    def get_energy_label_based_on_subscription_findings(self, findings):
        """Calculates the energy label based on the subscription findings
        Args:
            findings: Either a list of defender for cloud findings .
        Returns:
            The energy label of the subscription based on the provided configuration.
        """
        if not issubclass(DataFrame, type(findings)):
            findings = pd.DataFrame([finding.measurement_data for finding in findings])
        df = findings  # pylint: disable=invalid-name
        try:
            open_findings = df[(df['Subscription ID'] == self.subscription_id)& (df['Resource Group Name'] == '')]
        except KeyError:
            self._logger.info(f'No findings specific to the subscription {self.subscription_id}')
            self.energy_label = ResourceGroupEnergyLabel('A', 0, 0, 0)
            return self.energy_label
        try:
            number_of_high_findings = open_findings[open_findings['Severity'] == 'High'].shape[0]
            number_of_medium_findings = open_findings[open_findings['Severity'] == 'Medium'].shape[0]
            number_of_low_findings = open_findings[open_findings['Severity'] == 'Low'].shape[0]

            LOGGER.debug(f'Calculating for subscription {self.subscription_id} '
                         f'with number of high findings '
                         f'{number_of_high_findings}, '
                         f'number of medium findings {number_of_medium_findings}, '
                         f'number of low findings {number_of_low_findings}')

            for threshold in self._findings_thresholds:
                if all([number_of_high_findings <= threshold['high'],
                        number_of_medium_findings <= threshold['medium'],
                        number_of_low_findings <= threshold['low']]):
                    self.energy_label = SubscriptionEnergyLabelBasedOnFindings(threshold['label'],
                                                                               number_of_high_findings,
                                                                               number_of_medium_findings,
                                                                               number_of_low_findings)
                    LOGGER.debug(f'Energy Label for resource group {self.name} '
                                 f'has been calculated: {self.energy_label.label}')
                    break
                else:
                    LOGGER.debug('No match with thresholds for energy label, using default worst one.')
                    self.energy_label = SubscriptionEnergyLabelBasedOnFindings('F',
                                                                               number_of_high_findings,
                                                                               number_of_medium_findings,
                                                                               number_of_low_findings)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(
                f'Could not calculate energy label for subscription {self.subscription_id}, using the default "F"')
        return self.energy_label

    def get_energy_label_based_on_resource_groups(self, findings):
        """Get energy label based on the resource group findings."""
        label_counter = Counter(
            [resource_group.calculate_energy_label(findings).label for resource_group in self.resource_groups])
        labels = []
        resource_group_sums = []
        number_of_resource_groups = len(self.resource_groups)
        for threshold in self._subscription_resource_group_thresholds:
            label = threshold.get('label')
            percentage = threshold.get('percentage')
            labels.append(label)
            resource_group_sums.append(label_counter.get(label, 0))
            LOGGER.debug(f'Calculating for labels {labels} with threshold {percentage} '
                         f'and sums of {resource_group_sums}')
            if sum(resource_group_sums) / number_of_resource_groups * 100 >= percentage:
                LOGGER.debug(f'Found a match with label {label}')
                self._targeted_subscriptions_energy_label = SubscriptionEnergyLabelBasedOnResourceGroups(label,
                                                                                    min(label_counter.keys()),
                                                                                    max(label_counter.keys()),
                                                                                    number_of_resource_groups)
                break
            else:
                LOGGER.debug('Found no match with thresholds, using default worst label F.')
                self._targeted_subscriptions_energy_label = SubscriptionEnergyLabelBasedOnResourceGroups('F',
                                                                                    min(label_counter.keys()),
                                                                                    max(label_counter.keys()),
                                                                                    number_of_resource_groups)
        return self._targeted_subscriptions_energy_label

    def get_aggregated_energy_label(self, findings):
        """Aggregated Energy Label for the subscription."""
        energy_label_based_on_resource_groups = self.get_energy_label_based_on_resource_groups(findings)
        energy_label_based_on_findings_in_subscription = self.get_energy_label_based_on_subscription_findings(findings)
        energy_labels = [energy_label_based_on_resource_groups.label, energy_label_based_on_findings_in_subscription.label]
        energy_labels.sort()
        final_energy_label = energy_labels[1]
        return SubscriptionEnergyLabelAggregated(final_energy_label,
                                                 energy_label_based_on_resource_groups.resource_groups_measured,
                                                 energy_label_based_on_resource_groups.label,
                                                 energy_label_based_on_findings_in_subscription.label)


class ResourceGroup:
    """Models the Azure subscription's resource group that can label itself."""

    def __init__(self,
                 data
                 ):
        self._data = data
        self._threshold = RESOURCE_GROUP_THRESHOLDS

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def id(self):
        """id."""
        return self._data.id

    @property
    def location(self):
        """location."""
        return self._data.location

    @property
    def name(self):
        """name."""
        return self._data.name

    def calculate_energy_label(self, findings):
        """Calculates the energy label for the resource group.
        Args:
            findings: Either a list of defender for cloud findings .
        Returns:
            The energy label of the resource group based on the provided configuration.
        """
        if not issubclass(DataFrame, type(findings)):
            findings = pd.DataFrame([finding.measurement_data for finding in findings])
        df = findings  # pylint: disable=invalid-name
        try:
            open_findings = df[(df['Resource Group Name'] == self.name)]
        except KeyError:
            self._logger.info(f'No findings for resource group {self.name}')
            self.energy_label = ResourceGroupEnergyLabel('A', 0, 0, 0)
            return self.energy_label
        try:
            number_of_high_findings = open_findings[open_findings['Severity'] == 'High'].shape[0]
            number_of_medium_findings = open_findings[open_findings['Severity'] == 'Medium'].shape[0]
            number_of_low_findings = open_findings[open_findings['Severity'] == 'Low'].shape[0]

            LOGGER.debug(f'Calculating for resource group {self.name} '
                               f'with number of high findings '
                               f'{number_of_high_findings}, '
                               f'number of medium findings {number_of_medium_findings}, '
                               f'number of low findings {number_of_low_findings}')

            for threshold in self._threshold:
                if all([number_of_high_findings <= threshold['high'],
                        number_of_medium_findings <= threshold['medium'],
                        number_of_low_findings <= threshold['low']]):
                    self.energy_label = ResourceGroupEnergyLabel(threshold['label'],
                                                                 number_of_high_findings,
                                                                 number_of_medium_findings,
                                                                 number_of_low_findings)
                    LOGGER.debug(f'Energy Label for resource group {self.name} '
                                       f'has been calculated: {self.energy_label.label}')
                    break
                else:
                    LOGGER.debug('No match with thresholds for energy label, using default worst one.')
                    self.energy_label = ResourceGroupEnergyLabel('F',
                                                                 number_of_high_findings,
                                                                 number_of_medium_findings,
                                                                 number_of_low_findings)
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(f'Could not calculate energy label for resource group {self.name}, using the default "F"')
        return self.energy_label


class Finding:  # pylint: disable=too-many-public-methods
    """Models a finding."""

    def __init__(self,
                 data
                 ):
        self._data = data

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def __eq__(self, other):
        """Override the default equals behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) == hash(other)

    def __ne__(self, other):
        """Override the default unequal behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) != hash(other)

    @property
    def compliance_standard_id(self):
        """Compliance standard id."""
        return self._data.get('complianceStandardId', '')

    @property
    def compliance_control_id(self):
        """Compliance control id."""
        return self._data.get('complianceControlId', '')
    
    @property
    def compliance_state(self):
        """Compliance state."""
        return self._data.get('complianceState', '')

    @property
    def subscription_id(self):
        """Subscription id."""
        return self._data.get('subscriptionId', '')
    
    @property
    def resource_group(self):
        """Resource group name."""
        return self._data.get('resourceGroup', '')
    
    @property
    def resource_type(self):
        """Resource type."""
        return self._data.get('resourceType', '')

    @property
    def resource_name(self):
        """Resource name."""
        return self._data.get('resourceName', '')
    
    @property
    def resource_id(self):
        """Resource name."""
        return self._data.get('resourceId', '')

    @property
    def severity(self):
        """Severity."""
        return self._data.get('severity', '')

    @property
    def state(self):
        """Title."""
        return self._data.get('state', '')

    @property
    def recommendation_id(self):
        """Recommendation Id."""
        return self._data.get('recommendationId', '')
    
    @property
    def recommendation_name(self):
        """Recommendation Name."""
        return self._data.get('recommendationName', '')
    
    @property
    def recommendation_display_name(self):
        """Recommendation Display Name."""
        return self._data.get('recommendationDisplayName', '')

    @property
    def description(self):
        """Finding Description."""
        return self._data.get('description', '')
    
    @property
    def remediation_steps(self):
        """Remediation Steps."""
        return self._data.get('remediationSteps', '')
    
    @property
    def azure_portal_recommendation_link(self):
        """Azure portal recommendation link Steps."""
        return self._data.get('azurePortalRecommendationLink', '')
    
    @property
    def control_name(self):
        """Control Name."""
        return self._data.get('controlName', '')

    @property
    def measurement_data(self):
        """Measurement data for computing the energy label."""
        return {
            'Subscription ID': self.subscription_id,
            'Resource Group Name': self.resource_group,
            'Severity': self.severity
        }
