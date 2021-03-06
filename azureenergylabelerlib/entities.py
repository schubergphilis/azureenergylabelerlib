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
from copy import copy
from collections import Counter
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
from cachetools import cached, TTLCache
from pandas.core.frame import DataFrame
import pandas as pd
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.storage.blob import BlobServiceClient
from azure.mgmt.resource.policy import PolicyClient
import azure.mgmt.resourcegraph as arg
from .configuration import (TENANT_THRESHOLDS,
                            SUBSCRIPTION_THRESHOLDS,
                            RESOURCE_GROUP_THRESHOLDS,
                            FINDINGS_QUERY_STRING,
                            FILE_EXPORT_TYPES,
                            ENERGY_LABEL_CALCULATION_CONFIG)
from .validations import validate_allowed_denied_subscription_ids, DestinationPath
from .azureenergylabelerlibexceptions import (SubscriptionNotPartOfTenant,
                                              InvalidFrameworks,
                                              InvalidPath)
from .labels import (TenantEnergyLabel,
                     AggregateSubscriptionEnergyLabel)

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
    """Models the Defender for Cloud and retrieves findings."""

    frameworks = {'Azure Security Benchmark',
                  'Azure CIS 1.1.0'}

    def __init__(self,
                 credential,
                 subscription_list
                 ):
        self._credential = credential
        self.subscription_list = subscription_list
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
        finding_details_set = set()
        arg_client = arg.ResourceGraphClient(self._credential)
        arg_query_options = arg.models.QueryRequestOptions(result_format="objectArray")
        frameworks = DefenderForCloud.validate_frameworks(frameworks)
        for framework in frameworks:
            arg_query = arg.models.QueryRequest(subscriptions=self.subscription_list,
                                                query=FINDINGS_QUERY_STRING.format(framework=framework),
                                                options=arg_query_options)
            finding_data = arg_client.resources(arg_query).data
            for finding_details in finding_data:
                finding_details_set.add(Finding(finding_details))
        return list(finding_details_set)


class Tenant:  # pylint: disable=too-many-instance-attributes
    """Models the Azure tenant and retrieves subscrptions from it."""

    # pylint: disable=too-many-arguments,dangerous-default-value
    def __init__(self,
                 credential,
                 tenant_id,
                 thresholds=TENANT_THRESHOLDS,
                 subscription_thresholds=SUBSCRIPTION_THRESHOLDS,
                 resource_group_thresholds=RESOURCE_GROUP_THRESHOLDS,
                 allowed_subscription_ids=None,
                 denied_subscription_ids=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.tenant_id = tenant_id
        self.credential = credential
        self.thresholds = thresholds
        self.subscription_thresholds = subscription_thresholds
        self.resource_group_thresholds = resource_group_thresholds
        subscription_ids = [subscription.subscription_id for subscription in self.subscriptions]
        allowed_subscription_ids, denied_subscription_ids = validate_allowed_denied_subscription_ids(
            allowed_subscription_ids,
            denied_subscription_ids)
        self.allowed_subscription_ids = self._validate_tenant_subscription_ids(allowed_subscription_ids,
                                                                               subscription_ids)
        self.denied_subscription_ids = self._validate_tenant_subscription_ids(denied_subscription_ids, subscription_ids)
        self._subscriptions_to_be_labeled = None
        self._targeted_subscriptions_energy_label = None

    @staticmethod
    def _validate_tenant_subscription_ids(subscription_ids, tenant_subscription_ids):
        """Validates that a provided list of valid Azure subscription ids are actually part of the tenant.

        Args:
            subscription_ids: A list of valid Azure subscription ids.
            tenant_subscription_ids: All the tenant subscription ids.

        Returns:
            subscription_ids (list): A list of subscription ids that are part of the tenant.

        Raises:
            SubscriptionNotPartOfTenant: If subscription ids are not part of the current tenant.

        """
        subscriptions_not_in_tenant = set(subscription_ids) - set(tenant_subscription_ids)
        if subscriptions_not_in_tenant:
            raise SubscriptionNotPartOfTenant(f'The following subscription ids provided are not part of the tenant :'
                                              f' {subscriptions_not_in_tenant}')
        return subscription_ids

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def subscriptions(self):
        """Subscriptions of the Tenant.

        Returns:
            List of subscriptions retrieved

        """
        subscription_client = SubscriptionClient(self.credential)
        return [Subscription(self.credential, subscription_detail) for subscription_detail in
                subscription_client.subscriptions.list()]

    def get_allowed_subscriptions(self):
        """Retrieves allowed subscriptions based on an allow list.

        Returns:
            The list of subscriptions based on the allowed list.

        """
        return [subscription for subscription in self.subscriptions if
                subscription.subscription_id in self.allowed_subscription_ids]

    def get_not_denied_subscriptions(self):
        """Retrieves denied subscriptions based on an denied list.

        Returns:
            The list of subscriptions based on the denied list.

        """
        return [subscription for subscription in self.subscriptions if
                subscription.subscription_id not in self.denied_subscription_ids]

    @property
    def subscriptions_to_be_labeled(self):
        """Subscriptions to be labeled according to the allow or deny list arguments.

        Returns:
            subscription (list): A list of subscriptions to be labeled.

        """
        if self._subscriptions_to_be_labeled is None:
            if self.allowed_subscription_ids:
                self._logger.debug(f'Working on allow list {self.allowed_subscription_ids}')
                self._subscriptions_to_be_labeled = self.get_allowed_subscriptions()
            elif self.denied_subscription_ids:
                self._logger.debug(f'Working on deny list {self.denied_subscription_ids}')
                self._subscriptions_to_be_labeled = self.get_not_denied_subscriptions()
            else:
                self._logger.debug('Working on all tenant subscriptions')
                self._subscriptions_to_be_labeled = self.subscriptions
        return self._subscriptions_to_be_labeled

    def get_labeled_targeted_subscriptions(self, defender_for_cloud_findings):
        """Labels the subscriptions based on the allow and deny list provided.

        Args:
            defender_for_cloud_findings: The findings for a Tenant.

        Returns:
            labeled_subscriptions (list): A list of Azure Subscriptions objects that have their labels calculated.

        """
        labeled_subscriptions = []
        self._logger.debug('Calculating on defender for cloud findings')
        dataframe_measurements = pd.DataFrame([finding.measurement_data for finding in defender_for_cloud_findings])
        for subscription in self.subscriptions_to_be_labeled:
            self._logger.debug(f'Calculating energy label for subscription {subscription.subscription_id}')
            subscription.get_energy_label(dataframe_measurements)
            labeled_subscriptions.append(subscription)
        return labeled_subscriptions

    def get_energy_label_of_targeted_subscriptions(self, defender_for_cloud_findings):
        """Get the energy label of the targeted subscriptions.

        Args:
            defender_for_cloud_findings: The findings from defender for cloud.

        Returns:
            energy_label (str): The energy label of the targeted subscriptions.

        """
        if self._targeted_subscriptions_energy_label is None:
            labeled_subscriptions = self.get_labeled_targeted_subscriptions(defender_for_cloud_findings)
            label_counter = Counter(
                [subscription.get_energy_label(defender_for_cloud_findings).label for subscription in
                 labeled_subscriptions])
            number_of_subscriptions = len(labeled_subscriptions)
            self._logger.debug(f'Number of subscriptions calculated are {number_of_subscriptions}')
            subscription_sums = []
            labels = []
            for threshold in self.thresholds:
                label = threshold.get('label')
                percentage = threshold.get('percentage')
                labels.append(label)
                subscription_sums.append(label_counter.get(label, 0))
                self._logger.debug(f'Calculating for labels {labels} with threshold {percentage} '
                                   f'and sums of {subscription_sums}')
                if sum(subscription_sums) / number_of_subscriptions * 100 >= percentage:
                    self._logger.debug(f'Found a match with label {label}')
                    self._targeted_subscriptions_energy_label = AggregateSubscriptionEnergyLabel(label,
                                                                                                 min(label_counter.keys()),
                                                                                                 max(label_counter.keys()),
                                                                                                 number_of_subscriptions)
                    break
            else:
                self._logger.debug('Found no match with thresholds, using default worst label F.')
                self._targeted_subscriptions_energy_label = AggregateSubscriptionEnergyLabel('F',
                                                                                             min(label_counter.keys()),
                                                                                             max(label_counter.keys()),
                                                                                             number_of_subscriptions)
        return self._targeted_subscriptions_energy_label

    def get_energy_label(self, defender_for_cloud_findings):
        """Calculates and returns the energy label of the Tenant.

        Args:
            defender_for_cloud_findings: The measurement data of all the findings for a tenant.

        Returns:
            energy_label (TenantEnergyLabel): The labeling object of the Tenant.

        """
        aggregate_label = self.get_energy_label_of_targeted_subscriptions(defender_for_cloud_findings)
        coverage_percentage = len(self.subscriptions_to_be_labeled) / len(self.subscriptions) * 100
        return TenantEnergyLabel(aggregate_label.label,
                                 best_label=aggregate_label.best_label,
                                 worst_label=aggregate_label.worst_label,
                                 coverage=f'{coverage_percentage:.2f}%')


class Subscription:
    """Models the Azure subscription that can label itself."""

    def __init__(self,
                 credential,
                 data
                 ):
        self._credential = credential
        self._data = data
        self._threshold = SUBSCRIPTION_THRESHOLDS
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def _type(self):
        """Type of the azure resource."""
        return 'subscription'

    @property
    def _id(self):
        """id."""
        return self._data.id

    @property
    def subscription_id(self):
        """Subscription id."""
        return self._data.subscription_id

    @property
    def display_name(self):
        """display_name."""
        return self._data.display_name

    @property
    def tenant_id(self):
        """Tenant id."""
        return self._data.tenant_id

    @property
    def state(self):
        """State of the subscription."""
        return self._data.state

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def resource_groups(self):
        """Resource groups of this subscription."""
        resource_group_client = ResourceManagementClient(self._credential,
                                                         self.subscription_id)
        return [ResourceGroup(resource_group_detail) for resource_group_detail in
                resource_group_client.resource_groups.list()]

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def exempted_policies(self):
        """Policies exempted for this subscription."""
        policy_client = PolicyClient(credential=self._credential, subscription_id=self.subscription_id)
        return [ExemptedPolicy(exempted_policy_detail) for exempted_policy_detail in
                policy_client.policy_exemptions.list()]

    def get_open_findings(self, findings):
        """Findings for the subscription."""
        if not issubclass(DataFrame, type(findings)):
            findings = pd.DataFrame([finding.measurement_data for finding in findings])
        df = findings  # pylint: disable=invalid-name
        try:
            open_findings = df[(df['Subscription ID'] == self.subscription_id)]
        except KeyError:
            self._logger.info(f'No findings for subscription {self.subscription_id}')
            open_findings = pd.DataFrame([])
        return open_findings

    def get_energy_label(self, findings):
        """Calculates the energy label for the resource group.

        Args:
            findings: Either a list of defender for cloud findings.

        Returns:
            The energy label of the resource group based on the provided configuration.

        """
        return EnergyLabeler(findings=self.get_open_findings(findings),
                             threshold=self._threshold,
                             object_type=self._type,
                             name=self.subscription_id
                             ).energy_label


class ResourceGroup:
    """Models the Azure subscription's resource group that can label itself."""

    def __init__(self,
                 data
                 ):
        self._data = data
        self._threshold = RESOURCE_GROUP_THRESHOLDS
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def location(self):
        """location."""
        return self._data.location

    @property
    def name(self):
        """name."""
        return self._data.name

    @property
    def _type(self):
        """Azure resource type."""
        return 'resource_group'

    def get_open_findings(self, findings):
        """Findings for the resource group."""
        if not issubclass(DataFrame, type(findings)):
            findings = pd.DataFrame([finding.measurement_data for finding in findings])
        df = findings  # pylint: disable=invalid-name
        try:
            open_findings = df[(df['Resource Group Name'] == self.name.lower())]
        except KeyError:
            self._logger.info(f'No findings for resource group {self.name}')
            open_findings = pd.DataFrame([])
        return open_findings

    def get_energy_label(self, findings):
        """Calculates the energy label for the resource group.

        Args:
            findings: Either a list of defender for cloud findings.

        Returns:
            The energy label of the resource group based on the provided configuration.

        """
        return EnergyLabeler(findings=self.get_open_findings(findings),
                             threshold=self._threshold,
                             object_type=self._type,
                             name=self.name
                             ).energy_label


class Finding:  # pylint: disable=too-many-public-methods
    """Models a finding."""

    def __init__(self,
                 data
                 ):
        self._data = data
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def __hash__(self):
        return hash(self.recommendation_id)

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
    def not_applicable_reason(self):
        """Control Name."""
        return self._data.get('notApplicableReason', '')

    @property
    def first_evaluation_date(self):
        """First Evaluation Date."""
        first_evaluation_date = self._data.get('firstEvaluationDate', '').split('.')[0]
        return self._parse_date_time(first_evaluation_date)

    @property
    def status_change_date(self):
        """Status Change Date."""
        status_change_date = self._data.get('statusChangeDate', '').split('.')[0]
        return self._parse_date_time(status_change_date)

    @staticmethod
    def _parse_date_time(datetime_string):
        try:
            return datetime.strptime(datetime_string, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            return None

    @property
    def days_open(self):
        """Days open."""
        status_change_date = self.status_change_date
        current_time = datetime.now()
        try:
            return (current_time - status_change_date).days
        except Exception:  # pylint: disable=broad-except
            self._logger.exception('Could not calculate number of days open, '
                                   'last or first observation date is missing.')
            return -1

    @property
    def is_skipped(self):
        """The finding is skipped or not."""
        return self.compliance_state.lower() == 'skipped'

    @property
    def measurement_data(self):
        """Measurement data for computing the energy label."""
        return {
            'Subscription ID': self.subscription_id,
            'Resource Group Name': self.resource_group,
            'Severity': self.severity,
            'Days Open': self.days_open
        }


class ExemptedPolicy:
    """Defines an Exempted Defender For Cloud Policy data."""

    def __init__(self,
                 data
                 ):
        self._data = data
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def created_by(self):
        """Created by which user."""
        return self._data.system_data.created_by

    @property
    def created_at(self):
        """At what time the exemption was created."""
        return self._data.system_data.created_at

    @property
    def last_modified_by(self):
        """Last modified by which user."""
        return self._data.system_data.last_modified_by

    @property
    def last_modified_at(self):
        """Last modified at."""
        return self._data.system_data.last_modified_at

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data.id

    @property
    def name(self):
        """Name."""
        return self._data.name

    @property
    def type(self):
        """Type of the resource."""
        return self._data.type

    @property
    def exemption_category(self):
        """Exemption category."""
        return self._data.exemption_category

    @property
    def expires_on(self):
        """Exemption expires on."""
        return self._data.expires_on

    @property
    def display_name(self):
        """Display Name of the policy/recommendation."""
        return self._data.display_name.split('ASC-')[1]

    @property
    def description(self):
        """Description."""
        return self._data.description


class DataExporter:  # pylint: disable=too-few-public-methods
    """Export Azure security data."""

    #  pylint: disable=too-many-arguments
    def __init__(self,
                 export_types,
                 id,  # pylint: disable=redefined-builtin
                 energy_label,
                 defender_for_cloud_findings,
                 labeled_subscriptions,
                 credentials=None):
        self._id = id
        self.energy_label = energy_label
        self.defender_for_cloud_findings = defender_for_cloud_findings
        self.labeled_subscriptions = labeled_subscriptions
        self.export_types = export_types
        self._credentials = credentials
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def export(self, path):
        """Exports the data to the provided path."""
        destination = DestinationPath(path)
        if not destination.is_valid():
            raise InvalidPath(path)
        for export_type in self.export_types:
            data_file = DataFileFactory(export_type,
                                        self._id,
                                        self.energy_label,
                                        self.defender_for_cloud_findings,
                                        self.labeled_subscriptions)
            if destination.type == 'blob':
                self._export_to_blob(path, data_file.filename, data_file.json)  # pylint: disable=no-member
            else:
                self._export_to_fs(path, data_file.filename, data_file.json)  # pylint: disable=no-member

    def _export_to_fs(self, directory, filename, data):
        """Exports as json to local filesystem."""
        path = Path(directory)
        try:
            path.mkdir()
        except FileExistsError:
            self._logger.debug(f'Directory {directory} already exists.')
        with open(path.joinpath(filename), 'w') as jsonfile:
            jsonfile.write(data)
        self._logger.info(f'File {filename} copied to {directory}')

    def _export_to_blob(self, blob_url, filename, data):
        """Exports as json to Blob container object storage."""
        parsed_url = urlparse(blob_url)
        blob_service_client = BlobServiceClient(account_url=f'{parsed_url.scheme}://{parsed_url.netloc}/',
                                                credential=self._credentials)
        container = parsed_url.path.split('/')[1]
        blob_client = blob_service_client.get_blob_client(container=container, blob=filename)
        try:
            blob_client.upload_blob(data.encode('utf-8'), overwrite=True)
            self._logger.info(f'File {filename} copied to blob {blob_url}')
        except Exception as error:  # pylint: disable=broad-except
            self._logger.error(error)
            self._logger.info(f'File {filename} copy to blob {blob_url} failed')


class DataFileFactory:  # pylint: disable=too-few-public-methods
    """Data export factory to handle the different data types returned."""

    #  pylint: disable=too-many-arguments, unused-argument
    def __new__(cls,
                export_type,
                id,  # pylint: disable=redefined-builtin
                energy_label,
                defender_for_cloud_findings,
                labeled_subscriptions):
        data_file_configuration = next((datafile for datafile in FILE_EXPORT_TYPES
                                        if datafile.get('type') == export_type.lower()), None)

        if not data_file_configuration:
            LOGGER.error('Unknown data type %s', export_type)
            return None
        obj = data_file_configuration.get('object_type')
        arguments = {'filename': data_file_configuration.get('filename')}
        arguments.update({key: value for key, value in copy(locals()).items()
                          if key in data_file_configuration.get('required_arguments')})
        return obj(**arguments)


class EnergyLabeler:  # pylint: disable=too-few-public-methods
    """Generic EnergyLabel factory to return energy label for resource groups and subscriptions."""

    def __init__(self, object_type, name, findings, threshold):
        self.findings = findings
        self.threshold = threshold
        self.name = name
        self.object_type = object_type
        self.energy_label_class = self._energy_label_class()
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def _energy_label_class(self):
        config = next(
            (config for config in ENERGY_LABEL_CALCULATION_CONFIG if config.get('object_type') == self.object_type),
            None)
        return config.get('energy_label_object', None)

    @property
    def energy_label(self):
        """Energy Label for the subscription or resource group."""
        if self.findings.empty:
            return self.energy_label_class('A', 0, 0, 0)
        try:
            number_of_high_findings = self.findings[self.findings['Severity'] == 'High'].shape[0]
            number_of_medium_findings = self.findings[self.findings['Severity'] == 'Medium'].shape[0]
            number_of_low_findings = self.findings[self.findings['Severity'] == 'Low'].shape[0]
            open_findings_low_or_higher = self.findings[(self.findings['Severity'] == 'Low') |
                                                        (self.findings['Severity'] == 'Medium') |
                                                        (self.findings['Severity'] == 'High')]
            max_days_open = max(open_findings_low_or_higher['Days Open']) \
                if open_findings_low_or_higher['Days Open'].shape[0] > 0 else 0

            self._logger.debug(f'Calculating for {self.object_type} {self.name} '
                               f'with number of high findings '
                               f'{number_of_high_findings}, '
                               f'number of medium findings {number_of_medium_findings}, '
                               f'number of low findings {number_of_low_findings}, '
                               f'and findings have been open for over '
                               f'{max_days_open} days'
                               )
            for threshold in self.threshold:
                if all([number_of_high_findings <= threshold['high'],
                        number_of_medium_findings <= threshold['medium'],
                        number_of_low_findings <= threshold['low'],
                        max_days_open < threshold['days_open_less_than']]):
                    energy_label = self.energy_label_class(threshold['label'],
                                                           number_of_high_findings,
                                                           number_of_medium_findings,
                                                           number_of_low_findings,
                                                           max_days_open)
                    self._logger.debug(f'Energy Label for {self.object_type} {self.name} '
                                       f'has been calculated: {energy_label.label}')
                    break
                self._logger.debug('No match with thresholds for energy label, using default worst one.')
                energy_label = self.energy_label_class('F',
                                                       number_of_high_findings,
                                                       number_of_medium_findings,
                                                       number_of_low_findings,
                                                       max_days_open)
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(
                f'Could not calculate energy label for {self.object_type} {self.name}, using the default "F"')
            energy_label = self.energy_label_class('F', 0, 0, 0)
        return energy_label
