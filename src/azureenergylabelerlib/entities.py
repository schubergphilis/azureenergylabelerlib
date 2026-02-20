#!/usr/bin/env python
# File: entities.py
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
Main code for entities.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
from collections import Counter
from copy import copy
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import azure.mgmt.resourcegraph as arg
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.resource.policy import PolicyClient
from azure.storage.blob import BlobServiceClient
from cachetools import TTLCache, cached

from .azureenergylabelerlibexceptions import (
    InvalidFrameworks,
    InvalidPath,
    SubscriptionNotPartOfTenant,
)
from .configuration import (
    ENERGY_LABEL_CALCULATION_CONFIG,
    FILE_EXPORT_TYPES,
    FINDING_FILTERING_STATES,
    FINDINGS_QUERY_STRING,
    RESOURCE_GROUP_THRESHOLDS,
    SUBSCRIPTION_THRESHOLDS,
    TENANT_THRESHOLDS,
)
from .labels import AggregateSubscriptionEnergyLabel, TenantEnergyLabel
from .validations import DestinationPath, validate_allowed_denied_subscription_ids

__author__ = """Sayantan Khanra <skhanra@schubergphilis.com>"""
__docformat__ = """google"""
__date__ = """22-04-2022"""
__copyright__ = """Copyright 2022, Sayantan Khanra"""
__credits__ = ["Sayantan Khanra"]
__license__ = """MIT"""
__maintainer__ = """Sayantan Khanra"""
__email__ = """<skhanra@schubergphilis.com>"""
__status__ = """Development"""  # "Prototype", "Development", "Production".

LOGGER_BASENAME = """entities"""
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class DefenderForCloud:
    """Models the Defender for Cloud and retrieves findings."""

    frameworks = {"Microsoft cloud security benchmark", "Azure CIS 1.1.0"}

    def __init__(self, credential: Any, subscription_list: Any) -> None:
        self._credential = credential
        self.subscription_list = subscription_list
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")

    @staticmethod
    def validate_frameworks(frameworks: Any) -> Any:
        """Validates provided frameworks.

        Args:
            frameworks: One or more of the frameworks to
                validate according to an accepted list.

        Returns:
            True if frameworks are valid False otherwise.

        """
        if not isinstance(frameworks, (list, tuple, set)):
            frameworks = [frameworks]
        if set(frameworks).issubset(DefenderForCloud.frameworks):
            return frameworks
        raise InvalidFrameworks(frameworks)

    def get_findings(self, frameworks: Any) -> Any:
        """Filters provided findings by the provided frameworks.

        Args:
            frameworks: The frameworks to filter for

        Returns:
            findings (list(Findings)): A list of findings
                matching the provided frameworks

        """
        finding_details_set = set()
        arg_client = arg.ResourceGraphClient(self._credential)
        frameworks = DefenderForCloud.validate_frameworks(frameworks)
        query_options = {"result_format": "objectArray"}
        for framework in frameworks:
            done = False
            while not done:
                arg_query_options = arg.models.QueryRequestOptions(**query_options)  # type: ignore[arg-type]
                arg_query = arg.models.QueryRequest(
                    subscriptions=self.subscription_list,
                    query=FINDINGS_QUERY_STRING.format(framework=framework),
                    options=arg_query_options,
                )
                response = arg_client.resources(arg_query)
                for finding_details in response.data:
                    finding_details_set.add(Finding(finding_details))
                if response.skip_token:
                    query_options.update({"skip_token": response.skip_token})
                else:
                    done = True
        return list(finding_details_set)


class Tenant:
    """Models the Azure tenant and retrieves subscriptions from it."""

    # pylint: disable=too-many-arguments,dangerous-default-value
    def __init__(
        self,
        credential: Any,
        tenant_id: Any,
        thresholds: Any = TENANT_THRESHOLDS,
        subscription_thresholds: Any = SUBSCRIPTION_THRESHOLDS,
        resource_group_thresholds: Any = RESOURCE_GROUP_THRESHOLDS,
        allowed_subscription_ids: Any = None,
        denied_subscription_ids: Any = None,
        denied_resource_group_names: Any = None,
    ) -> None:
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")
        self.tenant_id = tenant_id
        self.credential = credential
        self.thresholds = thresholds
        self.subscription_thresholds = subscription_thresholds
        self.resource_group_thresholds = resource_group_thresholds
        self.denied_resource_group_names = denied_resource_group_names
        subscription_ids = [
            subscription.subscription_id for subscription in self.subscriptions
        ]
        allowed_subscription_ids, denied_subscription_ids = (
            validate_allowed_denied_subscription_ids(
                allowed_subscription_ids, denied_subscription_ids
            )
        )
        self.allowed_subscription_ids = self._validate_tenant_subscription_ids(
            allowed_subscription_ids, subscription_ids
        )
        self.denied_subscription_ids = self._validate_tenant_subscription_ids(
            denied_subscription_ids, subscription_ids
        )
        self._subscriptions_to_be_labeled = None
        self._targeted_subscriptions_energy_label: AggregateSubscriptionEnergyLabel | None = None

    @staticmethod
    def _validate_tenant_subscription_ids(
        subscription_ids: Any, tenant_subscription_ids: Any
    ) -> Any:
        """Validates that valid Azure subscription ids are part of tenant.

        Args:
            subscription_ids: A list of valid Azure
                subscription ids.
            tenant_subscription_ids: All the tenant
                subscription ids.

        Returns:
            subscription_ids (list): A list of subscription
                ids that are part of the tenant.

        Raises:
            SubscriptionNotPartOfTenant: If subscription
                ids are not part of the current tenant.

        """
        subscriptions_not_in_tenant = set(subscription_ids) - set(
            tenant_subscription_ids
        )
        if subscriptions_not_in_tenant:
            raise SubscriptionNotPartOfTenant(
                f"The following subscription ids provided are not part of the tenant :"
                f" {subscriptions_not_in_tenant}"
            )
        return subscription_ids

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def subscriptions(self) -> Any:
        """Subscriptions of the Tenant.

        Returns:
            List of subscriptions retrieved

        """
        subscription_client = SubscriptionClient(self.credential)
        return [
            Subscription(
                self.credential, subscription_detail, self.denied_resource_group_names
            )
            for subscription_detail in subscription_client.subscriptions.list()
            if subscription_detail.tenant_id == self.tenant_id
        ]

    def get_allowed_subscriptions(self) -> Any:
        """Retrieves allowed subscriptions based on an allow list.

        Returns:
            The list of subscriptions based on the allowed list.

        """
        return [
            subscription
            for subscription in self.subscriptions
            if subscription.subscription_id in self.allowed_subscription_ids
        ]

    def get_not_denied_subscriptions(self) -> Any:
        """Retrieves denied subscriptions based on an denied list.

        Returns:
            The list of subscriptions based on the denied list.

        """
        return [
            subscription
            for subscription in self.subscriptions
            if subscription.subscription_id not in self.denied_subscription_ids
        ]

    @property
    def subscriptions_to_be_labeled(self) -> Any:
        """Subscriptions to be labeled according to the allow or deny list arguments.

        Returns:
            subscription (list): A list of subscriptions to be labeled.

        """
        if self._subscriptions_to_be_labeled is None:
            if self.allowed_subscription_ids:
                self._logger.debug(
                    f"Working on allow list {self.allowed_subscription_ids}"
                )
                self._subscriptions_to_be_labeled = self.get_allowed_subscriptions()
            elif self.denied_subscription_ids:
                self._logger.debug(
                    f"Working on deny list {self.denied_subscription_ids}"
                )
                self._subscriptions_to_be_labeled = self.get_not_denied_subscriptions()
            else:
                self._logger.debug("Working on all tenant subscriptions")
                self._subscriptions_to_be_labeled = self.subscriptions
        return self._subscriptions_to_be_labeled

    def get_labeled_targeted_subscriptions(self, defender_for_cloud_findings: Any) -> Any:
        """Labels the subscriptions based on the allow and deny list provided.

        Args:
            defender_for_cloud_findings: The findings for a Tenant.

        Returns:
            labeled_subscriptions (list): A list of Azure
                Subscriptions objects that have their labels
                calculated.

        """
        labeled_subscriptions = []
        self._logger.debug("Calculating on defender for cloud findings")
        for subscription in self.subscriptions_to_be_labeled:
            self._logger.debug(
                "Calculating energy label for subscription "
                f"{subscription.subscription_id}"
            )
            subscription.get_energy_label(defender_for_cloud_findings)
            labeled_subscriptions.append(subscription)
        return labeled_subscriptions

    def get_energy_label_of_targeted_subscriptions(self, defender_for_cloud_findings: Any) -> Any:
        """Get the energy label of the targeted subscriptions.

        Args:
            defender_for_cloud_findings: The findings from defender for cloud.

        Returns:
            energy_label (str): The energy label of the targeted subscriptions.

        """
        if self._targeted_subscriptions_energy_label is None:
            labeled_subscriptions = self.get_labeled_targeted_subscriptions(
                defender_for_cloud_findings
            )
            label_counter = Counter(
                [
                    subscription.get_energy_label(defender_for_cloud_findings).label
                    for subscription in labeled_subscriptions
                ]
            )
            number_of_subscriptions = len(labeled_subscriptions)
            self._logger.debug(
                f"Number of subscriptions calculated are {number_of_subscriptions}"
            )
            subscription_sums = []
            labels = []
            for threshold in self.thresholds:
                label = threshold.get("label")
                percentage = threshold.get("percentage")
                labels.append(label)
                subscription_sums.append(label_counter.get(label, 0))
                self._logger.debug(
                    f"Calculating for labels {labels} with threshold {percentage} "
                    f"and sums of {subscription_sums}"
                )
                if sum(subscription_sums) / number_of_subscriptions * 100 >= percentage:
                    self._logger.debug(f"Found a match with label {label}")
                    self._targeted_subscriptions_energy_label = (
                        AggregateSubscriptionEnergyLabel(
                            label,
                            min(label_counter.keys()),
                            max(label_counter.keys()),
                            str(number_of_subscriptions),
                        )
                    )
                    break
            else:
                self._logger.debug(
                    "Found no match with thresholds, using default worst label F."
                )
                self._targeted_subscriptions_energy_label = (
                    AggregateSubscriptionEnergyLabel(
                        "F",
                        min(label_counter.keys()),
                        max(label_counter.keys()),
                        str(number_of_subscriptions),
                    )
                )
        return self._targeted_subscriptions_energy_label

    def get_energy_label(self, defender_for_cloud_findings: Any) -> Any:
        """Calculates and returns the energy label of the Tenant.

        Args:
            defender_for_cloud_findings: The measurement data
                of all the findings for a tenant.

        Returns:
            energy_label (TenantEnergyLabel): The labeling object of the Tenant.

        """
        aggregate_label = self.get_energy_label_of_targeted_subscriptions(
            defender_for_cloud_findings
        )
        coverage_percentage = (
            len(self.subscriptions_to_be_labeled) / len(self.subscriptions) * 100
        )
        return TenantEnergyLabel(
            aggregate_label.label,
            best_label=aggregate_label.best_label,
            worst_label=aggregate_label.worst_label,
            coverage=f"{coverage_percentage:.2f}%",
        )


class FindingParserLabeler:
    @staticmethod
    def _get_open_findings(findings: Any, attribute: Any, match: Any) -> Any:
        """Findings for the subscription."""
        return [
            finding
            for finding in findings
            if getattr(finding, attribute).lower() == match.lower()
        ]

    @staticmethod
    def get_not_skipped_findings(findings: Any) -> Any:
        """Not skipped findings for the subscription."""
        return [finding for finding in findings if not finding.is_skipped]

    @staticmethod
    def exclude_findings_by_state(findings: Any, states: Any) -> Any:
        """Returns findings excluding those with specific states."""
        return [finding for finding in findings if finding.state not in states]

    @staticmethod
    def _get_energy_label(findings: Any, threshold: Any, type_: Any, name: Any) -> Any:
        """Calculates the energy label for the entity.

        Args:
            findings: List of defender for cloud findings.
            threshold: The threshold to apply.
            type_: The object type of the entity.
            name: The name of the entity.

        Returns:
            The energy label of the entity based on the provided configuration.

        """
        return EnergyLabeler(
            findings=findings, threshold=threshold, object_type=type_, name=name
        ).energy_label


class Subscription(FindingParserLabeler):
    """Models the Azure subscription that can label itself."""

    def __init__(self, credential: Any, data: Any, denied_resource_group_names: Any = None) -> None:
        self._credential = credential
        self._data = data
        self._threshold = SUBSCRIPTION_THRESHOLDS
        self.denied_resource_group_names = denied_resource_group_names
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")

    @property
    def _type(self) -> Any:
        """Type of the azure resource."""
        return "subscription"

    @property
    def _id(self) -> Any:
        """id."""
        return self._data.id

    @property
    def subscription_id(self) -> Any:
        """Subscription id."""
        return self._data.subscription_id

    @property
    def display_name(self) -> Any:
        """display_name."""
        return self._data.display_name

    @property
    def tenant_id(self) -> Any:
        """Tenant id."""
        return self._data.tenant_id

    @property
    def state(self) -> Any:
        """State of the subscription."""
        return self._data.state

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def resource_groups(self) -> Any:
        """Resource groups of this subscription."""
        resource_group_client = ResourceManagementClient(
            self._credential, self.subscription_id
        )
        return [
            ResourceGroup(resource_group_detail)
            for resource_group_detail in resource_group_client.resource_groups.list()
            if resource_group_detail.name not in self.denied_resource_group_names
        ]

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def exempted_policies(self) -> Any:
        """Policies exempted for this subscription."""
        policy_client = PolicyClient(
            credential=self._credential,
            subscription_id=self.subscription_id,
            api_version="2020-07-01-preview",
        )
        return list(policy_client.policy_exemptions.list())

    def get_open_findings(self, findings: Any) -> Any:
        """Findings for the resource group."""
        return self._get_open_findings(
            findings, "subscription_id", self.subscription_id
        )

    def get_energy_label(self, findings: Any, states: Any = FINDING_FILTERING_STATES) -> Any:
        """Calculates the energy label for the Subscription.

        Args:
            findings: Either a list of defender for cloud findings.
            states: The states to filter findings out for.

        Returns:
            The energy label of the resource group based on the provided configuration.

        """
        not_skipped_findings = self.get_not_skipped_findings(
            self.get_open_findings(findings)
        )
        return self._get_energy_label(
            self.exclude_findings_by_state(not_skipped_findings, states),
            self._threshold,
            self._type,
            self.subscription_id,
        )


class ResourceGroup(FindingParserLabeler):
    """Models the Azure subscription's resource group that can label itself."""

    def __init__(self, data: Any) -> None:
        self._data = data
        self._threshold = RESOURCE_GROUP_THRESHOLDS
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")

    @property
    def location(self) -> Any:
        """location."""
        return self._data.location

    @property
    def name(self) -> Any:
        """name."""
        return self._data.name

    @property
    def _type(self) -> Any:
        """Azure resource type."""
        return "resource_group"

    def get_open_findings(self, findings: Any) -> Any:
        """Findings for the resource group."""
        return self._get_open_findings(findings, "resource_group", self.name)

    def get_energy_label(self, findings: Any, states: Any = FINDING_FILTERING_STATES) -> Any:
        """Calculates the energy label for the resource group.

        Args:
            findings: Either a list of defender for cloud findings.
            states: The states to filter findings out for.

        Returns:
            The energy label of the resource group based on the provided configuration.

        """
        not_skipped_findings = self.get_not_skipped_findings(
            self.get_open_findings(findings)
        )
        return self._get_energy_label(
            self.exclude_findings_by_state(not_skipped_findings, states),
            self._threshold,
            self._type,
            self.name,
        )


class Finding:
    """Models a finding."""

    def __init__(self, data: Any) -> None:
        self._data = data
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")

    def __hash__(self) -> Any:
        return hash(self.recommendation_id)

    def __eq__(self, other: Any) -> Any:
        """Override the default equals behavior."""
        if not isinstance(other, Finding):
            raise ValueError("Not a Finding object")
        return hash(self) == hash(other)

    def __ne__(self, other: Any) -> Any:
        """Override the default unequal behavior."""
        if not isinstance(other, Finding):
            raise ValueError("Not a Finding object")
        return hash(self) != hash(other)

    @property
    def compliance_standard_id(self) -> Any:
        """Compliance standard id."""
        return self._data.get("complianceStandardId", "")

    @property
    def compliance_control_id(self) -> Any:
        """Compliance control id."""
        return self._data.get("complianceControlId", "")

    @property
    def compliance_state(self) -> Any:
        """Compliance state."""
        return self._data.get("complianceState", "")

    @property
    def subscription_id(self) -> Any:
        """Subscription id."""
        return self._data.get("subscriptionId", "")

    @property
    def resource_group(self) -> Any:
        """Resource group name."""
        return self._data.get("resourceGroup", "")

    @property
    def resource_type(self) -> Any:
        """Resource type."""
        return self._data.get("resourceType", "")

    @property
    def resource_name(self) -> Any:
        """Resource name."""
        return self._data.get("resourceName", "")

    @property
    def resource_id(self) -> Any:
        """Resource name."""
        return self._data.get("resourceId", "")

    @property
    def severity(self) -> Any:
        """Severity."""
        return self._data.get("severity", "")

    @property
    def state(self) -> Any:
        """Title."""
        return self._data.get("state", "")

    @property
    def recommendation_id(self) -> Any:
        """Recommendation Id."""
        return self._data.get("recommendationId", "")

    @property
    def recommendation_name(self) -> Any:
        """Recommendation Name."""
        return self._data.get("recommendationName", "")

    @property
    def recommendation_display_name(self) -> Any:
        """Recommendation Display Name."""
        return self._data.get("recommendationDisplayName", "")

    @property
    def description(self) -> Any:
        """Finding Description."""
        return self._data.get("description", "")

    @property
    def remediation_steps(self) -> Any:
        """Remediation Steps."""
        return self._data.get("remediationSteps", "")

    @property
    def azure_portal_recommendation_link(self) -> Any:
        """Azure portal recommendation link Steps."""
        return self._data.get("azurePortalRecommendationLink", "")

    @property
    def control_name(self) -> Any:
        """Control Name."""
        return self._data.get("controlName", "")

    @property
    def not_applicable_reason(self) -> Any:
        """Control Name."""
        return self._data.get("notApplicableReason", "")

    @property
    def first_evaluation_date(self) -> Any:
        """First Evaluation Date."""
        first_evaluation_date = self._data.get("firstEvaluationDate", "").split(".")[0]
        return self._parse_date_time(first_evaluation_date)

    @property
    def status_change_date(self) -> Any:
        """Status Change Date."""
        status_change_date = self._data.get("statusChangeDate", "").split(".")[0]
        return self._parse_date_time(status_change_date)

    @staticmethod
    def _parse_date_time(datetime_string: Any) -> Any:
        try:
            return datetime.strptime(datetime_string, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None

    @property
    def days_open(self) -> Any:
        """Days open."""
        status_change_date = self.status_change_date
        current_time = datetime.now()
        try:
            return (current_time - status_change_date).days
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(
                "Could not calculate number of days open, "
                "last or first observation date is missing."
            )
            return -1

    @property
    def is_skipped(self) -> Any:
        """The finding is skipped or not."""
        return self.compliance_state.lower() == "skipped"


class DataExporter:
    """Export Azure security data."""

    #  pylint: disable=too-many-arguments
    def __init__(
        self,
        export_types: Any,
        id: Any,  # pylint: disable=redefined-builtin
        energy_label: Any,
        defender_for_cloud_findings: Any,
        labeled_subscriptions: Any,
        credentials: Any = None,
    ) -> None:
        self._id = id
        self.energy_label = energy_label
        self.defender_for_cloud_findings = defender_for_cloud_findings
        self.labeled_subscriptions = labeled_subscriptions
        self.export_types = export_types
        self._credentials = credentials
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")

    def export(self, path: Any) -> Any:
        """Exports the data to the provided path."""
        destination = DestinationPath(path)
        if not destination.is_valid():
            raise InvalidPath(path)
        for export_type in self.export_types:
            data_file = DataFileFactory(
                export_type,
                self._id,
                self.energy_label,
                self.defender_for_cloud_findings,
                self.labeled_subscriptions,
            )
            if destination.type == "blob":
                self._export_to_blob(path, data_file.filename, data_file.json)  # type: ignore[attr-defined]  # pylint: disable=no-member
            else:
                self._export_to_fs(path, data_file.filename, data_file.json)  # type: ignore[attr-defined]  # pylint: disable=no-member

    def _export_to_fs(self, directory: Any, filename: Any, data: Any) -> Any:
        """Exports as json to local filesystem."""
        path = Path(directory)
        try:
            path.mkdir()
        except FileExistsError:
            self._logger.debug(f"Directory {directory} already exists.")
        with open(path.joinpath(filename), "w", encoding="utf-8") as jsonfile:
            jsonfile.write(data)
        self._logger.info(f"File {filename} copied to {directory}")

    def _export_to_blob(self, blob_url: Any, filename: Any, data: Any) -> Any:
        """Exports as json to Blob container object storage."""
        parsed_url = urlparse(blob_url)

        account_url = (
            blob_url
            if parsed_url.query
            else f"{parsed_url.scheme}://{parsed_url.netloc}/"
        )
        # If SAS Token is included in the URL, ommit credential parameter
        credential = None if parsed_url.query else self._credentials
        blob_service_client = BlobServiceClient(
            account_url=account_url, credential=credential
        )
        container = parsed_url.path.split("/")[1]
        blob_client = blob_service_client.get_blob_client(
            container=container, blob=filename
        )

        message = f"Export {filename} to blob {blob_url}"
        try:
            blob_client.upload_blob(data.encode("utf-8"), overwrite=True)
            self._logger.info(f"{message} success")
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(f"{message} failure")


class DataFileFactory:
    """Data export factory to handle the different data types returned."""

    #  pylint: disable=too-many-arguments, unused-argument
    def __new__(
        cls,
        export_type: Any,
        id: Any,  # pylint: disable=redefined-builtin
        energy_label: Any,
        defender_for_cloud_findings: Any,
        labeled_subscriptions: Any,
    ) -> Any:
        data_file_configuration = next(
            (
                datafile
                for datafile in FILE_EXPORT_TYPES
                if datafile.get("type") == export_type.lower()
            ),
            None,
        )

        if not data_file_configuration:
            LOGGER.error("Unknown data type %s", export_type)
            return None
        obj = data_file_configuration.get("object_type")
        arguments = {"filename": data_file_configuration.get("filename")}
        arguments.update(
            {
                key: value
                for key, value in copy(locals()).items()
                if key in data_file_configuration.get("required_arguments")  # type: ignore[operator]
            }
        )
        return obj(**arguments)  # type: ignore[operator]


class EnergyLabeler:
    """Generic EnergyLabel factory.

    Returns energy label for resource groups and subscriptions.
    """

    def __init__(self, object_type: Any, name: Any, findings: Any, threshold: Any) -> None:
        self.findings = findings
        self.threshold = threshold
        self.name = name
        self.object_type = object_type
        self.energy_label_class = self._energy_label_class()
        self._logger = logging.getLogger(f"{LOGGER_BASENAME}.{self.__class__.__name__}")

    def _energy_label_class(self) -> Any:
        config = next(
            (
                config
                for config in ENERGY_LABEL_CALCULATION_CONFIG
                if config.get("object_type") == self.object_type
            ),
            None,
        )
        return config.get("energy_label_object", None) if config else None

    @property
    def energy_label(self) -> Any:
        """Energy Label for the subscription or resource group."""
        if not self.findings:
            return self.energy_label_class("A", 0, 0, 0, 0)
        counted_findings: Counter[str] = Counter()
        open_days_counter: Counter[int] = Counter()
        for finding in self.findings:
            counted_findings[finding.severity] += 1
            open_days_counter[finding.days_open] += 1
        try:
            number_of_high_findings = counted_findings.get("High", 0)
            number_of_medium_findings = counted_findings.get("Medium", 0)
            number_of_low_findings = counted_findings.get("Low", 0)
            max_days_open = max(open_days_counter)

            self._logger.debug(
                f"Calculating for {self.object_type} {self.name} "
                f"with number of high findings "
                f"{number_of_high_findings}, "
                f"number of medium findings {number_of_medium_findings}, "
                f"number of low findings {number_of_low_findings}, "
                f"and findings have been open for over "
                f"{max_days_open} days"
            )
            for threshold in self.threshold:
                if all(
                    [
                        number_of_high_findings <= threshold["high"],
                        number_of_medium_findings <= threshold["medium"],
                        number_of_low_findings <= threshold["low"],
                        max_days_open < threshold["days_open_less_than"],
                    ]
                ):
                    energy_label = self.energy_label_class(
                        threshold["label"],
                        number_of_high_findings,
                        number_of_medium_findings,
                        number_of_low_findings,
                        max_days_open,
                    )
                    self._logger.debug(
                        f"Energy Label for {self.object_type} {self.name} "
                        f"has been calculated: {energy_label.label}"
                    )
                    break
                self._logger.debug(
                    "No match with thresholds for energy label, "
                    "using default worst one."
                )
                energy_label = self.energy_label_class(
                    "F",
                    number_of_high_findings,
                    number_of_medium_findings,
                    number_of_low_findings,
                    max_days_open,
                )
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(
                "Could not calculate energy label for "
                f"{self.object_type} {self.name}, "
                'using the default "F"'
            )
            energy_label = self.energy_label_class("F", 0, 0, 0)
        return energy_label
