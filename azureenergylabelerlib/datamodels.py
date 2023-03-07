#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: datamodels.py
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
Main code for datamodels.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
import json

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
LOGGER_BASENAME = '''datamodels'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class TenantEnergyLabelingData:
    """Models the data for energy labeling to export."""

    def __init__(self,  # pylint: disable= too-many-arguments
                 filename,
                 id,  # pylint: disable= redefined-builtin
                 energy_label,
                 labeled_subscriptions,
                 defender_for_cloud_findings):
        self.filename = filename
        self._id = id
        self._energy_label = energy_label
        self._labeled_subscriptions = labeled_subscriptions
        self._defender_for_cloud_findings = defender_for_cloud_findings

    @property
    def json(self):
        """Data to json."""
        subscription_metrics = []
        for subscription in self._labeled_subscriptions:
            energy_label = subscription.get_energy_label(self._defender_for_cloud_findings)
            subscription_metrics.append({
                'Subscription ID': subscription.subscription_id,
                'Subscription Display Name': subscription.display_name,
                'Number of high findings': energy_label.number_of_high_findings,
                'Number of medium findings': energy_label.number_of_medium_findings,
                'Number of low findings': energy_label.number_of_low_findings,
                'Number of exempted findings': len(subscription.exempted_policies),
                'Number of maximum days open': energy_label.max_days_open,
                'Energy Label': energy_label.label
            })
        return json.dumps(
            [{
                'Tenant ID': self._id,
                'Tenant Energy Label': self._energy_label,
                'Labeled subscriptions': subscription_metrics
            }], indent=2, default=str)


class DefenderForCloudFindingsData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, defender_for_cloud_findings):
        self.filename = filename
        self._defender_for_cloud_findings = defender_for_cloud_findings

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Compliance Standard ID': finding.compliance_standard_id,
                            'Compliance Control ID': finding.compliance_control_id,
                            'Compliance State': finding.compliance_state,
                            'Subscription ID': finding.subscription_id,
                            'Resource Group': finding.resource_group,
                            'Resource Type': finding.resource_type,
                            'Resource Name': finding.resource_name,
                            'Resource ID': finding.resource_id,
                            'Severity': finding.severity,
                            'State': finding.state,
                            'Recommendation ID': finding.recommendation_id,
                            'Recommendation Name': finding.recommendation_name,
                            'Recommendation Display Name': finding.recommendation_display_name,
                            'Description': finding.description,
                            'Remediation Steps': finding.remediation_steps,
                            'Azure Portal Recommendation Link': finding.azure_portal_recommendation_link,
                            'Control Name': finding.control_name,
                            'Days Open': finding.days_open
                            }
                           for finding in self._defender_for_cloud_findings if not finding.is_skipped],
                          indent=2, default=str)


class SubscriptionExemptedPolicies:
    """Models the data for exempted policies to export."""

    def __init__(self, filename, labeled_subscriptions):
        self.filename = filename
        self._labeled_subscriptions = labeled_subscriptions

    @property
    def data(self):
        """Data of an subscription exempted policies to export."""
        exempted_policies = []
        for subscription in self._labeled_subscriptions:
            for exempted_policy in subscription.exempted_policies:
                exempted_policies.append({'Subscription ID': subscription.subscription_id,
                                          'Created At': exempted_policy.system_data.created_at,
                                          'Created By': exempted_policy.system_data.created_by,
                                          'Description': exempted_policy.description,
                                          'Display Name': exempted_policy.display_name,
                                          'Exemption Category': exempted_policy.exemption_category,
                                          'Last Modified By': exempted_policy.system_data.last_modified_by,
                                          'Last Modified At': exempted_policy.system_data.last_modified_at,
                                          'Name': exempted_policy.name,
                                          'Expires On': exempted_policy.expires_on
                                          })
        return exempted_policies

    @property
    def json(self):
        """Data to json."""
        return json.dumps(self.data, indent=2, default=str)


class LabeledSubscriptionData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeled_subscription, defender_for_cloud_findings):
        self.filename = filename
        self._labeled_subscription = labeled_subscription
        self._defender_for_cloud_findings = defender_for_cloud_findings

    @property
    def data(self):
        """Data of an subscription to export."""
        energy_label = self._labeled_subscription.get_energy_label(self._defender_for_cloud_findings)
        return {'Subscription ID': self._labeled_subscription.subscription_id,
                'Subscription Display Name': self._labeled_subscription.display_name,
                'Number of high findings': energy_label.number_of_high_findings,
                'Number of medium findings': energy_label.number_of_medium_findings,
                'Number of low findings': energy_label.number_of_low_findings,
                'Number of exempted findings': len(self._labeled_subscription.exempted_policies),
                'Number of maximum days open': energy_label.max_days_open,
                'Energy Label': energy_label.label}

    @property
    def json(self):
        """Data to json."""
        return json.dumps(self.data, indent=2, default=str)


class LabeledResourceGroupData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeled_resource_group_data, defender_for_cloud_findings):
        self.filename = filename
        self._subscription_id = labeled_resource_group_data.get('subscription_id')
        self._labeled_resource_group = labeled_resource_group_data.get('labeled_resource_group')
        self._defender_for_cloud_findings = defender_for_cloud_findings

    @property
    def data(self):
        """Data of an subscription to export."""
        energy_label = self._labeled_resource_group.get_energy_label(self._defender_for_cloud_findings)
        return {'Subscription ID': self._subscription_id,
                'ResourceGroup Name': self._labeled_resource_group.name,
                'Number of high findings':
                    energy_label.number_of_high_findings,
                'Number of medium findings': energy_label.number_of_medium_findings,
                'Number of low findings': energy_label.number_of_low_findings,
                'Number of maximum days open': energy_label.max_days_open,
                'Energy Label': energy_label.label}

    @property
    def json(self):
        """Data to json."""
        return json.dumps(self.data, indent=2, default=str)


class LabeledResourceGroupsData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeled_subscriptions, defender_for_cloud_findings):
        self.filename = filename
        self._labeled_subscriptions = labeled_subscriptions
        self._defender_for_cloud_findings = defender_for_cloud_findings

    @property
    def json(self):
        """Data to json."""
        labeled_resource_groups = []
        for subscription in self._labeled_subscriptions:
            for resource_group in subscription.resource_groups:
                labeled_resource_groups.append({
                    'subscription_id': subscription.subscription_id,
                    'labeled_resource_group': resource_group
                })
        return json.dumps([LabeledResourceGroupData(self.filename,
                                                    resource_group,
                                                    self._defender_for_cloud_findings).data
                           for resource_group in labeled_resource_groups], indent=2, default=str)


class LabeledSubscriptionsData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeled_subscriptions, defender_for_cloud_findings):
        self.filename = filename
        self._labeled_subscriptions = labeled_subscriptions
        self.defender_for_cloud_findings = defender_for_cloud_findings

    @property
    def json(self):
        """Data to json."""
        return json.dumps([LabeledSubscriptionData(self.filename, subscription, self.defender_for_cloud_findings).data
                           for subscription in self._labeled_subscriptions], indent=2, default=str)
