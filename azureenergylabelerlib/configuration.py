#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: configuration.py
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
configuration package.

Import all parts from configuration here
.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html
"""
import logging

from .datamodels import (TenantEnergyLabelingData,
                         LabeledResourceGroupsData,
                         LabeledSubscriptionsData,
                         DefenderForCloudFindingsData,
                         SubscriptionExemptedPolicies)
from .labels import ResourceGroupEnergyLabel, SubscriptionEnergyLabel

__author__ = 'Sayantan Khanra <skhanra@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Sayantan Khanra'''
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra'''
__email__ = '''<skhanra@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''configuration'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

FINDINGS_QUERY_STRING = "    securityresources\
    | where type == \"microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments\"\
    | extend complianceStandardId = replace( \"-\", \" \", extract(@'/regulatoryComplianceStandards/([^/]*)', 1, id))\
    | where complianceStandardId ==  \"{framework}\"\
    | extend failedResources = toint(properties.failedResources),skippedResources=toint(properties.skippedResources)\
    | where failedResources + skippedResources > 0 or properties.assessmentType == \"MicrosoftManaged\"\
    | join kind = leftouter(\
    securityresources\
    | where type == \"microsoft.security/assessments\") on subscriptionId, name\
    | where properties.state != \"Passed\"\
    | extend firstEvaluationDate = tostring(properties1.status.firstEvaluationDate)\
    | extend statusChangeDate = tostring(properties1.status.statusChangeDate)\
    | extend complianceState = tostring(properties.state)\
    | extend resourceSource = tolower(tostring(properties1.resourceDetails.Source))\
    | extend recommendationId = iff(isnull(id1) or isempty(id1), id, id1)\
    | extend resourceId = trim(' ', tolower(tostring(case(resourceSource =~ 'azure', properties1.resourceDetails.Id,\
                                                        resourceSource =~ 'gcp', properties1.resourceDetails.GcpResourceId,\
                                                        resourceSource =~ 'aws' and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), properties1.resourceDetails.Id,\
                                                        resourceSource =~ 'aws', properties1.resourceDetails.AwsResourceId,\
                                                        extract('^(.+)/providers/Microsoft.Security/assessments/.+$',1,recommendationId)))))\
    | extend regexResourceId = extract_all(@\"/providers/[^/]+(?:/([^/]+)/[^/]+(?:/[^/]+/[^/]+)?)?/([^/]+)/([^/]+)$\", resourceId)[0]\
    | extend resourceType = iff(resourceSource =~ \"aws\" and isnotempty(tostring(properties1.resourceDetails.ConnectorId)), tostring(properties1.additionalData.ResourceType), iff(regexResourceId[1] != \"\", regexResourceId[1], iff(regexResourceId[0] != \"\", regexResourceId[0], \"subscriptions\")))\
    | extend resourceName = tostring(regexResourceId[2])\
    | extend recommendationName = name\
    | extend recommendationDisplayName = tostring(iff(isnull(properties1.displayName) or isempty(properties1.displayName), properties.description, properties1.displayName))\
    | extend description = tostring(properties1.metadata.description)\
    | extend remediationSteps = tostring(properties1.metadata.remediationDescription)\
    | extend severity = tostring(properties1.metadata.severity)\
    | extend azurePortalRecommendationLink = tostring(properties1.links.azurePortal)\
    | extend complianceStandardId = replace( \"-\", \" \", extract(@'/regulatoryComplianceStandards/([^/]*)', 1, id))\
    | extend complianceControlId = extract(@\"/regulatoryComplianceControls/([^/]*)\", 1, id)\
    | mvexpand statusPerInitiative = properties1.statusPerInitiative\
                | extend expectedInitiative = statusPerInitiative.policyInitiativeName =~ \"ASC Default\"\
                | summarize arg_max(expectedInitiative, *) by complianceControlId, recommendationId\
                | extend state = iff(expectedInitiative, tolower(statusPerInitiative.assessmentStatus.code), tolower(properties1.status.code))\
                | extend notApplicableReason = iff(expectedInitiative, tostring(statusPerInitiative.assessmentStatus.cause), tostring(properties1.status.cause))\
                | project-away expectedInitiative\
    | project firstEvaluationDate, statusChangeDate, complianceStandardId, complianceControlId, complianceState, subscriptionId, resourceGroup = resourceGroup1 ,resourceType, resourceName, resourceId, recommendationId, recommendationName, recommendationDisplayName, description, remediationSteps, severity, state, notApplicableReason, azurePortalRecommendationLink\
    | join kind = leftouter (securityresources\
    | where type == \"microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols\"\
    | extend complianceStandardId = replace( \"-\", \" \", extract(@'/regulatoryComplianceStandards/([^/]*)', 1, id))\
    | where complianceStandardId == \"Microsoft cloud security benchmark\"\
    | extend  controlName = tostring(properties.description)\
    | project controlId = name, controlName\
    | distinct  *) on $right.controlId == $left.complianceControlId\
    | project-away controlId\
    | distinct *\
    | order by complianceControlId asc, recommendationId asc"

TENANT_THRESHOLDS = [{'label': 'A',
                      'percentage': 90},
                     {'label': 'B',
                      'percentage': 70},
                     {'label': 'C',
                      'percentage': 50},
                     {'label': 'D',
                      'percentage': 30},
                     {'label': 'E',
                      'percentage': 20}]

SUBSCRIPTION_THRESHOLDS = [{'label': 'A',
                            'high': 0,
                            'medium': 10,
                            'low': 20,
                            'days_open_less_than': 999},
                           {'label': 'B',
                            'high': 10,
                            'medium': 20,
                            'low': 40,
                            'days_open_less_than': 999},
                           {'label': 'C',
                            'high': 15,
                            'medium': 30,
                            'low': 60,
                            'days_open_less_than': 999},
                           {'label': 'D',
                            'high': 20,
                            'medium': 40,
                            'low': 80,
                            'days_open_less_than': 999},
                           {'label': 'E',
                            'high': 25,
                            'medium': 50,
                            'low': 100,
                            'days_open_less_than': 999}]

RESOURCE_GROUP_THRESHOLDS = [{'label': 'A',
                              'high': 0,
                              'medium': 10,
                              'low': 20,
                              'days_open_less_than': 999},
                             {'label': 'B',
                              'high': 10,
                              'medium': 20,
                              'low': 40,
                              'days_open_less_than': 999},
                             {'label': 'C',
                              'high': 15,
                              'medium': 30,
                              'low': 60,
                              'days_open_less_than': 999},
                             {'label': 'D',
                              'high': 20,
                              'medium': 40,
                              'low': 80,
                              'days_open_less_than': 999},
                             {'label': 'E',
                              'high': 25,
                              'medium': 50,
                              'low': 100,
                              'days_open_less_than': 999}]

DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS = {'Microsoft cloud security benchmark',
                                         'Azure CIS 1.1.0'}

FILE_EXPORT_TYPES = [
    {'type': 'tenant_energy_label',
     'filename': 'tenant-energy-label.json',
     'object_type': TenantEnergyLabelingData,
     'required_arguments': ['id', 'energy_label', 'labeled_subscriptions', 'defender_for_cloud_findings']},
    {'type': 'findings',
     'filename': 'defender-for-cloud-findings.json',
     'object_type': DefenderForCloudFindingsData,
     'required_arguments': ['defender_for_cloud_findings']},
    {'type': 'labeled_subscriptions',
     'filename': 'labeled-subscriptions.json',
     'object_type': LabeledSubscriptionsData,
     'required_arguments': ['labeled_subscriptions']},
    {'type': 'subscription_energy_label',
     'filename': 'subscription-energy-label.json',
     'object_type': LabeledSubscriptionsData,
     'required_arguments': ['labeled_subscriptions', 'defender_for_cloud_findings']},
    {'type': 'exempted_policies',
     'filename': 'exempted-policies.json',
     'object_type': SubscriptionExemptedPolicies,
     'required_arguments': ['labeled_subscriptions']},
    {'type': 'resource_group_energy_label',
     'filename': 'resource-group-energy-label.json',
     'object_type': LabeledResourceGroupsData,
     'required_arguments': ['labeled_subscriptions', 'defender_for_cloud_findings']},
]

DATA_EXPORT_TYPES = ['findings']

SUBSCRIPTION_METRIC_EXPORT_TYPES = ['subscription_energy_label']

RESOURCE_GROUP_METRIC_EXPORT_TYPES = ['resource_group_energy_label']

TENANT_METRIC_EXPORT_TYPES = ['tenant_energy_label']

EXEMPTED_POLICIES_EXPORT_TYPES = ['exempted_policies']

ALL_SUBSCRIPTION_EXPORT_DATA = SUBSCRIPTION_METRIC_EXPORT_TYPES + DATA_EXPORT_TYPES + RESOURCE_GROUP_METRIC_EXPORT_TYPES

ALL_TENANT_EXPORT_TYPES = TENANT_METRIC_EXPORT_TYPES + ALL_SUBSCRIPTION_EXPORT_DATA + EXEMPTED_POLICIES_EXPORT_TYPES

SUBSCRIPTION_ID_LENGTH = 36

ENERGY_LABEL_CALCULATION_CONFIG = [
    {
        'object_type': 'resource_group',
        'energy_label_object': ResourceGroupEnergyLabel
    },
    {
        'object_type': 'subscription',
        'energy_label_object': SubscriptionEnergyLabel
    }
]

FINDING_FILTERING_STATES = ('notapplicable', 'healthy')
