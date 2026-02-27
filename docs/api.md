# API Reference

This section documents the public API of the `azureenergylabelerlib` library.

## Main Interface

The primary entry point for the library is the `AzureEnergyLabeler` class.

::: azureenergylabelerlib.AzureEnergyLabeler

## Entities

Core domain objects that model Azure resources and labeling logic.

### Tenant

::: azureenergylabelerlib.entities.Tenant

### Subscription

::: azureenergylabelerlib.entities.Subscription

### ResourceGroup

::: azureenergylabelerlib.entities.ResourceGroup

### DefenderForCloud

::: azureenergylabelerlib.entities.DefenderForCloud

### Finding

::: azureenergylabelerlib.entities.Finding

### FindingParserLabeler

::: azureenergylabelerlib.entities.FindingParserLabeler

### EnergyLabeler

::: azureenergylabelerlib.entities.EnergyLabeler

### DataExporter

::: azureenergylabelerlib.entities.DataExporter

### DataFileFactory

::: azureenergylabelerlib.entities.DataFileFactory

## Labels

Dataclasses representing the computed energy labels at various levels.

### AggregateEnergyLabel

::: azureenergylabelerlib.labels.AggregateEnergyLabel

### AggregateSubscriptionEnergyLabel

::: azureenergylabelerlib.labels.AggregateSubscriptionEnergyLabel

### TenantEnergyLabel

::: azureenergylabelerlib.labels.TenantEnergyLabel

### SubscriptionEnergyLabel

::: azureenergylabelerlib.labels.SubscriptionEnergyLabel

### ResourceGroupEnergyLabel

::: azureenergylabelerlib.labels.ResourceGroupEnergyLabel

## Data Models

Classes that prepare labeling data for export (JSON).

### TenantEnergyLabelingData

::: azureenergylabelerlib.datamodels.TenantEnergyLabelingData

### DefenderForCloudFindingsData

::: azureenergylabelerlib.datamodels.DefenderForCloudFindingsData

### SubscriptionExemptedPolicies

::: azureenergylabelerlib.datamodels.SubscriptionExemptedPolicies

### LabeledSubscriptionData

::: azureenergylabelerlib.datamodels.LabeledSubscriptionData

### LabeledResourceGroupData

::: azureenergylabelerlib.datamodels.LabeledResourceGroupData

### LabeledResourceGroupsData

::: azureenergylabelerlib.datamodels.LabeledResourceGroupsData

### LabeledSubscriptionsData

::: azureenergylabelerlib.datamodels.LabeledSubscriptionsData

## Configuration

Default thresholds, frameworks, and export type definitions.

::: azureenergylabelerlib.configuration
    options:
      show_if_no_docstring: true
      members:
        - TENANT_THRESHOLDS
        - SUBSCRIPTION_THRESHOLDS
        - RESOURCE_GROUP_THRESHOLDS
        - DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS
        - FILE_EXPORT_TYPES
        - FINDING_FILTERING_STATES
        - ENERGY_LABEL_CALCULATION_CONFIG

## Schemas

Validation schemas for threshold configurations.

::: azureenergylabelerlib.schemas
    options:
      show_if_no_docstring: true
      members:
        - tenant_thresholds_schema
        - subscription_thresholds_schema
        - resource_group_thresholds_schema

## Validations

Utility functions for validating subscription IDs, resource group names, and paths.

### DestinationPath

::: azureenergylabelerlib.validations.DestinationPath

::: azureenergylabelerlib.validations
    options:
      members:
        - is_valid_subscription_id
        - are_valid_subscription_ids
        - validate_subscription_ids
        - validate_allowed_denied_subscription_ids
        - is_valid_resource_group_name
        - are_valid_resource_group_names
        - validate_resource_group_names

## Exceptions

Custom exceptions raised by the library.

::: azureenergylabelerlib.azureenergylabelerlibexceptions.InvalidCredentials

::: azureenergylabelerlib.azureenergylabelerlibexceptions.InvalidFrameworks

::: azureenergylabelerlib.azureenergylabelerlibexceptions.InvalidPath

::: azureenergylabelerlib.azureenergylabelerlibexceptions.InvalidSubscriptionListProvided

::: azureenergylabelerlib.azureenergylabelerlibexceptions.InvalidResourceGroupListProvided

::: azureenergylabelerlib.azureenergylabelerlibexceptions.MutuallyExclusiveArguments

::: azureenergylabelerlib.azureenergylabelerlibexceptions.SubscriptionNotPartOfTenant
