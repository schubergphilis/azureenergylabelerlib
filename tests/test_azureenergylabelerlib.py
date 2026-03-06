"""Tests for azureenergylabelerlib."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azureenergylabelerlib import AzureEnergyLabeler
from azureenergylabelerlib.configuration import (
    DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS,
    RESOURCE_GROUP_THRESHOLDS,
    SUBSCRIPTION_THRESHOLDS,
    TENANT_THRESHOLDS,
)

TENANT_ID = "18d9dec0-d762-11ec-9cb5-00155da09878"
SUBSCRIPTION_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


def _mock_subscription(tenant_id=TENANT_ID, subscription_id=SUBSCRIPTION_ID):
    return SimpleNamespace(
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        display_name="test-sub",
        id=f"/subscriptions/{subscription_id}",
        state="Enabled",
    )


def _build_labeler():
    """Create an AzureEnergyLabeler with all Azure calls mocked."""
    mock_credential = MagicMock()
    sub = _mock_subscription()
    # SubscriptionClient is imported in two modules, so both references must
    # be patched.  Using a shared mock avoids duplicating the setup.
    shared_sub_client = MagicMock()
    shared_sub_client.return_value.subscriptions.list.return_value = [sub]

    with (
        patch(
            "azureenergylabelerlib.azureenergylabelerlib.SubscriptionClient",
            shared_sub_client,
        ),
        patch(
            "azureenergylabelerlib.entities.SubscriptionClient",
            shared_sub_client,
        ),
    ):
        labeler = AzureEnergyLabeler(
            tenant_id=TENANT_ID,
            credentials=mock_credential,
        )
    return labeler


class TestAzureEnergyLabelerInit(unittest.TestCase):
    """Verify AzureEnergyLabeler initialises with correct defaults."""

    def setUp(self):
        self.labeler = _build_labeler()

    def test_tenant_thresholds_default(self):
        self.assertEqual(self.labeler.tenant_thresholds, TENANT_THRESHOLDS)

    def test_subscription_thresholds_default(self):
        self.assertEqual(self.labeler.subscription_thresholds, SUBSCRIPTION_THRESHOLDS)

    def test_resource_group_thresholds_default(self):
        self.assertEqual(
            self.labeler.resource_group_thresholds, RESOURCE_GROUP_THRESHOLDS
        )

    def test_matching_frameworks(self):
        self.assertEqual(
            set(self.labeler.matching_frameworks),
            DEFAULT_DEFENDER_FOR_CLOUD_FRAMEWORKS,
        )

    def test_tenant_has_one_subscription(self):
        self.assertEqual(len(self.labeler.tenant.subscriptions), 1)

    def test_denied_resource_group_names_default_empty(self):
        self.assertEqual(self.labeler.denied_resource_group_names, [])


if __name__ == "__main__":
    unittest.main()
