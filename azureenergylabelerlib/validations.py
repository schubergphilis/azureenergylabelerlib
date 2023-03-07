#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: validations.py
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
Main code for validations.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import logging
from urllib.parse import urlparse
from .azureenergylabelerlibexceptions import (InvalidSubscriptionListProvided,
                                              MutuallyExclusiveArguments,
                                              InvalidPath)
from .configuration import SUBSCRIPTION_ID_LENGTH

__author__ = '''Sayantan Khanra <skhanra@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''22-04-2022'''
__copyright__ = '''Copyright 2022, Sayantan Khanra'''
__credits__ = ["Sayantan Khanra"]
__license__ = '''MIT'''
__maintainer__ = '''Sayantan Khanra'''
__email__ = '''<skhanra@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''validations'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


def is_valid_subscription_id(subscription_id):
    """Checks whether a provided subscription_id is a valid Azure subscription id.

    Args:
        subscription_id (str): A subscription id string.

    Returns:
        True if the provided value is a valid Azure subscription id, false otherwise.

    """
    if not isinstance(subscription_id, str):
        return False
    return len(subscription_id) == SUBSCRIPTION_ID_LENGTH


def are_valid_subscription_ids(subscription_ids):
    """Checks whether a provided list of subscription ids contains all valid Azure subscription ids.

    Args:
        subscription_ids (list): A list of subscription id strings.

    Returns:
        True if the provided list contains all valid Azure subscription ids, false otherwise.

    """
    if not isinstance(subscription_ids, (list, tuple, set)):
        return False
    return all(is_valid_subscription_id(subscription) for subscription in subscription_ids)


def validate_subscription_ids(subscription_ids):
    """Validates a provided string or iterable that it contains valid Azure subscription ids.

    Args:
        subscription_ids: A string or iterable of strings with Azure subscription ids.

    Returns:
        subscription_ids (list): A list of valid Azure subscription ids.

    Raises:
        InvalidSubscriptionIdProvided: If any of the provided Subscription ids is not a valid Azure subscription id.

    """
    if subscription_ids is None:
        return []
    if not isinstance(subscription_ids, (list, tuple, set, str)):
        raise InvalidSubscriptionListProvided(f'Only list, tuple, set or string of subscriptions are accepted input, '
                                              f'received: {subscription_ids}')
    if is_valid_subscription_id(subscription_ids):
        subscription_ids = [subscription_ids]
    subscription_ids = sorted(list({subscription_id for subscription_id in subscription_ids if subscription_id}))
    if not are_valid_subscription_ids(subscription_ids):
        raise InvalidSubscriptionListProvided(
            f'The list provided contains invalid subscription ids: {subscription_ids}')
    return subscription_ids


def validate_allowed_denied_subscription_ids(allowed_subscription_ids=None, denied_subscription_ids=None):
    """Validates provided allow and deny subscription id lists.

    Not both arguments can contain values as they are logically mutually exclusive. The validations process also
    validates that the arguments contain valid subscription id values if provided.

    Args:
        allowed_subscription_ids (str|iterable): A single or multiple subscription id to validate,
            mutually exclusive with the deny list
        denied_subscription_ids (str|iterable): A single or multiple subscription id to validate,
            mutually exclusive with the allow list

    Returns:
        allowed_subscription_ids, denied_subscription_ids: A tuple of list values with valid subscription ids

    Raises:
        MutuallyExclusiveArguments: If both arguments contain values.
        InvalidSubscriptionListProvided: If any of the provided ids in the list is not a valid subscription id.

    """
    if all([allowed_subscription_ids, denied_subscription_ids]):
        raise MutuallyExclusiveArguments('allowed_subscription_ids and denied_subscription_ids are mutually exclusive.')
    return validate_subscription_ids(allowed_subscription_ids), validate_subscription_ids(denied_subscription_ids)


class DestinationPath:
    """Models a destination path and identifies if it is valid and it's type."""

    def __init__(self, location):
        self.location = location
        self._parsed_url = urlparse(location)
        self._blob_conditions = ["blob.core.windows.net" in self._parsed_url.netloc,
                                 len(self._parsed_url.path) >= 1]
        self._local_conditions = [self._parsed_url.scheme == "",
                                  self._parsed_url.netloc == "",
                                  len(self._parsed_url.path) >= 1]

    def is_valid(self):
        """Is the path valid."""
        return all(self._blob_conditions) or all(self._local_conditions)

    @property
    def type(self):
        """The type of the path."""
        if all(self._blob_conditions):
            return 'blob'
        if all(self._local_conditions):
            return 'local'
        raise InvalidPath(self.location)
