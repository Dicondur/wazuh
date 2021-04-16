#!/usr/bin/env python
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

from wazuh.tests.util import InitWDBSocketMock

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.mitre import *

# Tactics variables
TACTICS_FIELDS = {'id': 'id', 'name': 'name', 'description': 'description', 'short_name': 'short_name',
                  'created_time': 'created_time', 'modified_time': 'modified_time'}
TACTICS_RELATION_FIELDS = {'related_techniques'}
TACTICS_MIN_SELECT_FIELDS = {'id'}
TACTICS_TABLE_NAME = 'tactic'


@patch('wazuh.core.utils.WazuhDBConnection')
def test_WazuhDBQueryMitre_metadata(mock_wdb):
    """Verify that the method connects correctly to the database and returns the correct type."""
    mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql')
    db_query = WazuhDBQueryMitreMetadata()
    data = db_query.run()

    assert isinstance(db_query, WazuhDBQueryMitre) and isinstance(data, dict)


@patch('wazuh.core.utils.WazuhDBConnection')
def test_WazuhDBQueryMitreTactics(mock_wdb):
    """Test WazuhDBQueryMitreTactics class methods."""
    # Test WazuhDBQueryMitre is called with the appropriate table
    with patch('wazuh.core.mitre.WazuhDBQueryMitre.__init__') as mitre_init_mock:
        WazuhDBQueryMitreTactics()
        args, kwargs = mitre_init_mock.call_args
        assert kwargs.get('table') == TACTICS_TABLE_NAME

    # Verify that the method connects correctly to the database and returns the correct types.
    mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql')
    db_query = WazuhDBQueryMitreTactics()
    assert db_query.fields == TACTICS_FIELDS and db_query.relation_fields == TACTICS_RELATION_FIELDS and isinstance(
        db_query, WazuhDBQueryMitre)

    data = db_query.run()
    assert isinstance(data, dict)
    try:
        assert all([isinstance(data['items'][0][related_item], list) for related_item in TACTICS_RELATION_FIELDS])
    except KeyError:
        pytest.fail("Related item not found in data obtained from query")


@patch('wazuh.core.utils.WazuhDBConnection')
def test_get_tactics(mock_wdb):
    """Test get_tactics function."""
    info, data = get_tactics()

    assert isinstance(info['allowed_fields'], set) and info['allowed_fields'] == set(TACTICS_FIELDS.keys()).union(
        TACTICS_RELATION_FIELDS)
    assert isinstance(info['min_select_fields'], set) and info['min_select_fields'] == TACTICS_MIN_SELECT_FIELDS

    assert isinstance(data, dict)
