"""Tests for semantic parameter classification."""

from horcrux.intel.parameters import (
    ParameterSemanticRole,
    classify_parameter,
    is_static_asset_endpoint,
)


def test_classify_parameter_roles():
    assert classify_parameter("id") == ParameterSemanticRole.OBJECT_ID
    assert classify_parameter("basket_id") == ParameterSemanticRole.OBJECT_ID
    assert classify_parameter("userId") == ParameterSemanticRole.USER_ID
    assert classify_parameter("redirect") == ParameterSemanticRole.REDIRECT_URL
    assert classify_parameter("url") == ParameterSemanticRole.TARGET_URL
    assert classify_parameter("q") == ParameterSemanticRole.SEARCH_QUERY
    assert classify_parameter("query", "/rest/products/search") == ParameterSemanticRole.SEARCH_QUERY
    assert classify_parameter("file") == ParameterSemanticRole.FILE_PATH
    assert classify_parameter("quantity") == ParameterSemanticRole.BUSINESS_LOGIC
    assert classify_parameter("price") == ParameterSemanticRole.BUSINESS_LOGIC
    assert classify_parameter("role") == ParameterSemanticRole.PRIVILEGE_ROLE
    assert classify_parameter("token") == ParameterSemanticRole.AUTH_TOKEN
    assert classify_parameter("sort") == ParameterSemanticRole.SORT_ORDER
    assert classify_parameter("unknown_custom_foo") == ParameterSemanticRole.GENERIC_INPUT


def test_is_static_asset_endpoint():
    assert is_static_asset_endpoint("/polyfills.js") is True
    assert is_static_asset_endpoint("/main.js") is True
    assert is_static_asset_endpoint("/styles.css") is True
    assert is_static_asset_endpoint("/rest/products/search") is False
    assert is_static_asset_endpoint("/api/Feedbacks") is False
