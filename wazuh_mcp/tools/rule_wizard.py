"""F7: Custom Detection Rules Wizard — re-exports from focused sub-modules.

Tools:
    generate_rule_xml                 (rule_wizard_generate)
    validate_rule_xml                 (rule_wizard_validate)
    push_custom_rule                  (rule_wizard_deploy)
    push_custom_decoder               (rule_wizard_deploy)
    convert_sigma_rule                (rule_wizard_generate)
    sigma_bulk_import                 (rule_wizard_deploy)
    sigma_coverage_gap                (rule_wizard_generate)
    test_sigma_rule_against_archive   (rule_wizard_validate)
    suggest_rule_tuning               (rule_wizard_validate)
"""
from __future__ import annotations
from ..tool_context import ToolContext

from .rule_wizard_generate import register_generate, _sigma_to_wazuh_level, _extract_sigma_field_conditions  # noqa: F401
from .rule_wizard_validate import register_validate, _validate_rule_xml_impl  # noqa: F401
from .rule_wizard_deploy import register_deploy  # noqa: F401


def register(ctx: ToolContext) -> None:
    register_generate(ctx)
    register_validate(ctx)
    register_deploy(ctx)
