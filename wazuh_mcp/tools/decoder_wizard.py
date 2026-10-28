"""Decoder Wizard — aggregator entry point.

Mirrors ``rule_wizard.py``: a single ``register(ctx)`` that wires the decoder
validation and generation tools. Splitting keeps each concern in its own module
while the server's auto-discovery only needs one ``register``.

Tools registered:
    validate_decoder_xml    (decoder_wizard_validate)
    generate_decoder_xml    (decoder_wizard_generate)

All tools are NON-MUTATING (analyst role) — they never write to or restart the
Manager. Deployment stays manual via push_custom_decoder / push_custom_rule.
"""
from __future__ import annotations

from ..rbac import ROLE
from ..tool_context import ToolContext
from .decoder_wizard_validate import register_validate, _validate_decoder_xml_impl  # noqa: F401
from .decoder_wizard_generate import register_generate

REQUIRED_ROLE = ROLE.ANALYST


def register(ctx: ToolContext) -> None:
    register_validate(ctx)
    register_generate(ctx)
