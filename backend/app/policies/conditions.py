# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Evaluate policy `when` expressions."""

from __future__ import annotations

import ast
import re

from app.policies.context import PolicyContext

_COMPARISON = re.compile(
    r"^(input\.length|estimated_cost)\s*(>|<|>=|<=|==)\s*([\d.]+)$"
)
_USER_ROLE = re.compile(
    r'^user\.role\s*(==|!=)\s*["\']([^"\']+)["\']$'
)
_CATEGORY_EQ = re.compile(
    r'^input\.category\s*(==|!=)\s*["\']([^"\']+)["\']$'
)
_CATEGORY_IN = re.compile(
    r"^input\.category\s+in\s+(\[[^\]]*\])$"
)
_AND_SPLIT = re.compile(r"\s+and\s+", flags=re.IGNORECASE)


def evaluate_condition(when: str, context: PolicyContext) -> bool:
    expression = when.strip()
    if not expression:
        raise ValueError("Empty policy condition")

    parts = [part.strip() for part in _AND_SPLIT.split(expression) if part.strip()]
    if len(parts) > 1:
        return all(_evaluate_atomic(part, context) for part in parts)
    return _evaluate_atomic(expression, context)


def _evaluate_atomic(expression: str, context: PolicyContext) -> bool:
    if expression == "input.contains_secret":
        return context.contains_secret

    if expression == "input.contains_private_key":
        return context.contains_private_key

    if expression == "input.contains_injection":
        return context.contains_injection

    if expression == "input.contains_jailbreak":
        return context.contains_jailbreak

    if expression == "output.contains_secret":
        return context.output_contains_secret

    role_match = _USER_ROLE.match(expression)
    if role_match:
        operator, expected = role_match.groups()
        actual = context.user_role
        if operator == "==":
            return actual == expected
        return actual != expected

    category_eq = _CATEGORY_EQ.match(expression)
    if category_eq:
        operator, expected = category_eq.groups()
        matched = expected in context.categories or context.category == expected
        if operator == "==":
            return matched
        return not matched

    category_in = _CATEGORY_IN.match(expression)
    if category_in:
        values = _parse_string_list(category_in.group(1))
        return bool(context.categories.intersection(values)) or (
            context.category in values if context.category else False
        )

    match = _COMPARISON.match(expression)
    if match:
        left_name, operator, raw_value = match.groups()
        left_value = (
            float(context.input_length)
            if left_name == "input.length"
            else context.estimated_cost
        )
        right_value = float(raw_value)
        return _compare(left_value, operator, right_value)

    raise ValueError(f"Unsupported policy condition: {expression}")


def _parse_string_list(raw: str) -> set[str]:
    try:
        parsed = ast.literal_eval(raw)
    except (SyntaxError, ValueError) as exc:
        raise ValueError(f"Invalid category list: {raw}") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError(f"Invalid category list: {raw}")
    return set(parsed)


def _compare(left: float, operator: str, right: float) -> bool:
    if operator == ">":
        return left > right
    if operator == "<":
        return left < right
    if operator == ">=":
        return left >= right
    if operator == "<=":
        return left <= right
    if operator == "==":
        return left == right
    raise ValueError(f"Unsupported operator: {operator}")
