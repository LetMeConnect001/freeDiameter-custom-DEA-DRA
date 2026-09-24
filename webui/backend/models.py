"""
Data model for a friendly-named rt_rewrite rule.

Maps 1:1 onto what extensions/rt_rewrite actually supports (verified directly against
rt_rewrite_conf.y, not guessed): MAP (move a value from one AVP to another, dropping the
source), DROP (remove an AVP), ADD (insert a fixed-value AVP for a given command), and an
optional single IF condition comparing a named VARIABLE (itself bound to an AVP path) against a
literal value.

Oracle DSR's action set (diameter-manip, group-manip, find-replace-all, store) has no
documented-enough semantics to replicate faithfully and no direct equivalent in rt_rewrite as it
stands -- this model intentionally only exposes what can actually be generated and will actually
work against the real parser.
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, field_validator

COMPARISON_OPERATORS = ("<", "<=", "=", ">=", ">")


class RuleType(str, Enum):
    MOVE = "move"      # MAP
    DELETE = "delete"  # DROP
    ADD = "add"        # ADD


class Condition(BaseModel):
    """An IF clause: IF "<variable>" <operator> "<value>" prefixing a MOVE/DELETE/ADD."""
    variable_avp_path: List[str]  # e.g. ["Service-Information", "IMS-Information", "Role-Of-Node"]
    operator: str
    value: str

    @field_validator("operator")
    @classmethod
    def operator_must_be_valid(cls, v: str) -> str:
        if v not in COMPARISON_OPERATORS:
            raise ValueError(f"operator must be one of {COMPARISON_OPERATORS}")
        return v

    @field_validator("variable_avp_path")
    @classmethod
    def path_not_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("variable_avp_path must have at least one AVP name")
        return v


class Rule(BaseModel):
    id: Optional[int] = None
    name: str                      # friendly label shown in the UI list, not used in the generated config
    type: RuleType
    enabled: bool = True

    # MOVE: both required. DELETE: source_avp_path required, dest_avp_path unused.
    source_avp_path: Optional[List[str]] = None
    dest_avp_path: Optional[List[str]] = None

    # ADD only: the command (message type) this rule applies to, e.g. "Credit-Control-Request",
    # and the fixed value to write into dest_avp_path.
    command_name: Optional[str] = None
    value: Optional[str] = None

    condition: Optional[Condition] = None

    @field_validator("source_avp_path", "dest_avp_path")
    @classmethod
    def path_not_empty_if_set(cls, v):
        if v is not None and not v:
            raise ValueError("AVP path, if provided, must have at least one element")
        return v

    def validate_for_type(self) -> None:
        """Cross-field validation that depends on `type`. Called explicitly (not a pydantic
        validator) because it needs to see the whole object after all fields are set."""
        if self.type == RuleType.MOVE:
            if not self.source_avp_path or not self.dest_avp_path:
                raise ValueError("move rules require both source_avp_path and dest_avp_path")
        elif self.type == RuleType.DELETE:
            if not self.source_avp_path:
                raise ValueError("delete rules require source_avp_path")
        elif self.type == RuleType.ADD:
            if not self.command_name:
                raise ValueError("add rules require command_name (the message type this applies to)")
            if not self.dest_avp_path:
                raise ValueError("add rules require dest_avp_path (where to add the AVP)")
            if self.value is None:
                raise ValueError("add rules require a value")
