"""
SCP Loader — reads, validates, and compiles AWS Service Control Policies from
JSON files. Validates size constraints, required fields, and Effect values.
Raises SCPValidationError with descriptive details on any failure.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCP_MAX_SIZE_CHARS = 5120
VALID_EFFECTS = frozenset({"Allow", "Deny"})


class SCPValidationError(Exception):
    """Raised when an SCP policy fails structural or size validation."""

    def __init__(self, message: str, policy_file: str = "", statement_idx: int = -1):
        self.policy_file = policy_file
        self.statement_idx = statement_idx
        location = f" [{policy_file}]" if policy_file else ""
        stmt_loc = f" statement[{statement_idx}]" if statement_idx >= 0 else ""
        super().__init__(f"SCP validation error{location}{stmt_loc}: {message}")


class SCPLoader:
    """Loads, validates, and compiles AWS Service Control Policy JSON files."""

    def load_policy(self, filepath: str) -> dict:
        """
        Read an SCP JSON file and validate it. Returns the parsed policy dict.

        Validates:
          - File exists and is valid JSON
          - Total size <= 5120 characters
          - Has a 'Version' field
          - Has a 'Statement' field that is a non-empty list
          - Each statement has Effect (Allow|Deny), Action (list or str), Resource
        """
        path = Path(filepath)
        if not path.exists():
            raise SCPValidationError(f"File not found: {filepath}", filepath)
        if not path.is_file():
            raise SCPValidationError(f"Path is not a file: {filepath}", filepath)

        raw_text = path.read_text(encoding="utf-8")

        if len(raw_text) > SCP_MAX_SIZE_CHARS:
            raise SCPValidationError(
                f"File size {len(raw_text)} characters exceeds the AWS SCP limit of "
                f"{SCP_MAX_SIZE_CHARS} characters.",
                filepath,
            )

        try:
            policy = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise SCPValidationError(
                f"Invalid JSON: {exc}", filepath
            ) from exc

        self._validate_policy_structure(policy, filepath)
        logger.debug("Loaded and validated SCP from %s", filepath)
        return policy

    def _validate_policy_structure(self, policy: dict, source: str) -> None:
        if not isinstance(policy, dict):
            raise SCPValidationError("Top-level policy must be a JSON object.", source)

        if "Version" not in policy:
            raise SCPValidationError(
                "Missing required field 'Version'. Expected '2012-10-17'.", source
            )

        statements = policy.get("Statement")
        if statements is None:
            raise SCPValidationError("Missing required field 'Statement'.", source)

        if not isinstance(statements, list):
            raise SCPValidationError(
                f"'Statement' must be a list, got {type(statements).__name__}.", source
            )

        if len(statements) == 0:
            raise SCPValidationError("'Statement' list must not be empty.", source)

        for idx, stmt in enumerate(statements):
            self._validate_statement(stmt, source, idx)

    def _validate_statement(self, stmt: dict, source: str, idx: int) -> None:
        if not isinstance(stmt, dict):
            raise SCPValidationError(
                f"Statement must be a JSON object, got {type(stmt).__name__}.", source, idx
            )

        effect = stmt.get("Effect")
        if effect not in VALID_EFFECTS:
            raise SCPValidationError(
                f"'Effect' is '{effect}'; must be one of {sorted(VALID_EFFECTS)}.", source, idx
            )

        action = stmt.get("Action") or stmt.get("NotAction")
        if action is None:
            raise SCPValidationError(
                "Statement must contain 'Action' or 'NotAction'.", source, idx
            )
        if not isinstance(action, (list, str)):
            raise SCPValidationError(
                f"'Action' must be a string or list, got {type(action).__name__}.", source, idx
            )
        if isinstance(action, list):
            if len(action) == 0:
                raise SCPValidationError("'Action' list must not be empty.", source, idx)
            for act in action:
                if not isinstance(act, str):
                    raise SCPValidationError(
                        f"Each action must be a string, got {type(act).__name__}.", source, idx
                    )

        resource = stmt.get("Resource") or stmt.get("NotResource")
        if resource is None:
            raise SCPValidationError(
                "Statement must contain 'Resource' or 'NotResource'.", source, idx
            )

    def load_all(self, directory: str) -> dict[str, Any]:
        """
        Load all *.json files from a directory.
        Returns {stem_name: policy_dict}. Raises SCPValidationError on first failure.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            raise SCPValidationError(f"Directory not found: {directory}")

        policies: dict[str, Any] = {}
        json_files = sorted(dir_path.glob("*.json"))

        if not json_files:
            logger.warning("No SCP JSON files found in %s", directory)
            return policies

        for json_file in json_files:
            name = json_file.stem
            policies[name] = self.load_policy(str(json_file))
            logger.info("Loaded SCP '%s' from %s", name, json_file.name)

        return policies

    def compile_scp(self, policy_dict: dict) -> str:
        """
        Validate and serialize a policy dict to a compact JSON string ready
        for the boto3 organizations client. Verifies size after serialization.
        """
        if not isinstance(policy_dict, dict):
            raise SCPValidationError("compile_scp expects a dict, not %s." % type(policy_dict).__name__)

        self._validate_policy_structure(policy_dict, "<in-memory>")

        compiled = json.dumps(policy_dict, separators=(",", ":"), ensure_ascii=True)

        if len(compiled) > SCP_MAX_SIZE_CHARS:
            raise SCPValidationError(
                f"Compiled SCP is {len(compiled)} characters, which exceeds the "
                f"{SCP_MAX_SIZE_CHARS}-character AWS limit. Reduce the number of actions or statements."
            )

        return compiled

    def compile_all(self, policy_dicts: dict[str, Any]) -> dict[str, str]:
        """Compile a mapping of {name: policy_dict} into {name: compact_json_string}."""
        return {name: self.compile_scp(policy) for name, policy in policy_dicts.items()}

# _r 20260522161807-55502d30
