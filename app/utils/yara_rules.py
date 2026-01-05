"""YARA rule management utilities."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RuleInfo:
    """Information about a YARA rule file."""

    path: str
    name: str
    description: str
    author: str
    category: str
    rule_count: int
    tags: list[str]

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "category": self.category,
            "rule_count": self.rule_count,
            "tags": self.tags,
        }


class YARARuleManager:
    """Manages YARA rules: listing, importing, and organizing."""

    def __init__(self, rules_base_dir: str | None = None):
        """
        Initialize rule manager.

        Args:
            rules_base_dir: Base directory for YARA rules.
                           Defaults to app/data/yara
        """
        if rules_base_dir:
            self._base_dir = Path(rules_base_dir)
        else:
            self._base_dir = Path(__file__).parent.parent / "data" / "yara"

        self._custom_dir = self._base_dir / "custom"
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Ensure rule directories exist."""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._custom_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        """Get base rules directory."""
        return self._base_dir

    @property
    def custom_dir(self) -> Path:
        """Get custom rules directory."""
        return self._custom_dir

    def list_rules(self) -> list[RuleInfo]:
        """
        List all available YARA rules.

        Returns:
            List of RuleInfo objects.
        """
        rules = []

        for ext in ["*.yar", "*.yara"]:
            for rule_file in self._base_dir.rglob(ext):
                info = self._parse_rule_file(rule_file)
                if info:
                    rules.append(info)

        return sorted(rules, key=lambda r: r.name)

    def _parse_rule_file(self, path: Path) -> RuleInfo | None:
        """
        Parse a YARA rule file to extract metadata.

        Args:
            path: Path to rule file.

        Returns:
            RuleInfo or None if parsing fails.
        """
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        # Count rules (simple heuristic: count "rule " declarations)
        rule_count = content.count("\nrule ") + (1 if content.startswith("rule ") else 0)

        # Extract metadata from comments at top
        description = ""
        author = ""
        tags = []

        for line in content.split("\n")[:20]:  # Check first 20 lines
            line = line.strip()
            if line.startswith("//") or line.startswith("/*"):
                clean = line.lstrip("/*").lstrip("/").strip()
                if clean.lower().startswith("description:"):
                    description = clean[12:].strip()
                elif clean.lower().startswith("author:"):
                    author = clean[7:].strip()
                elif clean.lower().startswith("tags:"):
                    tags = [t.strip() for t in clean[5:].split(",")]

        # Determine category from path
        category = "default"
        if "custom" in str(path):
            category = "custom"
        elif "malware" in str(path).lower():
            category = "malware"
        elif "suspicious" in str(path).lower():
            category = "suspicious"
        elif "filetype" in str(path).lower():
            category = "filetype"

        return RuleInfo(
            path=str(path),
            name=path.stem,
            description=description or f"YARA rules from {path.name}",
            author=author or "Unknown",
            category=category,
            rule_count=rule_count,
            tags=tags,
        )

    def import_rules(self, source_path: str, category: str = "custom") -> tuple[bool, str]:
        """
        Import YARA rules from a file or directory.

        Args:
            source_path: Path to rule file or directory.
            category: Category subdirectory to import into.

        Returns:
            Tuple of (success, message).
        """
        source = Path(source_path)
        if not source.exists():
            return False, f"Source not found: {source_path}"

        target_dir = self._custom_dir if category == "custom" else self._base_dir / category
        target_dir.mkdir(parents=True, exist_ok=True)

        imported = 0

        if source.is_file():
            if source.suffix not in [".yar", ".yara"]:
                return False, "Invalid file extension. Must be .yar or .yara"

            # Validate rule syntax
            if not self._validate_rule_file(source):
                return False, "Invalid YARA rule syntax"

            target = target_dir / source.name
            shutil.copy2(source, target)
            imported = 1

        elif source.is_dir():
            for ext in ["*.yar", "*.yara"]:
                for rule_file in source.rglob(ext):
                    if self._validate_rule_file(rule_file):
                        target = target_dir / rule_file.name
                        shutil.copy2(rule_file, target)
                        imported += 1

        if imported == 0:
            return False, "No valid YARA rules found"

        return True, f"Imported {imported} rule file(s)"

    def _validate_rule_file(self, path: Path) -> bool:
        """
        Validate YARA rule syntax.

        Args:
            path: Path to rule file.

        Returns:
            True if valid.
        """
        try:
            import yara

            yara.compile(filepath=str(path))
            return True
        except ImportError:
            # If yara not available, do basic validation
            try:
                content = path.read_text()
                return "rule " in content
            except Exception:
                return False
        except Exception:
            return False

    def delete_custom_rule(self, rule_name: str) -> tuple[bool, str]:
        """
        Delete a custom rule file.

        Args:
            rule_name: Name of rule file (without extension).

        Returns:
            Tuple of (success, message).
        """
        for ext in [".yar", ".yara"]:
            rule_path = self._custom_dir / f"{rule_name}{ext}"
            if rule_path.exists():
                try:
                    rule_path.unlink()
                    return True, f"Deleted {rule_name}"
                except OSError as e:
                    return False, f"Failed to delete: {e}"

        return False, f"Rule not found: {rule_name}"

    def get_rule_content(self, rule_name: str) -> str | None:
        """
        Get content of a rule file.

        Args:
            rule_name: Name of rule file.

        Returns:
            Rule content or None.
        """
        for ext in ["*.yar", "*.yara"]:
            for rule_file in self._base_dir.rglob(ext):
                if rule_file.stem == rule_name:
                    try:
                        return rule_file.read_text()
                    except OSError:
                        return None
        return None

    def export_rules(self, output_path: str, include_custom: bool = True) -> tuple[bool, str]:
        """
        Export all rules to a directory.

        Args:
            output_path: Target directory.
            include_custom: Whether to include custom rules.

        Returns:
            Tuple of (success, message).
        """
        output = Path(output_path)
        output.mkdir(parents=True, exist_ok=True)

        exported = 0
        for ext in ["*.yar", "*.yara"]:
            for rule_file in self._base_dir.rglob(ext):
                if not include_custom and "custom" in str(rule_file):
                    continue
                target = output / rule_file.name
                shutil.copy2(rule_file, target)
                exported += 1

        return True, f"Exported {exported} rule files to {output_path}"

    def get_statistics(self) -> dict[str, Any]:
        """
        Get statistics about loaded rules.

        Returns:
            Statistics dictionary.
        """
        rules = self.list_rules()

        total_rules = sum(r.rule_count for r in rules)
        by_category = {}
        for r in rules:
            by_category[r.category] = by_category.get(r.category, 0) + r.rule_count

        return {
            "total_files": len(rules),
            "total_rules": total_rules,
            "by_category": by_category,
            "categories": list(set(r.category for r in rules)),
        }


def get_default_rules_dir() -> Path:
    """Get the default YARA rules directory."""
    return Path(__file__).parent.parent / "data" / "yara"


def ensure_default_rules():
    """Ensure default YARA rules are available."""
    rules_dir = get_default_rules_dir()
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "custom").mkdir(exist_ok=True)
    return rules_dir
