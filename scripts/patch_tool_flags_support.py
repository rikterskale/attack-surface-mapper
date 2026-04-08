#!/usr/bin/env python3
"""Apply --tool-flags support to attack_surface_mapper.py.

This patcher is idempotent and inserts:
- CLI argument: --tool-flags (repeatable TOOL=FLAGS)
- parse_tool_flags() helper using shlex.split
- main() integration that validates/applies flags safely
"""

from pathlib import Path

TARGET = Path("attack_surface_mapper.py")


def apply_patch() -> None:
    text = TARGET.read_text(encoding="utf-8")
    original = text

    if "import shlex" not in text:
        text = text.replace("import re\n", "import re\nimport shlex\n", 1)

    arg_block = '''    parser.add_argument(
        "--tool-flags",
        action="append",
        dest="tool_flags",
        metavar="TOOL=FLAGS",
        default=None,
        help=(
            "Extra flags for a tool (repeatable). "
            'Example: --tool-flags "nmap=-Pn -n -sS -T3"'
        ),
    )
'''
    if '"--tool-flags"' not in text:
        anchor = '    parser.add_argument("--verbose", "-v", action="store_true")\n'
        text = text.replace(anchor, arg_block + anchor, 1)

    helper = '''\n\ndef parse_tool_flags(items: Optional[List[str]]) -> Dict[str, List[str]]:
    """Parse repeatable --tool-flags entries into {tool_name: [flags...]}.

    Input format is ``TOOL=FLAGS`` (repeatable). Flags are shell-split using
    :func:`shlex.split` so quoted values are preserved.
    """
    parsed: Dict[str, List[str]] = {}
    if not items:
        return parsed

    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid --tool-flags entry '{item}' (expected TOOL=FLAGS)")

        tool_name, flags_str = item.split("=", 1)
        tool_name = tool_name.strip()
        if not tool_name:
            raise ValueError(f"Invalid --tool-flags entry '{item}' (tool name is empty)")

        try:
            flags = [f.strip() for f in shlex.split(flags_str) if f.strip()]
        except ValueError as e:
            raise ValueError(f"Invalid --tool-flags entry '{item}': {e}") from e

        parsed.setdefault(tool_name, []).extend(flags)

    return parsed
'''
    if "def parse_tool_flags(" not in text:
        text = text.replace("\n\nasync def main():\n", helper + "\n\nasync def main():\n", 1)

    main_block = '''    # Optional per-tool flag overrides from CLI (repeatable).
    try:
        user_tool_flags = parse_tool_flags(args.tool_flags)
    except ValueError as e:
        logger.error("invalid_tool_flags", error=str(e))
        print(f"\\u274c Error: {e}")
        sys.exit(1)

    for tool_name, flags in user_tool_flags.items():
        tool = registry.tools.get(tool_name)
        if not tool:
            logger.error("unknown_tool_in_tool_flags", tool=tool_name)
            print(f"\\u274c Error: Unknown tool in --tool-flags: '{tool_name}'")
            sys.exit(1)
        tool.extra_flags.extend(flags)
        logger.info("tool_flags_applied", tool=tool_name, flags=flags)

'''
    if "tool_flags_applied" not in text:
        anchor = "    policy = PolicyEngine(args.policy)\n    registry = ToolRegistry(policy)\n\n"
        text = text.replace(anchor, anchor + main_block, 1)

    if text != original:
        TARGET.write_text(text, encoding="utf-8")
        print("[updated] attack_surface_mapper.py")
    else:
        print("[ok] attack_surface_mapper.py already contains --tool-flags support")


if __name__ == "__main__":
    apply_patch()