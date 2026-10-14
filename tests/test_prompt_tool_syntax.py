"""The instructions vhir writes for other clients (LibreChat and the like)
carry sift-mcp's paragraph on tool syntax, verbatim."""

from vhir_cli.commands.client_setup import _PROMPT_PREFIX

TOOL_SYNTAX = (
    "TOOL SYNTAX: Before building a tool's command line, call get_tool_help"
    " (get_windows_tool_help on Windows) and use a recipe for the installed version,"
    " or the tool's own help. Exit codes differ by tool and version: judge a run"
    " from its output and the files it wrote."
)


def test_the_prompt_says_how_to_find_a_tools_syntax():
    assert TOOL_SYNTAX in _PROMPT_PREFIX.split("\n\n")
