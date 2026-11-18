"""DataFog guard: keeps personal data and credentials out of the model's context in Claude Code.

Values found in tool output are replaced by reversible markers such as
``[[EMAIL_ABC123]]`` before the model sees them, and markers are swapped back
to the real values locally when the agent writes.
"""

__version__ = "0.2.0.dev0"

# The only runtime dependency. 1.5.0 has a known email-detection regression.
CORE_REQUIREMENT = "datafog-core>=1.4.0,<1.5"
APP_ID = "claude-code"
