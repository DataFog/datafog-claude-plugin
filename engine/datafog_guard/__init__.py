"""DataFog guard: keeps personal data and credentials out of the model's context in Claude Code.

Values found in tool output are replaced by reversible markers such as
``[[EMAIL_ABC123]]`` before the model sees them, and markers are swapped back
to the real values locally when the agent writes.
"""

__version__ = "0.2.1"

# The detector. 1.5.0 and 1.6.0 have an email-detection regression (core #266); 1.7.0 fixed it.
CORE_REQUIREMENT = "datafog-core==1.7.0"
# The encrypted vault (datafog_fogvault.ApplicationVault). Released together with core; compiled
# wheels exist for macOS arm64, Linux x86_64 (glibc 2.38+) and Windows x64 only.
VAULT_REQUIREMENT = "datafog-fogvault==1.7.0"
APP_ID = "claude-code"
