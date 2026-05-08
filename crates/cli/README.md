# wafrift-cli

Command-line interface for the WAF Rift evasion toolkit.

The CLI builds standalone by default and is part of the workspace. Gossan-dependent origin bypass behavior is isolated behind the `gossan-integration` feature name so normal builds, tests, and metadata generation do not require a sibling gossan checkout or path dependency.

Run `wafrift --help` for available commands.
