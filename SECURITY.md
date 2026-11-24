# Security policy

claude-guard is a guard, so a way past it is a security bug. Please report it privately, not in a public issue.

## Reporting

Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a
vulnerability**. Only the maintainer sees the report.

Include:

- the claude-guard version (`claude-guard --version`);
- the subcommand and the hook input JSON that gets through (or crashes, hangs or logs what it shouldn't);
- what you expected and what happened.

Never put a real secret, key, token or personal ID number in a report. Build a fake one that has the right shape,
the way the tests do.

This is a one-maintainer project: replies are best effort, and a fix ships as a new release with a note in the
release text once it's out.

## What counts

- A command, file read, prompt or URL that a guard should block (by the rules in the README) but lets through.
- Input that crashes a guard, makes it hang, or makes it slow enough to time out (a timed-out hook doesn't block).
- A log line that holds what the README says is never logged (command text, file contents, query strings, prompt
  text, blocked names).
- A problem with the release artifacts or their build provenance.

## What doesn't

- The gaps the README lists under "What it doesn't cover" (scripts that fetch on their own, `!` commands, tools the
  guards don't know, IP addresses at the DNS layer). claude-guard catches mistakes and common traps; it isn't a
  sandbox. Run Claude Code's sandbox and permission rules as well.
- A rule you'd like changed (stricter or looser): open a normal issue.

## Supported versions

Only the latest release gets fixes.

## Checking a release

Every release binary has a `.sha256` file and GitHub build provenance. See "Verify a release" in the README.
