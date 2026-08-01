---
name: skill-installer
description: Install skills and agents from the AMD SLAI Marketplace into $CODEX_HOME/skills. Use when a user asks to list installable skills, install a skill, or browse available marketplace assets.
metadata:
  short-description: Install skills and agents from the AMD SLAI Marketplace
---

# Skill Installer

Helps install skills and agents from the AMD SLAI Marketplace hosted on Artifactory. No GitHub access is required — assets are downloaded directly from the AMD internal Artifactory instance.

Use the helper scripts based on the task:
- List available assets when the user asks what is available, or if the user uses this skill without specifying what to do.
- Install a specific skill or agent when the user provides a name.

## Communication

When listing skills, output approximately as follows:
"""
Skills and agents from AMD SLAI Marketplace:
1. skill-1
2. skill-2 [agent]
3. ...
4. skill-4 (already installed)
Which ones would you like installed?
"""

After installing a skill, tell the user: "Restart Codex to pick up new skills."

## Scripts

All of these scripts use the network to reach AMD Artifactory, so when running in the sandbox, request escalation when running them.

- `scripts/list-skills.py` (prints skills list with installed annotations)
- `scripts/list-skills.py --format json`
- `scripts/install-skill-from-github.py <asset-name>` (install from Artifactory)
- `scripts/install-skill-from-github.py <asset1> <asset2>` (install multiple)
- `scripts/install-skill-from-github.py <asset-name> --name <custom-name>` (custom directory name)

## Behavior and Options

- Downloads assets directly from AMD Artifactory (no authentication required).
- Aborts if the destination skill directory already exists.
- Installs into `$CODEX_HOME/skills/<skill-name>` (defaults to `./.codex/skills`).
- Multiple asset names can be specified to install in one run.
- Options: `--dest <path>`, `--name <name>`.

## Notes

- Asset listing is fetched from the AMD Artifactory manifest. If it is unavailable, explain the error and exit.
- Both skills and agents from the marketplace are available for installation.
- Installed annotations come from `$CODEX_HOME/skills`.
- The `slai-marketplace` CLI tool can also be used directly: `uvx --index https://atlartifactory.amd.com:8443/artifactory/api/pypi/SW-SLAI-PROD-LOCAL/simple slai-marketplace list`
