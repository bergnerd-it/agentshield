#!/usr/bin/env python3
"""Reset script for AgentShield demo environment."""

import os
import shutil
import sys
from pathlib import Path

DEFAULT_DEMO_DIR = Path.home() / ".agentshield-demo"
demo_dir = Path(os.environ.get("AGENTSHIELD_DEMO_DIR", str(DEFAULT_DEMO_DIR))).resolve()

# Strict safety guards: refuse to delete dangerous or non-demo directories
forbidden_targets = {
    Path("/").resolve(),
    Path.home().resolve(),
    Path.cwd().resolve(),
    Path.cwd().parent.resolve(),
}

if demo_dir in forbidden_targets:
    sys.stderr.write(f"ERROR: Refusing to reset dangerous target directory: {demo_dir}\n")
    sys.exit(1)

if not demo_dir.name.startswith((".agentshield-demo", "agentshield-demo", ".demo-", "agentshield_demo_")):
    sys.stderr.write(f"ERROR: Target directory name does not appear to be a demo directory: {demo_dir}\n")
    sys.exit(1)

if demo_dir.exists():
    print(f"Cleaning up demo data directory: {demo_dir}")
    shutil.rmtree(demo_dir)
    print("Demo directory successfully removed.")
else:
    print(f"Demo directory does not exist: {demo_dir} (already clean)")
