"""Allow `python -m fossrisk`."""
import sys

from .cli import main

sys.exit(main())
