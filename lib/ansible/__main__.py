# Copyright: (c) 2021, Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import annotations

import argparse
import importlib
import os
import sys
import types
from typing import Callable

from importlib.metadata import distribution, Distribution, EntryPoint


def _short_name(name: str) -> str:
    return name.removeprefix('ansible-').replace('ansible', 'adhoc')


def main() -> None:
    dist: Distribution = distribution('ansible-core')
    ep_map: dict[str, EntryPoint] = {_short_name(ep.name): ep for ep in dist.entry_points if ep.group == 'console_scripts'}

    parser: argparse.ArgumentParser = argparse.ArgumentParser(prog='python -m ansible', add_help=False)
    parser.add_argument('entry_point', choices=list(ep_map) + ['test'])
    args, extra = parser.parse_known_args()

    mainprime: Callable[..., None]

    if args.entry_point == 'test':
        ansible_root: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        source_root: str= os.path.join(ansible_root, 'test', 'lib')

        if os.path.exists(os.path.join(source_root, 'ansible_test', '_internal', '__init__.py')):
            # running from source, use that version of ansible-test instead of any version that may already be installed
            sys.path.insert(0, source_root)

        module: types.ModuleType = importlib.import_module('ansible_test._util.target.cli.ansible_test_cli_stub')
        mainprime = module.main
    else:
        mainprime = ep_map[args.entry_point].load()

    mainprime([args.entry_point] + extra)


if __name__ == '__main__':
    main()
