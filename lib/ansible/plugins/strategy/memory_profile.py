# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    strategy: memory_profile
    short_description: Executes tasks as linear would, but monkey patches in
                       various memory profiling logic
    description:
        - Task execution is 'linear' but with memory profiling information
    version_added: "2.5"
    author: Adam Miller <admiller@redhat.com>
'''

import uuid
import tempfile

from ansible.plugins.strategy.linear import StrategyModule as LinearStrategyModule

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

from ansible.executor.play_iterator import PlayIterator

try:
    from memory_profiler import profile
except ImportError:
    display.error("Python module memory_profile not found, but is required for memory profiling strategy")

# Short uuid to log to
play_uuid = uuid.uuid4().hex[:6]
mem_profile_log = tempfile.mktemp(prefix="ansible-memeory-profile-")
fd_mem_profile_log = open(mem_profile_log, "w+")
display.display("Memory Profile data file: {}".format(mem_profile_log))

original_add_tasks = PlayIterator.add_tasks


@profile(precision=2, stream=fd_mem_profile_log)
def add_tasks(self, host, task_list):
    """
    monkey patch in a custom add_tasks for the task of profiling the memory
    on each call
    """
    original_add_tasks(self, host, task_list)


# Re-assign PlayIterator functions we want
PlayIterator.add_tasks = add_tasks


class StrategyModule(LinearStrategyModule):
    def __init__(self, tqm):
        self.curr_tqm = tqm
        super(StrategyModule, self).__init__(tqm)

