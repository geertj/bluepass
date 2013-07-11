#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
from subprocess import Popen, PIPE


def get_machine_info():
    """Return a tuple (hostname, os, arch, cores, cpu_speed, memory)."""
    osname, hostname, dummy, dummy, arch = os.uname()
    cores = 0
    process = Popen(['sysctl', 'hw.availcpu'], stdout=PIPE)
    stdout, stderr = process.communicate()
    status = process.poll()
    if status:
        cores = 1
    else:
        cores = int(stdout.split()[-1])
    process = Popen(['sysctl', 'hw.cpufrequency_max'], stdout=PIPE)
    stdout, stderr = process.communicate()
    status = process.poll()
    if status:
        cpu_speed = 0
    else:
        cpu_speed = int(stdout.split()[-1]) / 1000000
    process = Popen(['sysctl', 'hw.memsize'], stdout=PIPE)
    stdout, stderr = process.communicate()
    status = process.poll()
    if status:
        memory = 0
    else:
        memory = int(stdout.split()[-1]) / 1000000
    return (hostname, osname, arch, cores, cpu_speed, memory)
