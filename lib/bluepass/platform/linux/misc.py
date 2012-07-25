#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os

def get_machine_info():
    """Return a tuple (hostname, os, arch, cores, cpu_speed, memory)."""
    osname, hostname, dummy, dummy, arch = os.uname()
    cores = 0
    fin = file('/proc/cpuinfo')
    for line in fin:
        line = line.strip()
        if not line:
            continue
        label, value = line.split(':')
        label = label.strip(); value = value.strip()
        if label == 'processor':
            cores += 1
    fin.close()
    fin = file('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq')
    cpu_speed = int(fin.readline().strip()) / 1000
    fin.close()
    memory = 0
    fin = file('/proc/meminfo')
    for line in fin:
        line = line.strip()
        if not line:
            continue
        label, value = line.split(':')
        label = label.strip(); value = value.strip()
        if label == 'MemTotal':
            value = value.rstrip('kB')
            memory = int(value) / 1000
            break
    return (hostname, osname, arch, cores, cpu_speed, memory)
