#!/usr/bin/env python
#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.
#
# This script calculates the strength of the Diceware(r) passphrases we
# generate under our PBKDF2 key derivation algorithm for various adversaries.
# The model takes into account Moore's law and contains a few tunable knobs.

import sys
import math

# Keys per year for one core. Assume only 10 keys per second due
# to the key stretching that is employed.
a = 10*86400*365
# Moore's law exponent: the 18-month variant
b = math.log(2) / 1.5
# Our adversaries with the # of cores they have available
adversaries = [(10, 'Home User'), (10000, 'Organized Crime'),
               (10000000, 'Govt Agency')]

def format_years(y):
    if y < 1.0/365/24/60:
        return '%.2f seconds' % (1.0 * y * 365 * 24 * 60 * 60)
    elif y < 1.0/365/24:
        return '%.2f minutes' % (1.0 * y * 365 * 24 * 60)
    elif y < 1.0/365:
        return '%.2f hours' % (1.0 * y * 365 * 24)
    elif y < 1.0:
        return '%.2f days' % (1.0 * y * 365)
    elif y < 10.0:
        return '%.2f years' % y
    elif y < 100.0:
        return '%.1f years' % y
    else:
        return '%.0f years' % y

rows = [['Words', 'Bits'] + [adv[1] for adv in adversaries]]

for keysize in range(1,7):
    keys = 6 ** (5 * keysize)
    bits = math.log(keys, 2)
    line = [str(keysize), str('%.2f' % bits)]
    for adv in adversaries:
        nkeys = 0
        for yr in range(1,1000):
            speed = adv[0] * a * math.exp(b*yr)
            nkeys += speed
            if nkeys > keys/2:
                tdesc = format_years(1.0 * yr * keys / 2 / nkeys)
                break
        else:
            tdesc = '> 1.000 years'
        line.append(tdesc)
    rows.append(line)

ncols = 2 + len(adversaries)
colsize = [0] * ncols
for row in rows:
    for ix in range(ncols):
        colsize[ix] = max(colsize[ix], len(row[ix]))
fmt = [ '%%-%ds' % sz for sz in colsize ]

print '  '.join(fmt[i] % rows[0][i] for i in range(ncols))
print '  '.join('-' * colsize[i] for i in range(ncols))
for row in rows[1:]:
    print '  '.join(fmt[i] % row[i] for i in range(ncols))
