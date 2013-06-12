#!/usr/bin/env python
#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.
#
# This script outputs the first and second "Oakley" groups from RFC2409
# in base64 encoded PKCS#3 "DHParameter" format. These groups are used in
# the Freedestop secrets service.
#
# The keys can be found in section 6.1 and 6.2 in the RFC here:
# http://www.ietf.org/rfc/rfc2409.txt

from pyasn1.codec.der import encoder
from pyasn1.type.univ import Sequence, Integer
from pyasn1.type.namedtype import NamedTypes, NamedType


oakley1 = """
         FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
         29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
         EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
         E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
        """
oakley2 = """
         FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
         29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
         EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
         E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
         EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
         FFFFFFFF FFFFFFFF
        """

class DHParameter(Sequence):
    componentType = NamedTypes(
        NamedType('prime', Integer()),
        NamedType('base', Integer()))

def format_asn1(hexfmt):
    s = hexfmt.replace(' ', '').replace('\n', '')
    i = int(s, 16)
    params = DHParameter()
    params.setComponentByName('prime', i)
    params.setComponentByName('base', 2)
    return encoder.encode(params).encode('base64').rstrip()

print 'Oakley #1:'
print format_asn1(oakley1)
print

print 'Oakley #2:'
print format_asn1(oakley2)
print
