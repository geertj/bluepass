#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import math
import os.path

from bluepass.crypto import CryptoProvider
from bluepass.factory import instance

__all__ = ('PasswordGenerator',)


class PasswordGenerator(object):
    """Password generator.
    
    This generator supports two password formats:

      * "random"

        The password is generated as a fixed number of characters randomly
        taken from a set of characters. The set of characters can be specified
        using regular expression style character ranges e.g. "[a-z0-9_]".

        This is the method used by default for generating individual passwords.

     * "diceware"

        The password is generated according to the "Diceware(tm)" method. See:
        http://world.std.com/~reinhold/diceware.html for more information.
        Diceware passphrases provide rememberable and extremely good
        passphrases.
        
        This method is used by default for vault passwords.
    """

    def __init__(self):
        """Create a new PasswordGenerator."""
        self.crypto = instance(CryptoProvider)
        self._load_wordlist()

    def _expand_alphabet(self, alphabet):
        """Expand all regular expression style character ranges
        (e.g. "[a-z0-9]") in the string `alphabet`."""
        s_start, s_set, s_try_start_range, s_end_range = range(4)
        result = []
        startchar = endchar = None
        state = s_start
        for ch in alphabet:
            if state == s_start:
                if ch == '[':
                    state = s_set
                else:
                    result.append(ch)
            elif state == s_set:
                if ch == ']':
                    state = s_start
                else:
                    startchar = ch
                    state = s_try_start_range
            elif state == s_try_start_range:
                if ch == '-':
                    state = s_end_range
                elif ch == ']':
                    result.append(startchar)
                    state = s_start
                else:
                    state = s_set
                    result.append(startchar)
            elif state == s_end_range:
                if ch == ']':
                    result.append(startchar)
                    result.append('-')
                    state = s_start
                else:
                    endchar = ch
                    for nr in range(ord(startchar), ord(endchar)+1):
                        result.append(chr(nr))
                    state = s_set
        if state != s_start:
            raise ValueError('Illegal alphabet specification')
        return result

    def _load_wordlist(self):
        """Load the Diceware wordlist."""
        pkgdir, modname = os.path.split(__file__)
        fname = os.path.join(pkgdir, 'data', 'diceware.wordlist.asc')
        fin = open(fname)
        wordlist = []
        for line in fin:
            if line[:5].isdigit() and line[5:6] == '\t':
                key, value = line.split()
                wordlist.append(value)
        fin.close()
        self.wordlist = wordlist

    def generate_random(self, size, alphabet=None):
        """Generate a random password, consisting of `size` characters
        from the alphabet `alphabet`.
        """
        if alphabet:
            alphabet = self._expand_alphabet(alphabet)
        password = self.crypto.random(size, alphabet)
        return password

    def strength_random(self, size, alphabet=None):
        """Return the strength of a random password."""
        if alphabet:
            alphabet = self._expand_alphabet(alphabet)
            nchars = len(alphabet)
        else:
            nchars = 255
        strength = int(math.log(nchars ** size, 2))
        return strength

    def generate_diceware(self, words):
        """Generate a Diceware passwords of `words` words."""
        password = self.crypto.random(words, self.wordlist, ' ')
        return password

    def strength_diceware(self, words):
        """Return the strength of a Diceware password."""
        strength = int(math.log(6.0 ** (5*words), 2))
        return strength

    def generate(self, method, *args, **kwargs):
        """Generate a password."""
        if method == 'random':
            return self.generate_random(*args, **kwargs)
        elif method == 'diceware':
            return self.generate_diceware(*args, **kwargs)
        else:
            raise ValueError('Unknown method: %s' % method)

    def strength(self, method, *args, **kwargs):
        if method == 'random':
            return self.strength_random(*args, **kwargs)
        elif method == 'diceware':
            return self.strength_diceware(*args, **kwargs)
        else:
            raise ValueError('Unknown method: %s' % method)
