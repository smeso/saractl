"""
    saractl - S.A.R.A.'s userspace utilities.
    Copyright (C) 2017  Salvatore Mesoraca <s.mesoraca16@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from collections import Counter
from collections.abc import Iterable
from functools import total_ordering
from itertools import chain
import logging
import struct


SARA_DFA_VERSION = 2


@total_ordering
class DictKey(object):
    def __init__(self, obj, *args):
        self.obj = {'path': obj[0], 'exact': obj[2]}

    def __gt__(self, other):
        if len(self.obj['path']) < len(other.obj['path']):
            return False
        elif len(self.obj['path']) > len(other.obj['path']):
            return True
        else:
            if self.obj['exact'] == other.obj['exact']:
                return self.obj['path'] < other.obj['path']
            elif self.obj['exact']:
                return False
            else:
                return True

    def __eq__(self, other):
        return self.obj['path'] == other.obj['path'] and \
            self.obj['exact'] == other.obj['exact']


class DFA:

    NR = 255

    def __init__(self, encoding='UTF-8', encoding_error='strict'):
        self.encoding = encoding
        self.encoding_error = encoding_error
        self.init()

    def init(self):
        self.dfa = []
        self.outputs = []
        self.star = {}
        self.compressed_tables = {}
        self.__add_state()

    def __add_state(self, loop=-1, o=-1):
        self.dfa.append([loop] * self.NR)
        self.outputs.append(o)

    def __add_state_match_all(self, value, target=None):
        if target is None:
            i = len(self.dfa)
        else:
            i = target
        self.dfa.append([i] * self.NR)
        self.outputs.append(value)
        return i

    def __is_match_all(self, n):
        j = list(set(self.dfa[n]))
        if len(j) == 1 and j[0] == n:
            return True
        return False

    def add_string(self, s, value, prefix=False):
        i = 0
        prevl = -1
        prevo = -1
        #s = s.encode(self.encoding, self.encoding_error)
        for c in s:
            c -= 1
            n = self.dfa[i][c]
            if i in self.star:
                prevl = self.star[i]
                prevo = self.outputs[n]
            if n >= 0 and not self.__is_match_all(n):
                i = n
                continue
            self.__add_state(prevl, prevo)
            self.dfa[i][c] = len(self.dfa) - 1
            i = len(self.dfa) - 1
        if prefix:
            n = self.__add_state_match_all(self.outputs[i])
            for k, v in enumerate(self.dfa[i]):
                if v == -1 or v == prevl:
                    self.dfa[i][k] = n
            self.outputs[n] = value
            self.star[i] = n
        self.outputs[i] = value

    def add_strings(self, ss):
        ss = ss[:]
        ss.sort(key=DictKey)
        for s in ss:
            self.add_string(s[0], s[1], s[2])

    def finalize(self):
        d = {}
        for i, v in enumerate(self.dfa):
            d[i] = v
        self.dfa = d
        d = {}
        for i, v in enumerate(self.outputs):
            d[i] = v
        self.outputs = d

    def __del_unreachable(self):
        s = set()
        for v in self.dfa.values():
            s.update(v)
        s = list(s.symmetric_difference(self.dfa.keys()))
        s.remove(0)
        try:
            s.remove(-1)
        except ValueError:
            pass
        for e in s:
            del self.dfa[e]

    def __del_pass_all(self):
        t = {}
        for k, v in list(self.dfa.items()):
            j = set(v)
            if len(j) == 1:
                j = list(j)[0]
                if j != k and j != -1 and self.outputs[k] == self.outputs[j] and self.__is_match_all(j):
                    if j in t:
                        j = t[j]
                    t[k] = j
                    del self.dfa[k]
                    del self.outputs[k]
        for k, v in self.dfa.items():
            for i, e in enumerate(v):
                if e in t:
                    self.dfa[k][i] = t[e]

    def __del_identical(self):
        t = {}
        f = {}
        for k, v in self.dfa.items():
            v = ','.join(str(x) for x in v) + ',' + str(self.outputs[k])
            if v in f:
                t[k] = f[v]
            else:
                f[v] = k
        for k in t:
            del self.dfa[k]
            del self.outputs[k]
        for k, v in self.dfa.items():
            for i, e in enumerate(v):
                if e in t:
                    self.dfa[k][i] = t[e]

    def __remap_sid(self):
        translate = {x[1]: x[0] for x in enumerate(self.dfa.keys())}
        translate[-1] = -1
        d = {}
        for k, v in self.dfa.items():
            d[translate[k]] = [translate[x] for x in v]
        self.dfa = d
        d = {}
        for k, v in self.outputs.items():
            d[translate[k]] = v
        self.outputs = d

    def simplify(self):
        self.__del_unreachable()
        self.__del_pass_all()
        self.__del_identical()
        self.__remap_sid()

    def __are_mergeable(self, idlist):
        values = [self.dfa[k] for k in idlist]
        defaults = [self.compressed_tables['default'][k] for k in idlist]
        for l in zip(*values):
            c = 0
            for a, b in zip(l, defaults):
                if a != b:
                    c += 1
                if c > 1:
                    return False
        return True

    def __merge_states(self, idlist):
        assert len(idlist)
        assert self.__are_mergeable(idlist)
        n, c = [], []
        for i in range(self.NR):
            for j in idlist:
                if self.dfa[j][i] != self.compressed_tables['default'][j]:
                    break
            n.append(self.dfa[j][i])
            c.append(j)
        return n, c

    def make_compressed_tables(self, debug=False):
        self.compressed_tables = {'default': [], 'base': [], 'next': [], 'check': [], 'outputs': []}
        for v in self.dfa.values():
            self.compressed_tables['default'].append(max(Counter(v).items(), key=lambda x: x[1])[0])
        groups = []
        for i in range(len(self.dfa)):
            analized = set(chain.from_iterable(groups))
            if i in analized:
                continue
            analized.add(i)
            group = [i]
            nexts = set(self.dfa[i])
            if -1 in nexts:
                nexts.remove(-1)
            nexts.difference_update(analized)
            analized.update(nexts)
            while nexts:
                for j in nexts:
                    if self.__are_mergeable(group+[j]):
                        group.append(j)
                old_nexts = nexts
                nexts = set()
                for k in old_nexts:
                    nexts.update(self.dfa[k])
                if -1 in nexts:
                    nexts.remove(-1)
                nexts.difference_update(analized)
                analized.update(nexts)
            groups.append(group)
        merged = True
        while merged:
            merged = False
            old_groups = groups
            groups = []
            while old_groups:
                to_del = []
                group = old_groups.pop()
                for i, g in enumerate(old_groups[:]):
                    if self.__are_mergeable(group+g):
                        group.extend(g)
                        to_del.append(i)
                        merged = True
                for d in sorted(to_del, reverse=True):
                    del old_groups[d]
                groups.append(group)
        b, nl, cl = {}, [], []
        for i, g in enumerate(groups):
            n, c = self.__merge_states(g)
            nl.append(n)
            cl.append(c)
            for e in g:
                b[e] = i
        self.compressed_tables['next'] = nl
        self.compressed_tables['check'] = cl
        self.compressed_tables['base'] = [b[i] for i in range(len(b))]
        self.compressed_tables['outputs'] = [self.outputs[i] for i in range(len(self.outputs))]
        if debug:
            return groups

    def build(self, ss, debug=False):
        self.init()
        self.add_strings(ss)
        self.finalize()
        self.simplify()
        g = self.make_compressed_tables(debug=debug)
        if debug:
            return g

    def serialize(self, ha):
        assert len(self.dfa) < (2**32-1)
        assert len(ha) == 20
        output = b'SARADFAT'
        snum = len(self.compressed_tables['default'])
        output += struct.pack('<I', SARA_DFA_VERSION)
        output += struct.pack('<L', snum)
        output += struct.pack('<L', len(self.compressed_tables['next']))
        output += ha
        for L in chain(self.compressed_tables['default'],
                       self.compressed_tables['base'],
                       chain.from_iterable(self.compressed_tables['next']),
                       chain.from_iterable(self.compressed_tables['check']),
                       self.compressed_tables['outputs']):
            if L == -1:
                L = 2**32-1
            output += struct.pack('<L', L)
        return output

    def deserialize(self, b, ha=None):
        assert b[:8] == b'SARADFAT'
        version = struct.unpack('<I', b[8:12])[0]
        assert version == SARA_DFA_VERSION
        snum = struct.unpack('<L', b[12:16])[0]
        snumn = struct.unpack('<L', b[16:20])[0]
        if ha is not None:
            assert b[20:40] == ha
        compressed_tables = {'default': [], 'base': [], 'next': [], 'check': [], 'outputs': []}
        i = 40
        for _ in range(snum):
            L = struct.unpack('<L', b[i:i+4])[0]
            if L == 2**32-1:
                L = -1
            compressed_tables['default'].append(L)
            i += 4
        for _ in range(snum):
            L = struct.unpack('<L', b[i:i+4])[0]
            if L == 2**32-1:
                L = -1
            compressed_tables['base'].append(L)
            i += 4
        for _ in range(snumn):
            l = []
            for _ in range(self.NR):
                L = struct.unpack('<L', b[i:i+4])[0]
                if L == 2**32-1:
                    L = -1
                l.append(L)
                i += 4
            compressed_tables['next'].append(l)
        for _ in range(snumn):
            l = []
            for _ in range(self.NR):
                L = struct.unpack('<L', b[i:i+4])[0]
                if L == 2**32-1:
                    L = -1
                l.append(L)
                i += 4
            compressed_tables['check'].append(l)
        for _ in range(snum):
            L = struct.unpack('<L', b[i:i+4])[0]
            if L == 2**32-1:
                L = -1
            compressed_tables['outputs'].append(L)
            i += 4
        return compressed_tables

    def compare_lists(self, a, b):
        if len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if isinstance(x, Iterable):
                if not self.compare_lists(x, y):
                    return False
            elif x != y:
                return False
        return True

    def compare_tables(self, a, b):
        for k in ('default', 'base', 'next', 'check', 'outputs'):
            if not self.compare_lists(a[k], b[k]):
                return False
        return True

    def match(self, s):
        i = 0
        #s = s.encode(self.encoding, self.encoding_error)
        for c in s:
            c -= 1
            n = self.dfa[i][c]
            if n >= 0:
                i = n
            else:
                return False, None
        if self.outputs[i] >= 0:
            return True, self.outputs[i]
        return False, None

    def match_compressed_tables(self, s):
        i = 0
        #s = s.encode(self.encoding, self.encoding_error)
        for c in s:
            c -= 1
            if self.compressed_tables['check'][self.compressed_tables['base'][i]][c] == i:
                n = self.compressed_tables['next'][self.compressed_tables['base'][i]][c]
            else:
                n = self.compressed_tables['default'][i]
            if n >= 0:
                i = n
            else:
                return False, None
        if self.outputs[i] >= 0:
            return True, self.outputs[i]
        return False, None

def dfa_malformed_test(b):
    try:
        with open('/sys/kernel/security/sara/dfa_test/.load', 'wb') as f:
            f.write(b)
        return False
    except OSError:
        return True

def dfa_kernel_test():
    for i, t in enumerate(TEST_SETS):
        d = DFA()
        d.build(t)
        s = d.serialize(b'\xAA'*20)
        with open('/sys/kernel/security/sara/dfa_test/.load', 'wb') as f:
            f.write(s)
        for t1 in t:
            for t2 in t1[3]:
                with open('/sys/kernel/security/sara/dfa_test/test', 'wb') as f:
                    f.write(t2[0])
                with open('/sys/kernel/security/sara/dfa_test/result', 'rb') as f:
                    result = int(f.read().strip())
                    if t2[1]:
                        if result != t1[1]:
                            logging.error('DFA test: {} {}'.format(i, t2[0]))
                            return False
                    else:
                        if result != 0xffffffff:
                            logging.error('DFA test: {} {}'.format(i, t2[0]))
                            return False
    for i, b in enumerate(MALFORMED_TESTS):
        if not dfa_malformed_test(b):
            logging.error('DFA malformed test: {}'.format(i))
            return False
    return True

MALFORMED_TESTS = [b'idjsdg',
                   b'SARADFAT\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARZDFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1019 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1019 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1019 + b'\x00'*1019 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1021 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1021 + b'\x00'*1021 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1021 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x0f'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\x00' + b'\x0f'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\xf0\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARADFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\x0f\xff\xff\xff\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARZDFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\xff\x00\x00\x00\xf0' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00',
                   b'SARZDFAT\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xfe\x03^\xed\xf9\xa1\xea\x97wx_%;[ZN\xc3\x84\xec\xe7\xff\xff\xff\x0f\x00\x00\x00\x00' + b'\xff'*1020 + b'\x00'*1020 + b'\x0f\x00\x00\x00']

TEST_SETS = [[(b'/qwlz/', 1, False, [(b'/qw', False),
                                     (b'/qwlz/', True),
                                     (b'/qwlz', False),
                                     (b'/sigo/', False)]),
              (b'/pep', 2, True, [(b'/pe', False),
                                  (b'/pep', True),
                                  (b'/pepe', True),
                                  (b'/pepe/dgfh', True),
                                  (b'/sigo/', False)]),
              (b'/pedp/dg', 3, True, [(b'/pedp/dg', True),
                                      (b'/p/usg', False),
                                      (b'/dijfsg', False),
                                      (b'/pedp/dgdokfsg', True),
                                      (b'/sigo/', False),
                                      (b'/pedp/dg/qwlzh', True),
                                      (b'/pedp/dg/qwl', True)]),
              (b'/pedp/dg/qwlz', 4, False, [(b'/pedp/dg/qwlz', True),
                                            (b'/sigo/', False)]),
              (b'/zio/dg/', 5, False, [(b'/zio/dg/', True),
                                       (b'/sigo/', False)]),
              (b'/zio/', 6, True, [(b'/zio/dg/34', True),
                                   (b'/zio/dg/dg/', True),
                                   (b'/sigo/', False)]),
              (b'/zio/', 7, False, [(b'/zio/', True)])],
             [(b'/aa/f', 1, True, [(b'/aa', False)]),
              (b'/aa/', 3, True, [(b'/aa', False)]),
              (b'/aa/', 2, False, [(b'/aa/', True)])],
             [(b'/aa/', 3, True, [(b'/aa', False)]),
              (b'/aa/', 2, False, [(b'/aa/', True)]),
              (b'/aa/f', 1, True, [(b'/aa', False)])],
             [(b'', 1, True, [(b'/', True),
                              (b'', True),
                              (b'asuhfdf', True),])],
             [(b'', 1, True, [(b'/', True),
                              (b'', True)]),
              (b'asu', 2, True, [(b'asuhfdf', True)])],
             [(b'/jgokd/', 1, True, [(b'/jgokd/', True),
                                     (b'/jgok', False),
                                     (b'/jgokd/dfh', True),
                                     (b'/jgokd/pksfg', True),
                                     (b'/jgokd/pksfgz', True),
                                     (b'/jgokd/pksfgh/dijk', True),
                                     (b'/jgokd/pksfgh/dijk/usg', True),
                                     (b'/jgokd/pksfgh/', True)]),
              (b'/jgokd/pksfgh', 2, False, [(b'/jgokd/pksfgh', True)]),
              (b'/jgokd/pksfgh/dijg', 3, True, [(b'/jgokd/pksfgh/dijg', True),
                                                (b'/jgokd/pksfgh/dijg/ijsg', True),
                                                (b'/jgokd/pksfgh/dijg/', True),
                                                (b'/jgokd/pksfgh/dijg//', True),
                                                (b'/jgokd/pksfgh/dijg/usg', True),
                                                (b'/jgokd/pksfgh/dijg/ufhok', True),
                                                (b'/jgokd/pksfgh/dijg/ufhokk', True),
                                                (b'/jgokd/pksfgh/dijg/ufhokd/ijsdg', True)]),
              (b'/jgokd/pksfgh/dijg/ufhokh', 4, True, [(b'/jgokd/pksfgh/dijg/ufhokh', True),
                                                       (b'/jgokd/pksfgh/dijg/ufhokh/ijsdg', True),
                                                       (b'/jgokd/pksfgh/dijg/ufhokhf', True),
                                                       (b'/jgokd/pksfgh/dijg/ufhokh/f', True),
                                                       ]),
              (b'/jg\xc3\xb2kd/pksfgh/dijg/ufhokh', 5, True, [(b'/jg\xc3\xb2kd/pksfgh/dijg/ufhokh', True),
                                                              (b'/jg\xc3\xb2kd/pksfgh/dijg/ufhokh/ijsdg', True),
                                                              (b'/jg\xc3\xb2kd/pksfgh/dijg/ufhokhf', True),
                                                              (b'/jg\xc3\xb2kd/pksfgh/dijg/ufhokh/f', True)])]]
