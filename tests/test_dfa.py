from itertools import chain
from unittest import TestCase

from sara.DFA import DFA, TEST_SETS


class TestDFA(TestCase):

    def __test_set(self, s):
        d = DFA()
        groups = d.build(s, debug=True)
        groups = list(chain.from_iterable(groups))
        self.assertTrue(len(groups) == len(set(groups)))
        self.assertTrue(len(groups) == len(d.dfa))
        self.assertTrue(min(groups) == 0)
        self.assertTrue(max(groups) == len(groups) - 1)
        if len(d.dfa) > 1:
            self.assertTrue((len(d.compressed_tables['next'])*2+2)*100/len(d.dfa) < 100)
        for m in s:
            for k in m[3]:
                r = d.match(k[0])
                r2 = d.match_compressed_tables(k[0])
                self.assertTrue(r[0] == k[1])
                if r[0]:
                    self.assertTrue(r[1] == m[1])
                r2 = d.match_compressed_tables(k[0])
                self.assertTrue(r[0] == r2[0])
                self.assertTrue(r[1] == r2[1])

    def __test_serialization(self, t):
        d = DFA()
        d.build(t)
        ha = b'\xAA'*20
        s = d.serialize(ha)
        i = d.deserialize(s)
        self.assertTrue(d.compare_tables(d.compressed_tables, i))

    def test_big1(self):
        for t in TEST_SETS:
            self.__test_set(t)

    def test_serialization(self):
        for t in TEST_SETS:
            self.__test_serialization(t)
