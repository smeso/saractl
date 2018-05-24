from hashlib import sha1
from itertools import combinations, permutations
from unittest import TestCase

from sara.submodules import wxprot


OK_FLAGS = {0: {'NONE'},
            8: {'WXORX'},
            9: {'WXORX', 'HEAP'},
            10: {'WXORX', 'STACK'},
            11: {'WXORX', 'HEAP', 'STACK'},
            12: {'OTHER', 'WXORX'},
            13: {'OTHER', 'WXORX', 'HEAP'},
            14: {'OTHER', 'WXORX', 'STACK'},
            15: {'WXORX', 'MPROTECT'},
            24: {'WXORX', 'COMPLAIN'},
            25: {'WXORX', 'HEAP', 'COMPLAIN'},
            26: {'WXORX', 'COMPLAIN', 'STACK'},
            27: {'WXORX', 'HEAP', 'COMPLAIN', 'STACK'},
            28: {'OTHER', 'WXORX', 'COMPLAIN'},
            29: {'OTHER', 'WXORX', 'HEAP', 'COMPLAIN'},
            30: {'OTHER', 'WXORX', 'COMPLAIN', 'STACK'},
            31: {'WXORX', 'MPROTECT', 'COMPLAIN'},
            40: {'WXORX', 'VERBOSE'},
            41: {'WXORX', 'HEAP', 'VERBOSE'},
            42: {'WXORX', 'VERBOSE', 'STACK'},
            43: {'WXORX', 'HEAP', 'VERBOSE', 'STACK'},
            44: {'OTHER', 'WXORX', 'VERBOSE'},
            45: {'OTHER', 'WXORX', 'HEAP', 'VERBOSE'},
            46: {'OTHER', 'WXORX', 'VERBOSE', 'STACK'},
            47: {'WXORX', 'VERBOSE', 'MPROTECT'},
            56: {'WXORX', 'VERBOSE', 'COMPLAIN'},
            57: {'WXORX', 'HEAP', 'VERBOSE', 'COMPLAIN'},
            58: {'WXORX', 'VERBOSE', 'COMPLAIN', 'STACK'},
            59: {'WXORX', 'HEAP', 'VERBOSE', 'STACK', 'COMPLAIN'},
            60: {'OTHER', 'WXORX', 'VERBOSE', 'COMPLAIN'},
            61: {'OTHER', 'WXORX', 'HEAP', 'VERBOSE', 'COMPLAIN'},
            62: {'OTHER', 'WXORX', 'VERBOSE', 'COMPLAIN', 'STACK'},
            63: {'WXORX', 'VERBOSE', 'MPROTECT', 'COMPLAIN'},
            76: {'OTHER', 'WXORX', 'MMAP'},
            77: {'OTHER', 'WXORX', 'HEAP', 'MMAP'},
            78: {'OTHER', 'WXORX', 'STACK', 'MMAP'},
            79: {'FULL'},
            92: {'OTHER', 'WXORX', 'COMPLAIN', 'MMAP'},
            93: {'OTHER', 'WXORX', 'HEAP', 'COMPLAIN', 'MMAP'},
            94: {'OTHER', 'WXORX', 'COMPLAIN', 'STACK', 'MMAP'},
            95: {'COMPLAIN', 'FULL'},
            108: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP'},
            109: {'OTHER', 'WXORX', 'HEAP', 'VERBOSE', 'MMAP'},
            110: {'OTHER', 'WXORX', 'VERBOSE', 'STACK', 'MMAP'},
            111: {'VERBOSE', 'FULL'},
            124: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'COMPLAIN'},
            125: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'HEAP', 'COMPLAIN'},
            126: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'COMPLAIN', 'STACK'},
            127: {'VERBOSE', 'COMPLAIN', 'FULL'},
            271: {'EMUTRAMP', 'WXORX', 'MPROTECT'},
            287: {'EMUTRAMP', 'WXORX', 'MPROTECT', 'COMPLAIN'},
            303: {'EMUTRAMP', 'WXORX', 'VERBOSE', 'MPROTECT'},
            319: {'WXORX', 'VERBOSE', 'MPROTECT', 'EMUTRAMP', 'COMPLAIN'},
            335: {'EMUTRAMP', 'FULL'},
            351: {'FULL', 'EMUTRAMP', 'COMPLAIN'},
            367: {'VERBOSE', 'FULL', 'EMUTRAMP'},
            383: {'VERBOSE', 'FULL', 'EMUTRAMP', 'COMPLAIN'},
            512: {'NONE', 'TRANSFER'},
            520: {'WXORX', 'TRANSFER'},
            521: {'WXORX', 'HEAP', 'TRANSFER'},
            522: {'WXORX', 'STACK', 'TRANSFER'},
            523: {'WXORX', 'HEAP', 'STACK', 'TRANSFER'},
            524: {'OTHER', 'WXORX', 'TRANSFER'},
            525: {'OTHER', 'WXORX', 'HEAP', 'TRANSFER'},
            526: {'OTHER', 'WXORX', 'STACK', 'TRANSFER'},
            527: {'WXORX', 'MPROTECT', 'TRANSFER'},
            536: {'WXORX', 'COMPLAIN', 'TRANSFER'},
            537: {'WXORX', 'HEAP', 'COMPLAIN', 'TRANSFER'},
            538: {'WXORX', 'COMPLAIN', 'STACK', 'TRANSFER'},
            539: {'WXORX', 'HEAP', 'COMPLAIN', 'STACK', 'TRANSFER'},
            540: {'OTHER', 'WXORX', 'COMPLAIN', 'TRANSFER'},
            541: {'OTHER', 'WXORX', 'HEAP', 'COMPLAIN', 'TRANSFER'},
            542: {'OTHER', 'WXORX', 'COMPLAIN', 'STACK', 'TRANSFER'},
            543: {'WXORX', 'MPROTECT', 'COMPLAIN', 'TRANSFER'},
            552: {'WXORX', 'VERBOSE', 'TRANSFER'},
            553: {'WXORX', 'HEAP', 'VERBOSE', 'TRANSFER'},
            554: {'WXORX', 'VERBOSE', 'STACK', 'TRANSFER'},
            555: {'WXORX', 'HEAP', 'VERBOSE', 'STACK', 'TRANSFER'},
            556: {'OTHER', 'WXORX', 'VERBOSE', 'TRANSFER'},
            557: {'OTHER', 'WXORX', 'HEAP', 'VERBOSE', 'TRANSFER'},
            558: {'OTHER', 'WXORX', 'VERBOSE', 'STACK', 'TRANSFER'},
            559: {'WXORX', 'VERBOSE', 'MPROTECT', 'TRANSFER'},
            568: {'WXORX', 'VERBOSE', 'COMPLAIN', 'TRANSFER'},
            569: {'WXORX', 'HEAP', 'VERBOSE', 'COMPLAIN', 'TRANSFER'},
            570: {'WXORX', 'VERBOSE', 'COMPLAIN', 'STACK', 'TRANSFER'},
            571: {'WXORX', 'VERBOSE', 'HEAP', 'COMPLAIN', 'STACK', 'TRANSFER'},
            572: {'OTHER', 'WXORX', 'VERBOSE', 'COMPLAIN', 'TRANSFER'},
            573: {'OTHER', 'WXORX', 'VERBOSE', 'HEAP', 'COMPLAIN', 'TRANSFER'},
            574: {'OTHER', 'WXORX', 'VERBOSE', 'COMPLAIN', 'STACK', 'TRANSFER'},
            575: {'WXORX', 'VERBOSE', 'MPROTECT', 'COMPLAIN', 'TRANSFER'},
            588: {'OTHER', 'WXORX', 'TRANSFER', 'MMAP'},
            589: {'OTHER', 'WXORX', 'HEAP', 'TRANSFER', 'MMAP'},
            590: {'OTHER', 'WXORX', 'STACK', 'TRANSFER', 'MMAP'},
            591: {'TRANSFER', 'FULL'},
            604: {'OTHER', 'WXORX', 'MMAP', 'COMPLAIN', 'TRANSFER'},
            605: {'OTHER', 'WXORX', 'MMAP', 'HEAP', 'COMPLAIN', 'TRANSFER'},
            606: {'OTHER', 'WXORX', 'MMAP', 'COMPLAIN', 'STACK', 'TRANSFER'},
            607: {'COMPLAIN', 'TRANSFER', 'FULL'},
            620: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'TRANSFER'},
            621: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'HEAP', 'TRANSFER'},
            622: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'STACK', 'TRANSFER'},
            623: {'VERBOSE', 'TRANSFER', 'FULL'},
            636: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'COMPLAIN', 'TRANSFER'},
            637: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'HEAP', 'COMPLAIN', 'TRANSFER'},
            638: {'OTHER', 'WXORX', 'VERBOSE', 'MMAP', 'COMPLAIN', 'STACK', 'TRANSFER'},
            639: {'VERBOSE', 'FULL', 'COMPLAIN', 'TRANSFER'},
            783: {'EMUTRAMP', 'WXORX', 'MPROTECT', 'TRANSFER'},
            799: {'WXORX', 'MPROTECT', 'EMUTRAMP', 'COMPLAIN', 'TRANSFER'},
            815: {'WXORX', 'VERBOSE', 'MPROTECT', 'EMUTRAMP', 'TRANSFER'},
            831: {'WXORX', 'VERBOSE', 'MPROTECT', 'EMUTRAMP', 'COMPLAIN', 'TRANSFER'},
            847: {'FULL', 'EMUTRAMP', 'TRANSFER'},
            863: {'FULL', 'EMUTRAMP', 'COMPLAIN', 'TRANSFER'},
            879: {'VERBOSE', 'FULL', 'EMUTRAMP', 'TRANSFER'},
            895: {'VERBOSE', 'FULL', 'EMUTRAMP', 'COMPLAIN', 'TRANSFER'}}


class TestWXProt(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.big_flags = {}
        cls.all_flags = set()
        cls.ok_groups = []
        for k, v in OK_FLAGS.items():
            cls.all_flags = cls.all_flags.union(v)
            cls.big_flags[k] = [v]
            v = list(v)
            malias = ['HEAP', 'STACK', 'OTHER']
            falias = ['MPROTECT', 'WXORX',
                      'MMAP'] + malias
            if 'WXORX' in v:
                v2 = v.copy()
                v2.remove('WXORX')
                if any(x in v2 for x in malias+['MMAP', 'MPROTECT', 'FULL']):
                    cls.big_flags[k].append(set(v2))
            if 'MPROTECT' in v:
                for i in range(1, len(malias)+1):
                    for a in combinations(malias, i):
                        cls.big_flags[k].append(set(v+list(a)))
                        cls.big_flags[k].append(set(v2+list(a)))
                v3 = v.copy()
                v3.remove('MPROTECT')
                v2.remove('MPROTECT')
                cls.big_flags[k].append(set(v3+malias))
                cls.big_flags[k].append(set(v2+malias))
            if 'FULL' in v:
                v2 = v.copy()
                for i in range(1, len(falias)+1):
                    for a in combinations(falias, i):
                        cls.big_flags[k].append(set(v2+list(a)))
                v2.remove('FULL')
                cls.big_flags[k].append(set(v2+falias))
                v2 += ['MPROTECT', 'MMAP']
                cls.big_flags[k].append(set(v2))
                for i in range(1, len(falias)+1):
                    for a in combinations(falias, i):
                        cls.big_flags[k].append(set(v2+list(a)))
                v2.remove('MPROTECT')
                cls.big_flags[k].append(set(v2+['HEAP','STACK']))
                cls.big_flags[k].append(set(v2+['HEAP','OTHER','STACK']))
                cls.big_flags[k].append(set(v2+['HEAP','OTHER','STACK','WXORX']))
                cls.big_flags[k].append(set(v2+['HEAP','STACK','WXORX']))
            if 'MMAP' in v:
                v2 = v.copy()
                if 'OTHER' in v2:
                    v2.remove('OTHER')
                if 'WXORX' in v2:
                    v2.remove('WXORX')
                cls.big_flags[k].append(set(v2))
                cls.big_flags[k].append(set(v2+['WXORX']))
                cls.big_flags[k].append(set(v2+['OTHER']))
                cls.big_flags[k].append(set(v2+['OTHER','WXORX']))
        cls.big_flags[512].append({'TRANSFER'})
        for g in cls.big_flags.values():
            cls.ok_groups.extend(g)

    def test_flags_to_text(self):
        for k, v in OK_FLAGS.items():
            f = wxprot.Config.flags_to_text(k)
            f = {x.strip().upper() for x in f.split(',')}
            self.assertTrue(v == f)

    def test_default_value_to_text(self):
        for k, v in OK_FLAGS.items():
            f = wxprot.Config.default_value_to_text(str(k))
            f = {x.strip().upper() for x in f.split(',')}
            self.assertTrue(v == f)

    def test_are_flags_valid_ok(self):
        for f in OK_FLAGS.keys():
            self.assertTrue(wxprot.Config.are_flags_valid(f))

    def test_are_flags_valid_invalid(self):
        for f in range(0x1000f):
            if f in OK_FLAGS:
                continue
            self.assertFalse(wxprot.Config.are_flags_valid(f))

    def test_build_xattr_from_single_line_with_emutramp(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '1'})
        for k, v in OK_FLAGS.items():
            for vv in permutations(v, len(v)):
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_with_emutramp_big(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '1'})
        for k, v in self.big_flags.items():
            for vv in v:
                vv = list(vv)
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_mprotect(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '0'})
        for k, v in OK_FLAGS.items():
            if 'EMUTRAMP' not in v:
                continue
            k &= 0xfeff
            for vv in permutations(v, len(v)):
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_mprotect_big(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '0'})
        for k, v2 in self.big_flags.items():
            for v in v2:
                if 'EMUTRAMP' not in v:
                    continue
                k &= 0xfeff
                vv = list(v)
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_none(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'NONE'},
                          extra_files={'emutramp_available': '0'})
        for k, v in OK_FLAGS.items():
            if 'EMUTRAMP' not in v:
                continue
            k &= 0x200
            for vv in permutations(v, len(v)):
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_none_big(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'NONE'},
                          extra_files={'emutramp_available': '0'})
        for k, v2 in self.big_flags.items():
            for v in v2:
                if 'EMUTRAMP' not in v:
                    continue
                k &= 0x200
                vv = list(v)
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_mprotect_none(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'NONE'},
                          extra_files={'emutramp_available': '0'})
        for k, v in OK_FLAGS.items():
            if 'EMUTRAMP' not in v:
                continue
            v = v.copy()
            v.remove('EMUTRAMP')
            v.add('EMUTRAMP_OR_MPROTECT')
            k &= 0xfeff
            for vv in permutations(v, len(v)):
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_mprotect_none_big(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'NONE'},
                          extra_files={'emutramp_available': '0'})
        for k, v2 in self.big_flags.items():
            for v in v2:
                if 'EMUTRAMP' not in v:
                    continue
                v = v.copy()
                v.remove('EMUTRAMP')
                v.add('EMUTRAMP_OR_MPROTECT')
                k &= 0xfeff
                vv = list(v)
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_none_mprotect(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '0'})
        for k, v in OK_FLAGS.items():
            if 'EMUTRAMP' not in v:
                continue
            v = v.copy()
            v.remove('EMUTRAMP')
            v.add('EMUTRAMP_OR_NONE')
            k &= 0x200
            for vv in permutations(v, len(v)):
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_no_emutramp_none_mprotect_big(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '0'})
        for k, v2 in self.big_flags.items():
            for v in v2:
                if 'EMUTRAMP' not in v:
                    continue
                v = v.copy()
                v.remove('EMUTRAMP')
                v.add('EMUTRAMP_OR_NONE')
                k &= 0x200
                vv = list(v)
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv)]))
                self.assertEqual(k,
                    c.build_xattr_from_single_line(['/filename', ','.join(vv+vv)]))

    def test_build_xattr_from_single_line_multi_emutramp(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '0'})
        with self.assertRaises(wxprot.WXPConfigException):
            c.build_xattr_from_single_line(['filename',
                                            'FULL,EMUTRAMP,EMUTRAMP_OR_MPROTECT'])
        with self.assertRaises(wxprot.WXPConfigException):
            c.build_xattr_from_single_line(['filename',
                                            'FULL,EMUTRAMP,EMUTRAMP_OR_NONE'])
        with self.assertRaises(wxprot.WXPConfigException):
            c.build_xattr_from_single_line(['filename',
                                            'FULL,EMUTRAMP_OR_NONE,EMUTRAMP_OR_MPROTECT'])

    def test_build_xattr_from_single_line_invalid(self):
        c = wxprot.Config(xattr=True,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '1'})
        for i in range(1, len(self.all_flags)+1):
            for f in combinations(self.all_flags, i):
                f = set(f)
                if f not in self.ok_groups:
                    with self.assertRaises(wxprot.WXPConfigException):
                        c.build_xattr_from_single_line(['/filename', ','.join(f)])

    def test_non_absolute_path(self):
        config_lines = [('location', ['file', 'mprotect'])]
        with self.assertRaises(wxprot.WXPConfigException):
            c = wxprot.Config(config_lines=config_lines,
                              main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                              extra_files={'emutramp_available': '1'})

    def test_star_only_path(self):
        config_lines = [('location', ['*', 'mprotect'])]
        c = wxprot.Config(config_lines=config_lines,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '1'})

    def test_build_dicts_from_config_lines(self):
        config_lines = [('location', ['/file', 'mprotect']),
                        ('location', ['/file2/*', 'mprotect']),
                        ('location', ['/file2/', 'wxorx']),
                        ('location', ['/file', 'full'])]
        expected_res = [{'exact': True, 'path': b'/file2/', 'flags': 8},
                        {'exact': False, 'path': b'/file2/', 'flags': 15},
                        {'exact': True, 'path': b'/file', 'flags': 15}]
        c = wxprot.Config(config_lines=config_lines,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '1'})
        self.assertTrue(len(expected_res) == len(c.dicts))
        for i, e in enumerate(expected_res):
            self.assertTrue(e['exact'] == c.dicts[i]['exact'])
            self.assertTrue(e['path'] == c.dicts[i]['path'])
            self.assertTrue(e['flags'] == c.dicts[i]['flags'])
        self.assertTrue(sha1(c.binary).hexdigest() == 'ccddb46fbe8b6ff7bdb9e1c56d22d35f1af4d76b')

    def test_build_dicts_from_binary(self):
        binary = (b'SARAWXPR\x00\x00\x00\x00\x03\x00\x00\x00\x12\x99'
                  b'#\xeeP\xaa\xe5Lqo\xd5\x86\xd6\xe4\xc5\x16\xd3'
                  b'\xf8!\x01\x07\x00\x08\x00\x01/file2/\x07\x00\x0f'
                  b'\x00\x00/file2/\x05\x00\x0f\x00\x01/file')
        config_lines = [('', ['/file2/', 'WXORX']),
                        ('', ['/file2/*', 'MPROTECT, WXORX']),
                        ('', ['/file', 'MPROTECT, WXORX'])]
        c = wxprot.Config(binary=binary,
                          main_options={'wxprot_emutramp_missing_default': 'MPROTECT'},
                          extra_files={'emutramp_available': '1'})
        self.assertTrue(len(config_lines) == len(c.config_lines))
        for i, e in enumerate(config_lines):
            self.assertTrue(e[0] == c.config_lines[i][0])
            self.assertTrue(e[1][0] == c.config_lines[i][1][0])
            self.assertTrue(e[1][1] == c.config_lines[i][1][1])
