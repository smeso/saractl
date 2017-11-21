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

from functools import total_ordering
from os.path import isfile
from struct import pack, unpack
from re import sub

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.descriptions import describe_p_type, describe_p_flags
    from elftools.common.exceptions import ELFError
except ImportError:
    ELFFile = None

from sara.submodules.BaseConfig import BaseConfig, ConfigException, BinaryException


config_name = 'wxprot'
long_name = 'WX Protection'
sysfs_name = config_name
default_value = 'default_flags'
main_options = [('wxprot_emutramp_missing_default', 'MPROTECT')]
extra_files = ['emutramp_available', 'xattr_enabled', 'xattr_user_allowed']
xattr_name = 'wxp'


def startup():
    pass


class WXPConfigException(ConfigException):
    ERR_FMT = "WX protection confinguration error at line '{location}': {description}."


class WXPBinaryException(BinaryException):
    ERR_FMT = "WX protection binary error: {description}."

SARA_PATH_MAX = 4096
SARA_WXP_HEAP = 0x0001
SARA_WXP_STACK = 0x0002
SARA_WXP_OTHER = 0x0004
SARA_WXP_WXORX = 0x0008
SARA_WXP_COMPLAIN = 0x0010
SARA_WXP_VERBOSE = 0x0020
SARA_WXP_MMAP = 0x0040
SARA_WXP_EMUTRAMP = 0x0100
SARA_WXP_MPROTECT = SARA_WXP_HEAP | SARA_WXP_OTHER | SARA_WXP_STACK
SARA_WXP_TRANSFER = 0x0200
SARA_WXP_FULL = SARA_WXP_MPROTECT | SARA_WXP_WXORX | SARA_WXP_MMAP
SARA_WXP_NONE = 0x0000
SARA_WXP_ALL = SARA_WXP_FULL | \
               SARA_WXP_EMUTRAMP | \
               SARA_WXP_COMPLAIN | \
               SARA_WXP_VERBOSE | \
               SARA_WXP_TRANSFER


class Config(BaseConfig):
    WARN = "WX protection config has been simplified"

    @total_ordering
    class DictKey(object):
        def __init__(self, obj, *args):
            self.obj = obj

        def __lt__(self, other):
            if len(self.obj['path']) < len(other.obj['path']):
                return False
            elif len(self.obj['path']) > len(other.obj['path']):
                return True
            else:
                if self.obj['exact'] == other.obj['exact']:
                    return self.obj['path'] < other.obj['path']
                elif self.obj['exact']:
                    return True
                else:
                    return False

        def __eq__(self, other):
            return self.obj['path'] == other.obj['path'] and \
                   self.obj['exact'] == other.obj['exact']

    def __init__(self,
                 config_lines=None,
                 binary=None,
                 xattr=False,
                 main_options=None,
                 extra_files=None):
        super().__init__(config_lines=config_lines,
                         binary=binary,
                         xattr=xattr,
                         main_options=main_options,
                         extra_files=extra_files)
        self.emudef = 'MPROTECT'
        self.emuavail = False

    def build_dicts_from_config_lines(self):
        self.load_emudef()
        seen = set()
        for location, line in self.config_lines:
            if line[0] in seen:
                continue
            seen.add(line[0])
            self.dicts.append(self.parse_line(location, line))
        self.dicts.sort(key=self.DictKey)

    def load_emudef(self):
        emudef = self.main_options['wxprot_emutramp_missing_default']
        if emudef is None:
            self.emudef = 'MPROTECT'
        else:
            emudef = emudef.strip().upper()
            if emudef == 'NONE':
                self.emudef = 'NONE'
            elif emudef == 'MPROTECT':
                self.emudef = 'MPROTECT'
            else:
                raise WXPConfigException('main', 'wrong value for "wxprot_emutramp_missing_default"')
        emuavail = self.extra_files['emutramp_available']
        if emuavail is None or emuavail.strip() == '0':
            self.emuavail = False
        else:
            self.emuavail = True

    def parse_line(self, location, line):
        if len(line) < 2:
            raise WXPConfigException(location, 'not enough fields')
        path = line[0]
        flags = ' '.join(line[1:])
        flags = list(set(sub(r',+', ',', sub(r'\s+', '', flags)).upper().split(',')))
        allowed_flags = ('FULL',
                         'VERBOSE',
                         'WXORX',
                         'STACK',
                         'HEAP',
                         'COMPLAIN',
                         'OTHER',
                         'MPROTECT',
                         'EMUTRAMP',
                         'EMUTRAMP_OR_MPROTECT',
                         'EMUTRAMP_OR_NONE',
                         'TRANSFER',
                         'MMAP',
                         'NONE')
        if any([f not in allowed_flags for f in flags]):
            raise WXPConfigException(location, 'invalid flag')
        if not (('NONE' in flags and len(flags) == 1) or
                ('NONE' in flags and len(flags) == 2 and 'TRANSFER' in flags) or
                'NONE' not in flags):
            raise WXPConfigException(location, 'invalid flags')
        if (len(path) - (1 if path[-1] == '*' else 0)) > SARA_PATH_MAX:
            raise WXPConfigException(location, 'path too long')
        ef = 0
        if 'EMUTRAMP' in flags:
            ef += 1
        if 'EMUTRAMP_OR_MPROTECT' in flags:
            ef += 1
        if 'EMUTRAMP_OR_NONE' in flags:
            ef += 1
        if ef > 1:
            raise WXPConfigException(location, 'can\'t use more the one version of the EMUTRAMP flag')
        if not self.emuavail and ef == 1:
            if 'EMUTRAMP_OR_NONE' in flags:
                flags.remove('EMUTRAMP_OR_NONE')
                emudo = 'NONE'
            elif 'EMUTRAMP_OR_MPROTECT' in flags:
                flags.remove('EMUTRAMP_OR_MPROTECT')
                emudo = 'MPROTECT'
                flags.append('MPROTECT')
            elif 'EMUTRAMP' in flags:
                flags.remove('EMUTRAMP')
                emudo = self.emudef
            if emudo == 'NONE':
                try:
                    flags.remove('MPROTECT')
                except ValueError:
                    pass
                try:
                    flags.remove('HEAP')
                except ValueError:
                    pass
                try:
                    flags.remove('OTHER')
                except ValueError:
                    pass
                try:
                    flags.remove('STACK')
                except ValueError:
                    pass
                try:
                    flags.remove('WXORX')
                except ValueError:
                    pass
                try:
                    flags.remove('MMAP')
                except ValueError:
                    pass
                try:
                    flags.remove('COMPLAIN')
                except ValueError:
                    pass
                try:
                    flags.remove('VERBOSE')
                except ValueError:
                    pass
                try:
                    flags.remove('FULL')
                except ValueError:
                    pass
        elif self.emuavail and ef == 1:
            if 'EMUTRAMP_OR_NONE' in flags:
                flags.remove('EMUTRAMP_OR_NONE')
                flags.append('EMUTRAMP')
            elif 'EMUTRAMP_OR_MPROTECT' in flags:
                flags.remove('EMUTRAMP_OR_MPROTECT')
                flags.append('EMUTRAMP')
        d = {}
        if path[-1] == '*':
            d['path'] = path[:-1]
            d['exact'] = False
        else:
            d['path'] = path
            d['exact'] = True
        d['flags'] = 0
        for f in flags:
            if f == 'FULL':
                d['flags'] |= SARA_WXP_FULL
            elif f == 'VERBOSE':
                d['flags'] |= SARA_WXP_VERBOSE
            elif f == 'WXORX':
                d['flags'] |= SARA_WXP_WXORX
            elif f == 'STACK':
                d['flags'] |= SARA_WXP_STACK | SARA_WXP_WXORX
            elif f == 'HEAP':
                d['flags'] |= SARA_WXP_HEAP | SARA_WXP_WXORX
            elif f == 'COMPLAIN':
                d['flags'] |= SARA_WXP_COMPLAIN
            elif f == 'OTHER':
                d['flags'] |= SARA_WXP_OTHER | SARA_WXP_WXORX
            elif f == 'EMUTRAMP':
                d['flags'] |= SARA_WXP_EMUTRAMP
            elif f == 'MPROTECT':
                d['flags'] |= SARA_WXP_MPROTECT | SARA_WXP_WXORX
            elif f == 'TRANSFER':
                d['flags'] |= SARA_WXP_TRANSFER
            elif f == 'MMAP':
                d['flags'] |= SARA_WXP_MMAP | SARA_WXP_OTHER | SARA_WXP_WXORX
        if not Config.are_flags_valid(d['flags']):
            raise WXPConfigException(location, 'invalid flags')
        if d['exact'] and isfile(d['path']) and not d['flags'] & SARA_WXP_COMPLAIN:
            if d['flags'] & SARA_WXP_WXORX and \
	       not (d['flags'] & SARA_WXP_EMUTRAMP) and \
	       self.execstack_check(d['path']):
                raise WXPConfigException(location,
			"WXORX protection is incompaible with GNU executable stack marking. Did you forget EMUTRAMP?")
            if d['flags'] & SARA_WXP_MMAP and self.relro_check(d['path']):
                raise WXPConfigException(location,
			"MMAP restriction is incompaible with binaries missing a RELRO section.")
            if d['flags'] & SARA_WXP_MMAP and self.dlopen_check(d['path']):
                raise WXPConfigException(location,
			"MMAP restriction is incompaible with binaries using dlopen(3).")
        return d

    def extra_dicts_stuff(self):
        pass

    @staticmethod
    def execstack_check(path):
        if ELFFile is not None:
            try:
                with open(path, 'rb') as f:
                    elffile = ELFFile(f)
                    for segment in elffile.iter_segments():
                        if describe_p_type(segment['p_type']) == 'GNU_STACK':
                            return describe_p_flags(segment['p_flags']) == 'RWE'
            except (IOError, TypeError, ELFError):
                pass
        return False

    @staticmethod
    def relro_check(path):
        if ELFFile is not None:
            try:
                with open(path, 'rb') as f:
                    elffile = ELFFile(f)
                    for segment in elffile.iter_segments():
                        if describe_p_type(segment['p_type']) == 'GNU_RELRO':
                            return False
            except (IOError, TypeError, ELFError):
                pass
            return True
        return False

    @staticmethod
    def dlopen_check(path):
        if ELFFile is not None:
            try:
                with open(path, 'rb') as f:
                    elffile = ELFFile(f)
                    for segment in elffile.iter_segments():
                        if describe_p_type(segment['p_type']) == 'DYNAMIC':
                            for tag in segment.iter_tags():
                                if tag.entry.d_tag == 'DT_NEEDED' and \
                                   tag.needed.startswith(b'libdl.so'):
                                    return True
            except (IOError, TypeError, ELFError):
                pass
        return False

    def build_binary(self):
        self._binary = b'SARAWXPR'
        self._binary += pack("<I", 0)
        self._binary += pack("<I", len(self.dicts))
        self._binary += self.bhash
        for rule in self.dicts:
            rule['path'] = rule['path'].encode('utf8')
            self._binary += pack("<H", len(rule['path']))
            self._binary += pack("<H", rule['flags'])
            self._binary += pack("B", rule['exact'])
            self._binary += rule['path']

    def build_dicts_from_binary(self):
        p = 0
        if self._binary[:8] != b'SARAWXPR':
            raise WXPBinaryException('wrong magic number')
        p += 8
        version, rnum = unpack("<II", self._binary[p:p+8])
        p += 8
        #bhash = self._binary[p:p+20]
        p += 20
        if version != 0:
            raise WXPBinaryException('wrong version')
        for _ in range(rnum):
            d = {}
            chunk = self._binary[p:p+5]
            p += 5
            if len(chunk) != 5:
                raise WXPBinaryException('wrong size')
            tmp = unpack("<HHB", chunk)
            path_len = tmp[0]
            d['flags'] = tmp[1]
            d['exact'] = tmp[2]
            chunk = self._binary[p:p+path_len].decode('utf8')
            p += path_len
            if len(chunk) != path_len:
                raise WXPBinaryException('wrong size')
            d['path'] = chunk
            self.dicts.append(d)

    def build_config_lines(self):
        for d in self.dicts:
            line = ['{path}{wild}'.format(path=d['path'],
                                          wild='' if d['exact'] else '*')]
            line.append(Config.flags_to_text(d['flags']))
            self.config_lines.append(('', line))

    def build_xattr_from_single_line(self, line):
        self.load_emudef()
        d = self.parse_line(line[0], line)
        return d['flags']

    @staticmethod
    def default_value_to_text(f):
        #return Config.flags_to_text(int(f.strip(), 16))
        return Config.flags_to_text(int(f.strip(), 10))

    @staticmethod
    def flags_to_text(f):
        line = ''
        if not Config.are_flags_valid(f):
            raise WXPBinaryException('invalid flags')
        if f == SARA_WXP_NONE:
            line += 'NONE'
        elif f == SARA_WXP_TRANSFER:
            line += 'NONE, TRANSFER'
        else:
            if (f & SARA_WXP_FULL) == SARA_WXP_FULL:
                line += 'FULL, '
            else:
                if (f & SARA_WXP_MPROTECT) == SARA_WXP_MPROTECT:
                    line += 'MPROTECT, '
                else:
                    if f & SARA_WXP_HEAP:
                        line += 'HEAP, '
                    if f & SARA_WXP_STACK:
                        line += 'STACK, '
                    if f & SARA_WXP_OTHER:
                        line += 'OTHER, '
                if f & SARA_WXP_WXORX:
                    line += 'WXORX, '
                if f & SARA_WXP_MMAP:
                    line += 'MMAP, '
            if f & SARA_WXP_EMUTRAMP:
                line += 'EMUTRAMP, '
            if f & SARA_WXP_TRANSFER:
                line += 'TRANSFER, '
            if f & SARA_WXP_VERBOSE:
                line += 'VERBOSE, '
            if f & SARA_WXP_COMPLAIN:
                line += 'COMPLAIN, '
        return line.rstrip(', ')

    @staticmethod
    def are_flags_valid(flags):
        flags &= ~SARA_WXP_TRANSFER
        if (flags & SARA_WXP_ALL) != flags:
            return False
        if flags & SARA_WXP_MPROTECT and \
           not (flags & SARA_WXP_WXORX):
            return False
        if flags & (SARA_WXP_COMPLAIN | SARA_WXP_VERBOSE) and \
           not (flags & (SARA_WXP_MPROTECT |
                         SARA_WXP_WXORX |
                         SARA_WXP_MMAP)):
            return False
        if flags & SARA_WXP_MMAP and \
           not (flags & SARA_WXP_OTHER):
            return False
        if flags & SARA_WXP_EMUTRAMP and \
           (flags & SARA_WXP_MPROTECT) != SARA_WXP_MPROTECT:
            return False
        return True
