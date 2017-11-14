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

import logging
from glob import iglob
from hashlib import sha1
from os.path import join, isdir
from re import sub
from shlex import quote, split

from sara.submodules.BaseConfig import ConfigException
from sara.submodules import submodules


class SubModLoader(object):
    def __init__(self, config_path, sysfs_path):
        self.config_path = config_path
        self.sysfs_path = join(sysfs_path, 'sara')
        if not isdir(self.sysfs_path):
            raise Exception('S.A.R.A. is not available at "{}".'.format(self.sysfs_path))
        self.main_options = {'sara_enabled': 0,
                             'sara_locked': 0}
        self.__submodules = []
        self.__config_objects = {}
        for sm in submodules:
            if not isdir(join(self.sysfs_path, sm.sysfs_name)):
                continue
            d = {}
            self.main_options['{}_enabled'.format(sm.config_name)] = 1
            d['config_name'] = sm.config_name
            d['long_name'] = sm.long_name
            d['sysfs_name'] = sm.sysfs_name
            d['default_value'] = sm.default_value
            d['main_options'] = dict(sm.main_options).keys()
            for name, default_value in sm.main_options:
                self.main_options[name] = default_value
            d['extra_files'] = sm.extra_files
            d['xattr_name'] = sm.xattr_name
            d['startup'] = sm.startup
            d['config'] = sm.Config
            self.__submodules.append(d)

    def get_submodules_names(self):
        return ['main'] + [s['config_name'] for s in self.__submodules]

    def enable(self, subm='main'):
        if self.is_locked:
            logging.error('configuration is locked.')
            return
        self.__write_flag(subm, 'enabled', 1)

    def disable(self, subm='main'):
        if self.is_locked:
            logging.error('configuration is locked.')
            return
        self.__write_flag(subm, 'enabled', 0)

    def lock(self):
        self.__write_flag('main', 'locked', 1)

    @property
    def is_locked(self):
        return bool(int(self.__get_flag('main', 'locked').strip()))

    def call_startup(self):
        for d in self.__submodules:
            d['startup']()

    def load_config(self, force=False, config=None, skip_main=False):
        if self.is_locked:
            logging.error('configuration is locked.')
            return False
        self.__load_main_config()
        self.__load_config_objects(config)
        if not skip_main:
            for k, v in self.main_options.items():
                if k == 'sara_enabled':
                    if v == 0:
                        self.disable()
                elif k in ('wxprot_xattr_enabled',
                           'wxprot_xattr_user_allowed'):
                    subm, name = k.split('_', 1)
                    if v == 1:
                        self.__write_flag(subm, name, 1)
                    else:
                        self.__write_flag(subm, name, 0)
                elif k.endswith('_enabled'):
                    if v == 0:
                        self.disable(k[:-8])
        for k, v in self.__config_objects.items():
            if not force:
                if v.xhash == self.__get_flag(k, 'hash').strip():
                    continue
            lf = join(self.sysfs_path, k, '.load')
            try:
                with open(lf, 'wb') as fd:
                    fd.write(v.binary)
            except IOError:
                pass
        if not skip_main:
            for k, v in self.main_options.items():
                if k == 'sara_enabled':
                    if v == 1:
                        self.enable()
                elif k.endswith('_enabled') and k != 'wxprot_xattr_enabled':
                    if v == 1:
                        self.enable(k[:-8])
            if self.main_options['sara_locked'] == 1:
                self.lock()
        return True

    def xattr_encode(self, submodule, value, filename=None):
        self.__load_main_config()
        for sm in self.__submodules:
            if sm['config_name'] == submodule:
                mopts = {k: v for k, v in self.main_options.items() if k in sm['main_options']}
                exf = {}
                for f in sm['extra_files']:
                    exf[f] = self.__get_flag(sm['sysfs_name'], f)
                try:
                    obj = sm['config'](xattr=True,
                                       main_options=mopts,
                                       extra_files=exf)
                except ConfigException as e:
                    obj = None
                    logging.warning(e)
                if obj:
                    if filename is None:
                        filename = 'xattr '
                    else:
                        filename = quote(filename) + ' '
                    value = split(filename + value)
                    return obj.build_xattr_from_single_line(value)
                break
        return None

    def xattr_decode(self, xattr_name, value):
        for sm in self.__submodules:
            if sm['xattr_name'] == xattr_name:
                return sm['config'].default_value_to_text(value)

    def xattr_names(self):
        return {sm['config_name']: sm['xattr_name'] for sm in self.__submodules}

    def get_config_binaries(self, config=None, extras=None):
        ret = {}
        self.__load_main_config()
        self.__load_config_objects(config, extras)
        for k, v in self.__config_objects.items():
            ret[k] = v.binary
        return ret

    def get_extras(self):
        ret = {'main': {}}
        for f in ('enabled', 'locked'):
            ret['main'][f] = self.__get_flag('main', f)
        for d in self.__submodules:
            ret[d['sysfs_name']] = {'long_name': d['long_name']}
            for f in ('enabled', 'hash', 'version'):
                ret[d['sysfs_name']][f] = self.__get_flag(d['sysfs_name'], f)
            for f in d['extra_files']:
                ret[d['sysfs_name']][f] = self.__get_flag(d['sysfs_name'], f)
        return ret

    def get_current_configs(self):
        ret = {}
        self.__load_main_config()
        self.__load_config_objects_binary()
        for k, v in self.__config_objects.items():
            ret[k] = v.config
        return ret

    def get_default_values(self):
        ret = {}
        for d in self.__submodules:
            v = self.__get_flag(d['sysfs_name'], d['default_value'])
            if v is not None:
                v = d['config'].default_value_to_text(v)
            ret[d['sysfs_name']] = v
        return ret

    def test_config(self):
        self.__load_config_objects_binary()
        extras = self.get_extras()
        oldv = {}
        for k, v in self.__config_objects.items():
            oldv[k] = (extras[k]['hash'], sha1(v.binary).digest())
            if oldv[k][0] == '0'*40 and len(v.binary) != 0:
                return False
            if oldv[k][0] != '0'*40 and len(v.binary) == 0:
                return False
        for k, v in self.__config_objects.items():
            lf = join(self.sysfs_path, k, '.load')
            try:
                with open(lf, 'wb') as fd:
                    fd.write(v.binary)
            except IOError:
                pass
        self.__load_config_objects_binary()
        extras = self.get_extras()
        cfs = {}
        for k, v in self.__config_objects.items():
            if oldv[k][0] != extras[k]['hash']:
                return False
            if oldv[k][1] != sha1(v.binary).digest():
                return False
            cfs[k] = v.config
        self.__load_config_objects(config=cfs)
        binaries = {}
        for k, v in self.__config_objects.items():
            binaries[k] = v.binary
        self.__load_config_objects_binary(binaries=binaries)
        for k, v in self.__config_objects.items():
            if cfs[k] != v.config:
                return False
        return True

    def __get_flag(self, subname, flag_name):
        df = join(self.sysfs_path, subname, flag_name)
        try:
            with open(df, 'r', encoding='ascii') as fd:
                return fd.read().strip()
        except IOError:
            return None
        except FileNotFoundError:
            return None

    def __write_flag(self, subname, flag_name, value):
        df = join(self.sysfs_path, subname, flag_name)
        try:
            with open(df, 'w', encoding='ascii') as fd:
                fd.write('{}\n'.format(value))
        except IOError:
            pass
        except PermissionError:
            pass

    def __load_config_objects(self, config=None, extras=None):
        for d in self.__submodules:
            if config is not None and d['config_name'] in config:
                cf = []
                for line in config[d['config_name']].split('\n'):
                    line = split(line, comments=True)
                    if len(line):
                        cf.append(('custom', line))
            elif config is not None:
                continue
            else:
                cf = self.__read_config(d['config_name'])
            mopts = {k: v for k, v in self.main_options.items() if k in d['main_options']}
            exf = {}
            for f in d['extra_files']:
                exf[f] = self.__get_flag(d['sysfs_name'], f)
            if extras:
                exf.update(extras)
            try:
                obj = d['config'](config_lines=cf,
                                  main_options=mopts,
                                  extra_files=exf)
            except ConfigException as e:
                obj = None
                logging.warning(e)
            else:
                self.__config_objects[d['sysfs_name']] = obj

    def __load_config_objects_binary(self, binaries=None):
        for d in self.__submodules:
            if binaries is not None and d['sysfs_name'] in binaries:
                binary = binaries[d['sysfs_name']]
            else:
                bf = join(self.sysfs_path, d['sysfs_name'], '.dump')
                try:
                    with open(bf, 'rb') as fd:
                        binary = fd.read()
                except IOError:
                    binary = b''
            mopts = {k: v for k, v in self.main_options.items() if k in d['main_options']}
            exf = {}
            for f in d['extra_files']:
                exf[f] = self.__get_flag(d['sysfs_name'], f)
            try:
                obj = d['config'](binary=binary,
                                  main_options=mopts,
                                  extra_files=exf)
            except ConfigException as e:
                obj = None
                logging.warning(e)
            self.__config_objects[d['sysfs_name']] = obj

    def __load_main_config(self):
        cf = join(self.config_path, 'main.conf')
        try:
            with open(cf, 'r', encoding='ascii') as fd:
                for ln, line in enumerate(fd, 1):
                    line = sub(r'\s+', '', line.split('#')[0]).split('=', 1)
                    if len(line) == 1 and line[0] == '':
                        continue
                    if len(line) != 2 or not line[0] or not line[1]:
                        logging.warning('Syntax error at {}:{}'.format(cf, ln))
                        continue
                    try:
                        self.main_options[line[0]] = int(line[1].strip())
                    except ValueError:
                        self.main_options[line[0]] = line[1]
        except IOError:
            pass

    def __read_config(self, config_name):
        cf = join(self.config_path, '{}.conf'.format(config_name))
        cd = join(self.config_path, '{}.conf.d'.format(config_name), '*.conf')
        ret = self.__parse_file(cf)
        for f in sorted(iglob(cd)):
            ret += self.__parse_file(f)
        return ret

    def __parse_file(self, cf):
        ret = []
        try:
            with open(cf, 'r', encoding='utf8') as fd:
                for ln, line in enumerate(fd, 1):
                    line = split(line, comments=True)
                    if line:
                        ret.append(('{}:{}'.format(cf, ln), line))
        except IOError:
            pass
        return ret
