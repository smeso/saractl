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
from base64 import encodebytes
from os import makedirs
from os.path import join
from sara.SubModLoader import SubModLoader
from sara.templates import SH_TEMPLATE, C_TEMPLATE, c_array


class Sara(object):
    def __init__(self, config_path, sysfs_path):
        self.sysfs_path = sysfs_path
        self.__sml = SubModLoader(config_path, self.sysfs_path)

    def enable(self, subm='main'):
        self.__sml.enable(subm=subm)

    def disable(self, subm='main'):
        self.__sml.disable(subm=subm)

    def lock(self):
        self.__sml.lock()

    @property
    def is_locked(self):
        return self.__sml.is_locked

    def startup(self):
        if self.__sml.load_config(force=True):
            self.__sml.call_startup()
        else:
            return False
        return True

    def load(self, force=False):
        return self.__sml.load_config(force=force)

    def test(self):
        if not self.__sml.test_config():
            logging.error('config test failed.')
            return False
        return True

    def status(self, verbose=False):
        ret = {}
        ret['extras'] = self.__sml.get_extras()
        ret['default_values'] = self.__sml.get_default_values()
        if verbose:
            ret['configs'] = self.__sml.get_current_configs()
        return ret

    def xattr_encode(self, submodule, value, filename=None):
        return self.__sml.xattr_encode(submodule, value, filename=filename)

    def xattr_decode(self, xattr_name, value):
        return self.__sml.xattr_decode(xattr_name, value)

    def xattr_names(self):
        return self.__sml.xattr_names()

    def make_bin_config_files(self, dest_dir, config=None):
        configs = self.__sml.get_config_binaries(config, {'emutramp_available': '1'})
        configs['wxprot_noemutramp'] = self.__sml.get_config_binaries(config, {'emutramp_available': '2'})['wxprot']
        makedirs(dest_dir, exist_ok=True)
        for k, v in configs.items():
            with open(join(dest_dir, k), 'wb') as fd:
                fd.write(v)

    def make_bin_config_sh(self, dest, config=None):
        configs = self.__sml.get_config_binaries(config, {'emutramp_available': '1'})
        configs['wxprot_noemutramp'] = self.__sml.get_config_binaries(config, {'emutramp_available': '2'})['wxprot']
        for k in configs:
            configs[k] = encodebytes(configs[k]).decode('ascii')
        for k in ('sara_locked', 'sara_enabled', 'wxprot_enabled',
                  'wxprot_xattr_enabled', 'wxprot_xattr_user_allowed'):
            configs[k] = self.__sml.main_options[k]
        configs['sysfs_path'] = self.sysfs_path
        shscript = SH_TEMPLATE.format(**configs)
        with open(dest, 'w') as fd:
            fd.write(shscript)

    def make_bin_config_c(self, dest, config=None):
        configs = self.__sml.get_config_binaries(config, {'emutramp_available': '1'})
        configs['wxprot_noemutramp'] = self.__sml.get_config_binaries(config, {'emutramp_available': '2'})['wxprot']
        for k in configs:
            configs[k] = c_array(configs[k])
        for k in ('sara_locked', 'sara_enabled', 'wxprot_enabled',
                  'wxprot_xattr_enabled', 'wxprot_xattr_user_allowed'):
            configs[k] = self.__sml.main_options[k]
        configs['sysfs_path'] = self.sysfs_path
        csource = C_TEMPLATE.format(**configs)
        with open(dest, 'w') as fd:
            fd.write(csource)
