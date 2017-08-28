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
from abc import ABC, abstractmethod
from hashlib import sha1
from operator import itemgetter


class ConfigException(Exception):
    ERR_FMT = "generic error at line '{location}': {description}."

    def __init__(self, location, description):
        super(ConfigException, self).__init__()
        self.location = location
        self.description = description

    def __str__(self):
        return self.ERR_FMT.format(location=self.location, description=self.description)


class BinaryException(Exception):
    ERR_FMT = "generic binary error: {description}."

    def __init__(self, description):
        super(BinaryException, self).__init__()
        self.description = description

    def __str__(self):
        return self.ERR_FMT.format(description=self.description)


class BaseConfig(ABC):
    WARN = "config have been simplified"

    def __init__(self,
                 config_lines=None,
                 binary=None,
                 main_options=None,
                 extra_files=None):
        assert config_lines is None or binary is None
        assert config_lines is not None or binary is not None
        if main_options is None:
            self.main_options = {}
        else:
            self.main_options = main_options
        if extra_files is None:
            self.extra_files = {}
        else:
            self.extra_files = extra_files
        self.dicts = []
        if config_lines is not None:
            self._binary = b''
            self.config_lines = config_lines
            self.build_dicts_from_config_lines()
            if self.extra_dicts_stuff():
                logging.warning(self.WARN)
            self.build_binary()
        else:
            self._binary = binary
            self.config_lines = []
            self.build_dicts_from_binary()
            self.build_config_lines()

    def __hash(self):
        return sha1(self.config.encode('utf8'))

    @property
    def xhash(self):
        return self.__hash().hexdigest()

    @property
    def bhash(self):
        return self.__hash().digest()

    @property
    def binary(self):
        return self._binary

    @property
    def config(self):
        g = itemgetter(1)
        return ''.join(
            [' '.join(g(l)) + '\n' for l in self.config_lines])

    @abstractmethod
    def build_dicts_from_config_lines(self):
        pass

    def extra_dicts_stuff(self):
        pass

    @abstractmethod
    def build_binary(self):
        pass

    @abstractmethod
    def build_dicts_from_binary(self):
        pass

    @abstractmethod
    def build_config_lines(self):
        pass

    @staticmethod
    @abstractmethod
    def default_value_to_text(v):
        return
