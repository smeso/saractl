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
from argparse import ArgumentParser
from sara.Sara import Sara
from sara.submodules import submodules_names


class CLI(object):
    def __init__(self, argv):
        self.prog = 'saractl'
        self.argv = argv
        self.argparse = self.build_argparse(prog=self.prog,
                                            version='0.1',
                                            submodules=submodules_names)
        self.parsed_args = self.argparse.parse_args(argv[1:])
        if self.parsed_args.log_level is None:
            self.log_level = logging.WARNING
        elif self.parsed_args.log_level <= 0:
            self.log_level = logging.ERROR
        elif self.parsed_args.log_level == 1:
            self.log_level = logging.INFO
        elif self.parsed_args.log_level >= 2:
            self.log_level = logging.DEBUG
        logging.basicConfig(format='%(message)s', level=self.log_level)
        self.config_dir = self.parsed_args.config_dir
        self.securityfs = self.parsed_args.securityfs
        self.submodule = self.parsed_args.submodule
        self.cmd = self.parsed_args.cmd_name
        self.sara = self.__safe_call(Sara, self.config_dir, self.securityfs)

    def __safe_call(self, fname, *args, **kwargs):
        try:
            return fname(*args, **kwargs)
        except Exception as e:
            if self.log_level == logging.DEBUG:
                raise
            else:
                logging.error(e)
                exit(1)

    def do_cmd(self):
        if self.cmd == 'load':
            force = False
            if self.parsed_args.force:
                force = True
            ret = self.__safe_call(self.sara.load, force=force)
            if not ret:
                logging.error('config load failed.')
                return 1
        elif self.cmd == 'startup':
            ret = self.__safe_call(self.sara.startup)
            if not ret:
                logging.error('startup failed.')
                return 1
        elif self.cmd == 'enable':
            self.__safe_call(self.sara.enable, self.submodule)
        elif self.cmd == 'disable':
            self.__safe_call(self.sara.disable, self.submodule)
        elif self.cmd == 'status':
            verbose = False
            if self.parsed_args.log_level is not None and self.parsed_args.log_level >= 1:
                verbose = True
            ret = self.__safe_call(self.sara.status, verbose=verbose)
            if self.submodule == 'main':
                if ret['extras']['main']['enabled'] == '1':
                    print('SARA: enabled')
                else:
                    print('SARA: disabled')
                if ret['extras']['main']['locked'] == '1':
                    print('Configuration: locked')
                else:
                    print('Configuration: unlocked')
            if self.submodule == 'main' or self.submodule == 'wxprot':
                self.__status_helper(ret, 'wxprot')
        elif self.cmd == 'lock':
            self.__safe_call(self.sara.lock)
        elif self.cmd == 'screenlock':
            self.__safe_call(self.sara.screenlock)
        elif self.cmd == 'screenunlock':
            self.__safe_call(self.sara.screenunlock)
        elif self.cmd == 'config_to_file':
            dest = self.parsed_args.output
            if dest is not None:
                dest = dest[0]
            if self.parsed_args.output_format == 'binary':
                if dest is None:
                    dest = './output/'
                self.__safe_call(self.sara.make_bin_config_files, dest)
            elif self.parsed_args.output_format == 'sh':
                if dest is None:
                    dest = './output.sh'
                self.__safe_call(self.sara.make_bin_config_sh, dest)
            elif self.parsed_args.output_format == 'c':
                if dest is None:
                    dest = './output.c'
                self.__safe_call(self.sara.make_bin_config_c, dest)
        elif self.cmd == 'test':
            return int(not self.__safe_call(self.sara.test))
        return 0

    def __status_helper(self, data, submodule):
        ln = data['extras'][submodule]['long_name']
        en = data['extras'][submodule]['enabled']
        h = data['extras'][submodule]['hash'].strip()
        v = data['extras'][submodule]['version']
        c = None
        if 'configs' in data:
            c = data['configs'][submodule]
        print('{}: {}'.format(ln, 'enabled' if en == '1' else 'disabled'))
        print('Default: {}'.format(data['default_values'][submodule]))
        print('Version: {}'.format(v))
        if h == '0'*40:
            print('{}: configuration not loaded'.format(ln))
        else:
            print('{}: configuration loaded ({})'.format(ln, h))
        if c:
            print('-' * 79)
            print(c.strip())
            print('-' * 79)

    def build_argparse(self, prog, version, submodules):
        parser = ArgumentParser(prog=prog,
                                description=prog +
                                ' is the userspace utility that manages S.A.R.A. LSM\'s configurations.')
        sms = ', '.join(submodules)
        log_level_g = parser.add_mutually_exclusive_group()
        log_level_g.add_argument('-v', '--verbose',
                                 dest='log_level',
                                 action='count',
                                 help='Be verbose. For extra verbosity use multiple -v.')
        log_level_g.add_argument('-q', '--quiet',
                                 dest='log_level',
                                 action='store_const',
                                 const=0,
                                 help='Suppress any output.')
        parser.add_argument('-V',
                            '--version',
                            action='version',
                            version='{} {}'.format(prog, version))
        parser.add_argument('-c',
                            '--config-dir',
                            default='/etc/sara',
                            help='Specify config directory. Defaults to "/etc/sara"')
        parser.add_argument('-S',
                            '--securityfs',
                            default='/sys/kernel/security',
                            help='The mount point of the securityfs. Defaults to "/sys/kernel/security".')
        parser.add_argument('-s',
                            '--submodule',
                            choices=['main'] + submodules,
                            default='main',
                            help='Select the submodule you want to work with. Available submodules: {}. Defaults to "main".'.format(sms))
        subparsers = parser.add_subparsers(dest='cmd_name')
        lo = subparsers.add_parser('load',
                                   help='Load configurations. If a config is already present and up to date it won\'t be loaded again (-s is ignored).')
        lo.add_argument('-f',
                        '--force',
                        action='store_const',
                        const=True,
                        default=False,
                        help='Force reload even if the config is already up to date.')
        subparsers.add_parser('startup', help='Load configurations for the first time at boot (-s is ignored).')
        subparsers.add_parser('enable', help='Enable S.A.R.A.')
        subparsers.add_parser('disable', help='Disable S.A.R.A.')
        subparsers.add_parser('status', help='Get S.A.R.A. status.')
        subparsers.add_parser('lock', help='Prevent changing the config until next reboot.')
        subparsers.add_parser('screenlock',
                              help='Enable extra protections to secure your computer while you are away form keyboard (-s is ignored).')
        subparsers.add_parser('screenunlock',
                              help='Disable extra protections (-s is ignored).')
        ctf = subparsers.add_parser('config_to_file',
                                    help='Generate various binary formats to import the configuration without {} (-s is ignored).'.format(prog))
        ctf.add_argument('-F',
                         '--output-format',
                         choices=['binary', 'sh', 'c'],
                         default='binary',
                         help='Select the desired output format. Available formats: "binary", "sh" and "c". Defaults to "binary".')
        ctf.add_argument('-o',
                         '--output',
                         nargs=1,
                         default=None,
                         help='Output file or directory. Defaults to "./output/" directory for "binary" format, "./output.sh" file for "sh" format and "./output.c" file for "c" format.')
        subparsers.add_parser('test', help='Run some self-tests.')
        return parser
