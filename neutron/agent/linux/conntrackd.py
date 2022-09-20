# Copyright (c) 2015 UnitedStack, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import errno
import os
import stat

from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils.fileutils import ensure_tree
import six

from neutron.agent.linux import external_process
from neutron.agent.linux import utils


CONNTRACKD_SERVICE_NAME = 'conntrackd'


LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class ConfigBase(object):

    @abc.abstractmethod
    def build_config(self):
        """Build config file content."""
        pass


class ConntrackdUnix(ConfigBase):

    def __init__(self, path, backlog):
        self.path = path
        self.backlog = backlog

    def build_config(self):
        config = ['    UNIX {',
                  '        Path %s' % self.path,
                  '        Backlog %d' % self.backlog,
                  '    }']

        return config


class ConntrackdFilter(ConfigBase):

    def __init__(self, protocol_accept, address_ignore):
        self.protocol_accept = protocol_accept
        self.address_ignore = address_ignore

    def build_config(self):
        config = ['    Filter {',
                  '        Protocol Accept {',
                  '            %s' % self.protocol_accept,
                  '        }',
                  '        Address Ignore {',
                  '            %s' % self.address_ignore,
                  '        }',
                  '    }']

        return config


class ConntrackdGeneral(ConfigBase):

    def __init__(self, hash_size, hash_limit, syslog, lock_file,
                 unix, socket_buffer_size, socket_buffer_size_max_grown,
                 filter):
        self.hash_size = hash_size
        self.hash_limit = hash_limit
        self.syslog = syslog
        self.lock_file = lock_file
        self.unix = unix
        self.socket_buffer_size = socket_buffer_size
        self.socket_buffer_size_max_grown = socket_buffer_size_max_grown
        self.filter = filter

    def build_config(self):
        config = ['General {',
                  '    HashSize %d' % self.hash_size,
                  '    HashLimit %d' % self.hash_limit,
                  '    Syslog %s' % self.syslog,
                  '    LockFile %s' % self.lock_file]
        config.extend(self.unix.build_config())
        config.append('    SocketBufferSize %d' % self.socket_buffer_size)
        config.append(
            '    SocketBufferSizeMaxGrown %d' %
            self.socket_buffer_size_max_grown)
        config.extend(self.filter.build_config())
        config.append('}')

        return config


class ConntrackdMode(ConfigBase):

    def __init__(self, mode):
        self.mode = mode

    def build_config(self):
        config = ['    Mode %s{' % self.mode,
                  '    }']

        return config


class ConntrackdTransport(ConfigBase):

    def __init__(self, transport, default, ipv4_address,
                 ipv4_interface, group, interface, snd_socket_buffer,
                 rcv_socket_buffer, checksum):
        self.transport = transport
        self.default = default
        self.ipv4_address = ipv4_address
        self.ipv4_interface = ipv4_interface
        self.group = group
        self.interface = interface
        self.snd_socket_buffer = snd_socket_buffer
        self.rcv_socket_buffer = rcv_socket_buffer
        self.checksum = checksum

    def build_config(self):
        config = ['    %s %s{' % (self.transport, self.default),
                  '        IPv4_address %s' % self.ipv4_address,
                  '        IPv4_interface %s' % self.ipv4_interface,
                  '        Group %d' % self.group,
                  '        Interface %s' % self.interface,
                  '        SndSocketBuffer %d' % self.snd_socket_buffer,
                  '        RcvSocketBuffer %d' % self.rcv_socket_buffer,
                  '        Checksum %s' % self.checksum,
                  '    }']

        return config


class ConntrackdSync(ConfigBase):

    def __init__(self, mode, transport):
        self.mode = mode
        self.transport = transport

    def build_config(self):
        config = ['Sync {']
        config.extend(self.mode.build_config())
        config.extend(self.transport.build_config())
        config.append('}')

        return config


class ConntrackdConfig(ConfigBase):

    def __init__(self, general_config, sync_config):
        self.general_config = general_config
        self.sync_config = sync_config

    def build_config(self):
        config = []

        config.extend(self.general_config.build_config())
        config.extend(self.sync_config.build_config())

        return config


class ConntrackdManager(object):
    """Wrapper for conntrackd.

    This wrapper permits to write conntrackd config file,
    to start/restart conntrackd process.

    """

    def __init__(self, resource_id, config, process_monitor,
                 conf_path='/tmp', namespace=None):
        self.resource_id = resource_id
        self.config = config
        self.process_monitor = process_monitor
        self.conf_path = conf_path
        self.namespace = namespace

    def build_ha_script(self):
        ha_script_template = """#!/bin/sh
#
# (C) 2006-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Description:
#
# This is the script for primary-backup setups for keepalived
# (http://www.keepalived.org). You may adapt it to make it work with other
# high-availability managers.
#
# Do not forget to include the required modifications to your keepalived.conf
# file to invoke this script during keepalived's state transitions.
#
# Contributions to improve this script are welcome :).
#

CONNTRACKD_BIN=/usr/sbin/conntrackd
CONNTRACKD_LOCK=%(lock)s
CONNTRACKD_CONFIG=%(config)s

case "$1" in
  primary)
    #
    # commit the external cache into the kernel table
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -c
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -c"
    fi

    #
    # flush the internal and the external caches
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -f
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -f"
    fi

    #
    # resynchronize my internal cache to the kernel table
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -R
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -R"
    fi

    #
    # send a bulk update to backups
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -B
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -B"
    fi
    ;;
  backup)
    #
    # is conntrackd running? request some statistics to check it
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -s
    if [ $? -eq 1 ]
    then
        #
    # something's wrong, do we have a lock file?
    #
        if [ -f $CONNTRACKD_LOCK ]
    then
        logger "WARNING: conntrackd was not cleanly stopped."
        logger "If you suspect that it has crashed:"
        logger "1) Enable coredumps"
        logger "2) Try to reproduce the problem"
        logger "3) Post the coredump to netfilter-devel@vger.kernel.org"
        rm -f $CONNTRACKD_LOCK
    fi
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -d
    if [ $? -eq 1 ]
    then
        logger "ERROR: cannot launch conntrackd"
        exit 1
    fi
    fi
    #
    # shorten kernel conntrack timers to remove the zombie entries.
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -t
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -t"
    fi

    #
    # request resynchronization with master firewall replica (if any)
    # Note: this does nothing in the alarm approach.
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -n
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -n"
    fi
    ;;
  fault)
    #
    # shorten kernel conntrack timers to remove the zombie entries.
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -t
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -t"
    fi
    ;;
  *)
    logger "ERROR: unknown state transition"
    echo "Usage: primary-backup.sh {primary|backup|fault}"
    exit 1
    ;;
esac

exit 0
"""
        ha_script_content = ha_script_template % dict(
            lock=self.config.general_config.lock_file,
            config=self.get_full_config_file_path('conntrackd.conf'))
        ha_script_path = self.get_ha_script_path()

        file_utils.replace_file(ha_script_path, ha_script_content)
        os.chmod(ha_script_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def get_ha_script_path(self, ensure_conf_dir=True):
        conf_dir = self.get_conf_dir()
        if ensure_conf_dir:
            ensure_tree(conf_dir, 0o755)
        return os.path.join(conf_dir, 'primary-backup.sh')

    def _get_pid_file_path(self):
        return self.get_full_config_file_path('conntrackd.pid')

    def _create_pid_file(self):
        config_path = self.get_full_config_file_path('conntrackd.conf')
        pid_file = self._get_pid_file_path()

        cmd = 'conntrackd -d -C %s' % config_path
        pids = utils.find_pids_by_cmd(cmd)

        if pids:
            pid = pids[0]
            file_utils.replace_file(pid_file, pid)
        else:
            raise RuntimeError('No conntrackd process found.')

    def get_conf_on_disk(self):
        config_path = self.get_full_config_file_path('conntrackd.conf')
        try:
            with open(config_path) as conf:
                return conf.read()
        except (OSError, IOError) as e:
            if e.errno != errno.ENOENT:
                raise

    def spawn(self):
        config_path = self._output_config_file()
        self.build_ha_script()

        def callback(pidfile):
            cmd = ['conntrackd', '-d',
                   '-C', config_path]
            return cmd

        def pre_cmd_callback():
            # conntrack.lock & conntrackd.ctl must be removed before
            # start a new conntrackd.
            lock_file = self.config.general_config.lock_file
            ctl_file = self.config.general_config.unix.path

            cmd = ['rm', '-f', lock_file]
            utils.execute(cmd, run_as_root=True, check_exit_code=False)
            cmd = ['rm', '-f', ctl_file]
            utils.execute(cmd, run_as_root=True, check_exit_code=False)

        def post_cmf_callback():
            self._create_pid_file()

        pm = self.get_process(callback=callback,
                              pre_cmd_callback=pre_cmd_callback,
                              post_cmd_callback=post_cmf_callback)
        pm.enable(reload_cfg=False)
        self._create_pid_file()

        self.process_monitor.register(uuid=self.resource_id,
                                      service_name=CONNTRACKD_SERVICE_NAME,
                                      monitored_process=pm)

        LOG.debug('Conntrackd spawned with config %s', self.conf_path)

    def get_process(self, callback=None, pre_cmd_callback=None,
                    post_cmd_callback=None):
        return external_process.ProcessManager(
            cfg.CONF,
            self.resource_id,
            self.namespace,
            default_cmd_callback=callback,
            default_pre_cmd_callback=pre_cmd_callback,
            default_post_cmd_callback=post_cmd_callback,
            pid_file=self._get_pid_file_path())

    def disable(self):
        self.process_monitor.unregister(uuid=self.resource_id,
                                        service_name=CONNTRACKD_SERVICE_NAME)

        config_path = self.get_full_config_file_path('conntrackd.conf')
        cmd = ['conntrackd', '-C', config_path, '-k']
        utils.execute(cmd, run_as_root=True)

    def _output_config_file(self):
        config_str = self.get_config_str()
        config_path = self.get_full_config_file_path('conntrackd.conf')
        file_utils.replace_file(config_path, config_str)

        return config_path

    def get_full_config_file_path(self, filename, ensure_conf_dir=True):
        conf_dir = self.get_conf_dir()
        if ensure_conf_dir:
            ensure_tree(conf_dir, 0o755)
        return os.path.join(conf_dir, filename)

    def get_conf_dir(self):
        confs_dir = os.path.abspath(os.path.normpath(self.conf_path))
        conf_dir = os.path.join(confs_dir, self.resource_id)
        return conf_dir

    def get_config_str(self):
        return '\n'.join(self.build_config())

    def build_config(self):
        return self.config.build_config()
