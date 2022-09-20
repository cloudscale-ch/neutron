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

from neutron.agent.linux import conntrackd
from neutron.tests import base


class ConntrackdUnixTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['    UNIX {',
                    '        Path /var/run/conntrackd.ctl',
                    '        Backlog 20',
                    '    }']
        return expected

    def get_instance(self):
        conntrackd_unix = conntrackd.ConntrackdUnix(
            path='/var/run/conntrackd.ctl', backlog=20)
        return conntrackd_unix

    def test_build_config(self):
        conntrackd_unix = self.get_instance()
        config = conntrackd_unix.build_config()
        self.assertEqual(self.get_expected(), config)


class ConntrackdFilterTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['    Filter {',
                    '        Protocol Accept {',
                    '            TCP',
                    '        }',
                    '        Address Ignore {',
                    '            IPv4_address 127.0.0.1',
                    '        }',
                    '    }']
        return expected

    def get_instance(self):
        conntrackd_filter = conntrackd.ConntrackdFilter(
            protocol_accept='TCP',
            address_ignore='IPv4_address 127.0.0.1')
        return conntrackd_filter

    def test_build_config(self):
        conntrackd_filter = self.get_instance()
        config = conntrackd_filter.build_config()
        self.assertEqual(self.get_expected(), config)


class ConntrackdGeneralTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['General {',
                    '    HashSize 8192',
                    '    HashLimit 65535',
                    '    Syslog on',
                    '    LockFile /var/lock/conntrack.lock',
                    '    UNIX {',
                    '        Path /var/run/conntrackd.ctl',
                    '        Backlog 20',
                    '    }',
                    '    SocketBufferSize 262142',
                    '    SocketBufferSizeMaxGrown 655355',
                    '    Filter {',
                    '        Protocol Accept {',
                    '            TCP',
                    '        }',
                    '        Address Ignore {',
                    '            IPv4_address 127.0.0.1',
                    '        }',
                    '    }',
                    '}']
        return expected

    def get_instance(self):
        conntrackd_general = conntrackd.ConntrackdGeneral(
            hash_size=8192, hash_limit=65535, syslog='on',
            lock_file='/var/lock/conntrack.lock',
            unix=conntrackd.ConntrackdUnix(
                path='/var/run/conntrackd.ctl', backlog=20),
            socket_buffer_size=262142,
            socket_buffer_size_max_grown=655355,
            filter=conntrackd.ConntrackdFilter(
                protocol_accept='TCP',
                address_ignore='IPv4_address 127.0.0.1')
        )
        return conntrackd_general

    def test_build_config(self):
        conntrackd_general = self.get_instance()
        config = conntrackd_general.build_config()
        self.assertEqual(self.get_expected(), config)


class ConntrackdModeTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['    Mode FTFW{',
                    '    }']
        return expected

    def get_instance(self):
        conntrackd_mode = conntrackd.ConntrackdMode('FTFW')
        return conntrackd_mode

    def test_build_config(self):
        conntrackd_mode = self.get_instance()
        config = conntrackd_mode.build_config()
        self.assertEqual(self.get_expected(), config)


class ConntrackdTransporTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['    Multicast Default{',
                    '        IPv4_address 225.0.0.50',
                    '        IPv4_interface 192.168.0.5',
                    '        Group 3780',
                    '        Interface eth0',
                    '        SndSocketBuffer 24985600',
                    '        RcvSocketBuffer 24985600',
                    '        Checksum on',
                    '    }']
        return expected

    def get_instance(self):
        conntrackd_transport = conntrackd.ConntrackdTransport(
            transport='Multicast', default='Default',
            ipv4_address='225.0.0.50', ipv4_interface='192.168.0.5',
            group=3780, interface='eth0', snd_socket_buffer=24985600,
            rcv_socket_buffer=24985600, checksum='on')
        return conntrackd_transport

    def test_build_config(self):
        conntrackd_transport = self.get_instance()
        config = conntrackd_transport.build_config()
        self.assertEqual(self.get_expected(), config)


class ConntrackdSyncTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['Sync {',
                    '    Mode FTFW{',
                    '    }',
                    '    Multicast Default{',
                    '        IPv4_address 225.0.0.50',
                    '        IPv4_interface 192.168.0.5',
                    '        Group 3780',
                    '        Interface eth0',
                    '        SndSocketBuffer 24985600',
                    '        RcvSocketBuffer 24985600',
                    '        Checksum on',
                    '    }',
                    '}']
        return expected

    def get_instance(self):
        conntrackd_sync = conntrackd.ConntrackdSync(
            mode=conntrackd.ConntrackdMode(mode='FTFW'),
            transport=conntrackd.ConntrackdTransport(
                transport='Multicast', default='Default',
                ipv4_address='225.0.0.50', ipv4_interface='192.168.0.5',
                group=3780, interface='eth0', snd_socket_buffer=24985600,
                rcv_socket_buffer=24985600, checksum='on'))
        return conntrackd_sync

    def test_build_config(self):
        conntrackd_sync = self.get_instance()
        config = conntrackd_sync.build_config()
        self.assertEqual(self.get_expected(), config)


class ConntrackdConfigTestCase(base.BaseTestCase):

    def get_expected(self):
        expected = ['General {',
                    '    HashSize 8192',
                    '    HashLimit 65535',
                    '    Syslog on',
                    '    LockFile /var/lock/conntrack.lock',
                    '    UNIX {',
                    '        Path /var/run/conntrackd.ctl',
                    '        Backlog 20',
                    '    }',
                    '    SocketBufferSize 262142',
                    '    SocketBufferSizeMaxGrown 655355',
                    '    Filter {',
                    '        Protocol Accept {',
                    '            TCP',
                    '        }',
                    '        Address Ignore {',
                    '            IPv4_address 127.0.0.1',
                    '        }',
                    '    }',
                    '}',
                    'Sync {',
                    '    Mode FTFW{',
                    '    }',
                    '    Multicast Default{',
                    '        IPv4_address 225.0.0.50',
                    '        IPv4_interface 192.168.0.5',
                    '        Group 3780',
                    '        Interface eth0',
                    '        SndSocketBuffer 24985600',
                    '        RcvSocketBuffer 24985600',
                    '        Checksum on',
                    '    }',
                    '}']
        return expected

    def get_instance(self):
        conntrackd_config = conntrackd.ConntrackdConfig(
            general_config=conntrackd.ConntrackdGeneral(
                hash_size=8192, hash_limit=65535, syslog='on',
                lock_file='/var/lock/conntrack.lock',
                unix=conntrackd.ConntrackdUnix(
                    path='/var/run/conntrackd.ctl', backlog=20),
                socket_buffer_size=262142,
                socket_buffer_size_max_grown=655355,
                filter=conntrackd.ConntrackdFilter(
                    protocol_accept='TCP',
                    address_ignore='IPv4_address 127.0.0.1')),
            sync_config=conntrackd.ConntrackdSync(
                mode=conntrackd.ConntrackdMode(mode='FTFW'),
                transport=conntrackd.ConntrackdTransport(
                    transport='Multicast', default='Default',
                    ipv4_address='225.0.0.50', ipv4_interface='192.168.0.5',
                    group=3780, interface='eth0', snd_socket_buffer=24985600,
                    rcv_socket_buffer=24985600, checksum='on')))
        return conntrackd_config

    def test_build_config(self):
        conntrackd_config = self.get_instance()
        config = conntrackd_config.build_config()
        self.assertEqual(self.get_expected(), config)
