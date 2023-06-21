#!/usr/bin/env python3
#
#  Copyright (c) 2023, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
import ipaddress
import json
import logging
import unittest

import config
import thread_cert

# Test description:
#   This test verifies DNS-SD server can work well in a multiple border router scenario. The DNS-SD server can answer
#   queries from the Host.
#   BR1 is the SRP server and BR2 is the DNS-SD server.
# Topology:
#    ----------------(eth)-----------------------
#           |                   |
#          BR1                 HOST
#           |
#        +--+----+
#        |       |
#    CLIENT1  CLIENT2
#

BR1 = 1
ED1, ED2 = 2, 3
HOST = 4

DOMAIN = 'default.service.arpa.'
SERVICE = '_testsrv._udp'
SERVICE_FULL_NAME = f'{SERVICE}.{DOMAIN}'

VALID_SERVICE_NAMES = [
    '_abc._udp.default.service.arpa.',
    '_abc._tcp.default.service.arpa.',
]

class TestDnssdServerWithMultiClient(thread_cert.TestCase):
    USE_MESSAGE_FACTORY = False

    TOPOLOGY = {
        BR1: {
            'name': 'BR1',
            'is_otbr': True,
            'version': '1.2',
            'allowlist': [ED1, ED2],
        },
        ED1: {
            'name': 'ED1',
            'mode': 'rn',
            'allowlist': [BR1]
        },
        ED2: {
            'name': 'ED2',
            'mode': 'rn',
            'allowlist': [BR1],
        },
        HOST: {
            'name': 'Host',
            'is_host': True
        },
    }

    def test(self):
        br1 = self.nodes[BR1]
        ed1 = self.nodes[ED1]
        ed2 = self.nodes[ED2]
        host = self.nodes[HOST]

        host.start(start_radvd=False)
        self.simulator.go(5)

        br1.start()
        self.simulator.go(config.LEADER_STARTUP_DELAY)
        self.assertEqual('leader', br1.get_state())
        br1.srp_server_set_enabled(True)
        br1.dns_upstream_query_state = False

        ed1.start()
        self.simulator.go(5)
        self.assertEqual('child', ed1.get_state())

        ed2.start()
        self.simulator.go(5)
        self.assertEqual('child', ed2.get_state())

        self.simulator.go(10)

        br1_addr = br1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0]

        # 2. Check the host & service published by a WiFi host.
        # check if AAAA query works
        wifi_host_linklocal_address = 'fe80::1234'
        wifi_host_routable_address = '2402::abcd'
        wifi_host_full_name = f'wifi-host.{DOMAIN}'
        wifi_service_instance_full_name = f'wifi-service._host._tcp.{DOMAIN}'
        host.publish_mdns_host('wifi-host', [wifi_host_linklocal_address, wifi_host_routable_address])
        host.publish_mdns_service('wifi-service1', '_host._tcp', 12345, 'wifi-host', {'k1': 'v1', 'k2': 'v2'})
        host.publish_mdns_service('wifi-service2', '_host._tcp', 12346, 'wifi-host', {'k1': 'v1', 'k2': 'v2'})

        self.simulator.go(5)

        ed1.dns_resolve_service_instant('wifi-service1', f'_host._tcp.{DOMAIN}'.upper(), br1.get_mleid(), 53)
        ed1.dns_resolve_service_instant('wifi-service3', f'_host._tcp.{DOMAIN}'.upper(), br1.get_mleid(), 53)
        ed2.dns_resolve_service_instant('wifi-service2', f'_host._tcp.{DOMAIN}'.upper(), br1.get_mleid(), 53)
        ed2.dns_resolve_service_instant('wifi-service4', f'_host._tcp.{DOMAIN}'.upper(), br1.get_mleid(), 53)

        
        dig_result = host.dns_dig(br1_addr, wifi_host_full_name, 'AAAA')
        self._assert_dig_result_matches(
            dig_result, {
                'QUESTION': [(wifi_host_full_name, 'IN', 'AAAA')],
                'ANSWER': [(wifi_host_full_name, 'IN', 'AAAA', wifi_host_routable_address),],
            })

        host.bash('pkill avahi-publish')

    def _assert_have_question(self, dig_result, question):
        for dig_question in dig_result['QUESTION']:
            if self._match_record(dig_question, question):
                return

        self.fail((dig_result, question))

    def _assert_have_answer(self, dig_result, record, additional=False):
        for dig_answer in dig_result['ANSWER' if not additional else 'ADDITIONAL']:
            dig_answer = list(dig_answer)
            dig_answer[1:2] = []  # remove TTL from answer

            record = list(record)

            # convert IPv6 addresses to `ipaddress.IPv6Address` before matching
            if dig_answer[2] == 'AAAA':
                dig_answer[3] = ipaddress.IPv6Address(dig_answer[3])

            if record[2] == 'AAAA':
                record[3] = ipaddress.IPv6Address(record[3])

            if self._match_record(dig_answer, record):
                return

            print('not match: ', dig_answer, record,
                  list(a == b or (callable(b) and b(a)) for a, b in zip(dig_answer, record)))

        self.fail((record, dig_result))

    def _match_record(self, record, match):
        assert not any(callable(elem) for elem in record), record

        if record == match:
            return True

        return all(a == b or (callable(b) and b(a)) for a, b in zip(record, match))

    def _assert_dig_result_matches(self, dig_result, expected_result):
        self.assertEqual(dig_result['opcode'], expected_result.get('opcode', 'QUERY'), dig_result)
        self.assertEqual(dig_result['status'], expected_result.get('status', 'NOERROR'), dig_result)

        if 'QUESTION' in expected_result:
            self.assertEqual(len(dig_result['QUESTION']), len(expected_result['QUESTION']), dig_result)

            for question in expected_result['QUESTION']:
                self._assert_have_question(dig_result, question)

        if 'ANSWER' in expected_result:
            self.assertEqual(len(dig_result['ANSWER']), len(expected_result['ANSWER']), dig_result)

            for record in expected_result['ANSWER']:
                self._assert_have_answer(dig_result, record, additional=False)

        if 'ADDITIONAL' in expected_result:
            self.assertGreaterEqual(len(dig_result['ADDITIONAL']), len(expected_result['ADDITIONAL']), dig_result)

            for record in expected_result['ADDITIONAL']:
                self._assert_have_answer(dig_result, record, additional=True)

        logging.info("dig result matches:\r%s", json.dumps(dig_result, indent=True))

if __name__ == '__main__':
    unittest.main()
