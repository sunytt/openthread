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
import unittest

import config
import thread_cert

# Test description:
#   This test verifies TREL service discovery.
#
# Topology:
#    ----------------(eth)--------------------------
#           |               |
#       BR1 (Leader) ----- BR2
#
#
from config import PACKET_VERIFICATION_TREL
from pktverify.packet_filter import PacketFilter
from pktverify.packet_verifier import PacketVerifier

BR1 = 1
BR2 = 2


class TestTrelServiceDiscovery(thread_cert.TestCase):
    USE_MESSAGE_FACTORY = False
    PACKET_VERIFICATION = PACKET_VERIFICATION_TREL

    TOPOLOGY = {
        BR1: {
            'name': 'BR1',
            'allowlist': [BR2],
            'is_otbr': True,
            'version': '1.2',
        },
        BR2: {
            'name': 'BR2',
            'allowlist': [BR1, ROUTER2],
            'is_otbr': True,
            'version': '1.2',
        },
    }

    def test(self):
        br1 = self.nodes[BR1]
        br2 = self.nodes[BR2]

        if br1.is_trel_enabled() is None:
            self.skipTest("TREL is not supported")

        if br1.is_trel_enabled() == False:
            br1.enable_trel()

        if br2.is_trel_enabled() == False:
            br2.enable_trel()

        br1.start()
        self.wait_node_state(br1, 'leader', 10)

        br2.start()
        self.wait_node_state(br2, 'router', 10)

        # Allow the network to stabilize
        self.simulator.go(config.BORDER_ROUTER_STARTUP_DELAY)

        self.collect_ipaddrs()
        self.collect_rloc16s()

        br2_mleid = br2.get_mleid()
        self.assertTrue(br1.ping(br2_mleid))

        br1_addrs = br1.get_ether_addrs()
        print(br1_addrs)
        br2_addrs = br2.get_ether_addrs()
        print(br2_addrs)

        br1_trel_peers = br1.get_trel_peers()
        print(br1_trel_peers)
        br2_trel_peers = br2.get_trel_peers()
        print(br2_trel_peers)

        br1.disable_ether()
        br2.disable_ether()
        br1.enable_ether()
        br2.enable_ether()

        self.simulator.go(5)

        br1_addrs = br1.get_ether_addrs()
        print(br1_addrs)
        br2_addrs = br2.get_ether_addrs()
        print(br2_addrs)

        br1_trel_peers = br1.get_trel_peers()
        print(br1_trel_peers)
        br2_trel_peers = br2.get_trel_peers()
        print(br2_trel_peers)


    def verify(self, pv: PacketVerifier):
        pkts: PacketFilter = pv.pkts
        BR1_RLOC16 = pv.vars['BR1_RLOC16']
        BR2_RLOC16 = pv.vars['BR2_RLOC16']

        print('BR1_RLOC16:', hex(BR1_RLOC16))
        print('BR2_RLOC16:', hex(BR2_RLOC16))

        # Make sure BR1 and BR2 always use TREL for transmitting ping request and reply
        pkts.filter_wpan_src16_dst16(BR1_RLOC16, BR2_RLOC16).filter_ping_request().must_not_next()
        pkts.filter_wpan_src16_dst16(BR1_RLOC16, BR2_RLOC16).filter_ping_reply().must_not_next()

        pkts.filter_wpan_src16_dst16(BR2_RLOC16, BR1_RLOC16).filter_ping_request().must_not_next()
        pkts.filter_wpan_src16_dst16(BR2_RLOC16, BR1_RLOC16).filter_ping_reply().must_not_next()


if __name__ == '__main__':
    unittest.main()
