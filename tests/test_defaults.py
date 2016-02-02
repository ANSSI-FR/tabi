import collections

from tabi.parallel.core import InternalMessage, DefaultRoute


# Abstracted BGP UPDATE messages
default_update4      = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                     "0.0.0.0/0", 64497, "64497 64497 64497")
default_update6     = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                     "::/0", 64497, "64497 64497 64497")
non_default_update  = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                     "1.0.0.0/1", 64497, "64497 64497 64497")


# Expected output messages
expected_message_announce4 = collections.OrderedDict([ ("prefix", "0.0.0.0/0"),
                                                     ("asn", 64497,),
                                                     ("as_path", "64497 64497 64497") ])
expected_message_announce6 = collections.OrderedDict([ ("prefix", "::/0"),
                                                     ("asn", 64497,),
                                                     ("as_path", "64497 64497 64497") ])
expected_message4 = collections.OrderedDict([ ("timestamp", 2807),
                                              ("collector", "collector"),
                                              ("peer_as", 64496),
                                              ("peer_ip", "127.0.0.1"),
                                              ("announce", expected_message_announce4) ])
expected_message6 = collections.OrderedDict([ ("timestamp", 2807),
                                              ("collector", "collector"),
                                              ("peer_as", 64496),
                                              ("peer_ip", "127.0.0.1"),
                                              ("announce", expected_message_announce6) ])


class TestDefault:

  def test_non_default_process(self):
    """Check that non default prefixes are not processed."""

    default_route = DefaultRoute()
    assert default_route.process(non_default_update) == []

  def test_default_ipv4_message(self):
    """Check the format of the output message with the default IPv4 prefix."""

    default_route = DefaultRoute()
    assert default_route.message(default_update4) == expected_message4

  def test_default_ipv6_message(self):
    """Check the format of the output message with the default IPv6 prefix."""

    default_route = DefaultRoute()
    assert default_route.message(default_update6) == expected_message6

  def test_default_ipv4_process(self):
    """Check the full processing of the default IPv4 prefix."""

    default_route = DefaultRoute()
    assert default_route.process(default_update4) == [ expected_message4 ]

  def test_default_ipv6_process(self):
    """Check the full processing of the default IPv6 prefix."""

    default_route = DefaultRoute()
    assert default_route.process(default_update6) == [ expected_message6 ]
