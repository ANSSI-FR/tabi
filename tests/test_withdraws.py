import collections

from tabi.parallel.core import InternalMessage, RouteInformation, HijackInformation, Route, Hijack, Withdraw, bview_fake_withdraw
from tabi.parallel.rib import EmulatedRIB


# Abstracted BGP UPDATE messages
update4 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                          "1.2.3.0/24", 64497, "64496 64499 64497")

update4_2 = InternalMessage(2807, "collector", 64498, "127.0.0.2",
                            "1.2.3.0/24", 64497, "64498 64499 64497")

withdraw4 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "1.2.3.0/24", None, None)

useless_withdraw4 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                    "2.0.0.0/8", None, None)

withdraw4_2 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                              "1.2.3.4/32", None, None)

hijack4_specific = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                   "1.2.3.4/32", 666, "64496 64499 666")

hijack4 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                          "1.2.3.0/24", 666, "64496 64499 666")


# Expected output messages
expected_regular_withdraw4 = collections.OrderedDict([ ("timestamp", 2807),
                                                       ("collector", "collector"),
                                                       ("peer_as", 64496),    
                                                       ("peer_ip", "127.0.0.1"),    
                                                       ("action", "W"),
                                                       ("prefix", "1.2.3.0/24"),
                                                       ("asn", 64497) ]) 

withdraw_specific_hijack4 = collections.OrderedDict([ ("prefix", "1.2.3.4/32"),
                                                      ("asn", 666) ])
expected_specific_hijack_withdraw4 = collections.OrderedDict([ ("timestamp", 2807),
                                                       ("collector", "collector"),
                                                       ("peer_as", 64496),    
                                                       ("peer_ip", "127.0.0.1"),    
                                                       ("type", "W"),
                                                       ("withdraw", withdraw_specific_hijack4),
                                                       ("asn", 64497) ]) 

withdraw_hijack4 = collections.OrderedDict([ ("prefix", "1.2.3.0/24"),
                                             ("asn", 666) ])
expected_hijack_withdraw4 = collections.OrderedDict([ ("timestamp", 2807),
                                                      ("collector", "collector"),
                                                      ("peer_as", 64496),    
                                                      ("peer_ip", "127.0.0.1"),    
                                                      ("type", "W"),
                                                      ("withdraw", withdraw_hijack4),
                                                      ("asn", 64497) ]) 

expected_fake_withdraw_route = collections.OrderedDict([ ("timestamp", 42),
                                                         ("collector", "collector"),
                                                         ("peer_as", 64496),
                                                         ("peer_ip", "127.0.0.1"),
                                                         ("action", "FW"),
                                                         ("prefix", "1.2.3.0/24"),
                                                         ("asn", 64497) ])

expected_fake_withdraw_hijack = collections.OrderedDict([ ("timestamp", 42),
                                                          ("collector", "collector"),
                                                          ("peer_as", 64496),
                                                          ("peer_ip", "127.0.0.1"),
                                                          ("type", "FW"),
                                                          ("withdraw",
                                                            collections.OrderedDict([ ("prefix", "1.2.3.0/24"),
                                                                                      ("asn", 666) ]) ),
                                                          ("asn", 64497) ])

class TestWithdraw:

  def test_withdraw_message(self):
    """Check the format of the output WITHDRAW messages."""

    withdraw = Withdraw(EmulatedRIB())
    information = RouteInformation(64497, None, None)
    assert withdraw.message(withdraw4, information) == expected_regular_withdraw4

    information = HijackInformation(64497, 666, None, None)
    assert withdraw.message(withdraw4, information) == expected_hijack_withdraw4

  def test_useless_withdraw(self):
    """Check that a useless WITHDRAW does nothing."""

    rib = EmulatedRIB()

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Process a hijack
    hijack = Hijack(rib, 0)
    hijack.process(hijack4_specific)

    # Process a uselss WITHDRAW
    withdraw = Withdraw(rib)
    route_messages, hijack_messages = withdraw.process(useless_withdraw4)

    assert len(route_messages + hijack_messages) == 0

  def test_regular_withdraw(self):
    """Check that a WITHDRAW is correctly processed."""

    rib = EmulatedRIB()

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Process a WITHDRAW
    withdraw = Withdraw(rib)
    route_messages, hijack_messages = withdraw.process(withdraw4)

    assert route_messages == [ expected_regular_withdraw4 ]
    assert len(hijack_messages) == 0
    assert len(rib.nodes()) == 0

  def test_withdraw_different_peers(self):
    """Check that a WITHDRAW only applies to a peer."""

    rib = EmulatedRIB()

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)
    route.process(update4_2)

    # Process a WITHDRAW
    withdraw = Withdraw(rib)
    route_messages, hijack_messages = withdraw.process(withdraw4)

    assert route_messages == [ expected_regular_withdraw4 ]
    assert len(hijack_messages) == 0
    assert len(rib.nodes()) == 1

  def test_hijack_withdraw(self):
    """Check that a WITHDRAW concerning a hijack is correctly processed."""

    rib = EmulatedRIB()
    rib.set_access_time(0)

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Process the hijack
    hijack = Hijack(rib, "F")
    hijack.process(hijack4_specific)

    # Process a WITHDRAW
    withdraw = Withdraw(rib)
    route_messages, hijack_messages = withdraw.process(withdraw4_2)

    assert len(route_messages) == 0
    assert hijack_messages == [ expected_specific_hijack_withdraw4 ]

    ri = RouteInformation(origin_asn=64497, peer_as=64496, peer_ip='127.0.0.1')
    nodes_data = map(lambda x: (x.prefix, x.data), rib.nodes())
    assert nodes_data == [ ("1.2.3.0/24", { "routes_information": { ri: 0 } }) ]

  def test_route_and_hijack_withdraw(self):
    """Check that a WITHDRAW concerning a route and a hijack is correctly processed."""

    rib = EmulatedRIB()

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Process the hijack
    hijack = Hijack(rib, "F")
    hijack.process(hijack4)

    # Process a WITHDRAW
    withdraw = Withdraw(rib)
    route_messages, hijack_messages = withdraw.process(withdraw4)

    assert route_messages == [ expected_regular_withdraw4 ]
    assert hijack_messages == [ expected_hijack_withdraw4 ]
    assert len(rib.nodes()) == 0

  def test_bview_fake_withdraw_nothing(self):
    """Check the bview_fake_withdraw() behavior when there is nothing to do."""

    rib = EmulatedRIB()
    rib.set_access_time(0)

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Pretend to do a withdraw
    route_messages, hijack_messages = bview_fake_withdraw(rib, "collector", 0, 42)

    assert len(route_messages) == 0
    assert len(hijack_messages) == 0
    assert len(rib.nodes()) == 1

  def test_bview_fake_withdraw_route(self):
    """Check the bview_fake_withdraw() behavior with regular routes."""

    rib = EmulatedRIB()
    rib.set_access_time(0)

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Pretend to do a withdraw
    route_messages, hijack_messages = bview_fake_withdraw(rib, "collector", 1, 42)

    assert len(route_messages) == 1
    assert route_messages[0] == expected_fake_withdraw_route
    assert len(hijack_messages) == 0

    assert len(rib.nodes()) == 0

  def test_bview_fake_withdraw_both(self):
    """Check the bview_fake_withdraw() behavior with both a route and a hijack."""

    rib = EmulatedRIB()
    rib.set_access_time(0)

    # Process an UPDATE
    route = Route(rib)
    route.process(update4)

    # Process the hijack
    hijack = Hijack(rib, "F")
    hijack.process(hijack4)

    # Pretend to do a withdraw
    route_messages, hijack_messages = bview_fake_withdraw(rib, "collector", 1, 42)

    assert len(route_messages) == 1
    assert route_messages[0] == expected_fake_withdraw_route
    assert hijack_messages[0] == expected_fake_withdraw_hijack
    assert len(hijack_messages) == 1

    assert len(rib.nodes()) == 0
