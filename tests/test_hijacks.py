import collections

from tabi.parallel.core import InternalMessage, Route, Hijack, Withdraw
from tabi.parallel.rib import EmulatedRIB


# Abstracted BGP UPDATE messages
update4_1 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "1.2.0.0/16", 64497, "64496 64499 64497")
update4_2 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "1.0.0.0/8", 64497, "64496 64499 64497")
update4_3 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "1.0.0.0/8", 64498, "64496 64499 64498")

hijack4_exact = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                "1.2.0.0/16", 666, "64496 64499 666")

hijack4_specific = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                                   "1.2.3.0/24", 666, "64496 64499 666")

hijack4_peer = InternalMessage(2807, "collector", 64500, "127.0.0.2",
                               "1.0.0.0/8", 666, "64500 64499 666")


# Expected output messages
conflict_with4_1 = collections.OrderedDict([ ("prefix", "1.2.0.0/16"),  
                                           ("asn", 64497) ])      
conflict_with4_2 = collections.OrderedDict([ ("prefix", "1.0.0.0/8"),  
                                           ("asn", 64497) ])      
conflict_with4_3 = collections.OrderedDict([ ("prefix", "1.0.0.0/8"),  
                                           ("asn", 64498) ])      
                                                                          
announce4_exact = collections.OrderedDict([ ("prefix", "1.2.0.0/16"),              
                                            ("asn", 666),                    
                                            ("as_path",  "64496 64499 666") ])          
announce4_specific = collections.OrderedDict([ ("prefix", "1.2.3.0/24"),              
                                               ("asn", 666),                    
                                               ("as_path",  "64496 64499 666") ])          
announce4_peer = collections.OrderedDict([ ("prefix", "1.0.0.0/8"),              
                                           ("asn", 666),                    
                                           ("as_path",  "64500 64499 666") ])          

expected_message4_exact_1 = collections.OrderedDict([ ("timestamp", 2807),         
                                                    ("collector", "collector"),         
                                                    ("peer_as", 64496),             
                                                    ("peer_ip", "127.0.0.1"),             
                                                    ("type", "F"),            
                                                    ("announce", announce4_exact),         
                                                    ("conflict_with", conflict_with4_1),
                                                    ("asn", 64497) ])
expected_message4_exact_2 = collections.OrderedDict([ ("timestamp", 2807),         
                                                    ("collector", "collector"),         
                                                    ("peer_as", 64496),             
                                                    ("peer_ip", "127.0.0.1"),             
                                                    ("type", "F"),            
                                                    ("announce", announce4_exact),         
                                                    ("conflict_with", conflict_with4_2),
                                                    ("asn", 64497) ])

expected_message4_specific_1 = collections.OrderedDict([ ("timestamp", 2807),         
                                                       ("collector", "collector"),         
                                                       ("peer_as", 64496),             
                                                       ("peer_ip", "127.0.0.1"),             
                                                       ("type", "F"),            
                                                       ("announce", announce4_specific),         
                                                       ("conflict_with", conflict_with4_1) ,
                                                       ("asn", 64497) ])
expected_message4_specific_2 = collections.OrderedDict([ ("timestamp", 2807),         
                                                       ("collector", "collector"),         
                                                       ("peer_as", 64496),             
                                                       ("peer_ip", "127.0.0.1"),             
                                                       ("type", "F"),            
                                                       ("announce", announce4_specific),         
                                                       ("conflict_with", conflict_with4_2),
                                                       ("asn", 64497) ])
expected_message4_specific_3 = collections.OrderedDict([ ("timestamp", 2807),         
                                                       ("collector", "collector"),         
                                                       ("peer_as", 64496),             
                                                       ("peer_ip", "127.0.0.1"),             
                                                       ("type", "F"),            
                                                       ("announce", announce4_specific),         
                                                       ("conflict_with", conflict_with4_3),
                                                       ("asn", 64498) ])


class TestHijack:

  def test_hijack_ipv4_message(self):
    """Check the format of the output message with the conflicting IPv4 prefix."""

    hijack = Hijack(None, "F")
    assert hijack.message(hijack4_exact, "1.2.0.0/16", 64497) == expected_message4_exact_1

  def test_update_ipv4_hijack(self):
    """Check if IPv4 hijacks are correcty processed."""

    # Setup the internal objects
    rib = EmulatedRIB()
    route = Route(rib)
    route.process(update4_1)

    # Process the exact hijack
    hijack = Hijack(rib, "F")
    messages = hijack.process(hijack4_exact)

    assert messages == [ expected_message4_exact_1 ]

    # Process the specific hijack
    messages = hijack.process(hijack4_specific)

    assert messages == [ expected_message4_specific_1 ]

  def test_update_ipv4_several_hijacks(self):
    """Check if multiple IPv4 hijacks are correcty processed."""

    # Setup the internal objects
    rib = EmulatedRIB()
    route = Route(rib)
    route.process(update4_1)
    route.process(update4_2)

    # Process the exact hijack
    hijack = Hijack(rib, "F")
    messages = hijack.process(hijack4_exact)

    assert messages == [ expected_message4_exact_1, expected_message4_exact_2 ]

    # Process the specific hijack
    messages = hijack.process(hijack4_specific)

    assert messages == [ expected_message4_specific_1, expected_message4_specific_2  ]

  def test_update_ipv4_several_origins_hijacks(self):
    """Check if hijacks against different origins are correcty processed."""

    rib = EmulatedRIB()

    # Process the update message
    route = Route(rib)
    route.process(update4_2)
    route.process(update4_3)

    # Process the hijack
    hijack = Hijack(rib, "F")
    messages = hijack.process(hijack4_specific)

    assert messages == [ expected_message4_specific_2, expected_message4_specific_3 ]


  def test_hijacks_different_peers(self):
    """Check if hijacks from different peers are correctly processed."""

    # Setup the internal objects
    rib = EmulatedRIB()
    route = Route(rib)
    hijack = Hijack(rib, "U")
    withdraw = Withdraw(rib)

    # A prefix is seen from peer_as 0
    different_peers_update1 = InternalMessage(0, "collector", 0, "127.0.0.1",
                                              "2011:db8::/32", 10, "0 10")
    expected_different_peers_update1 = collections.OrderedDict([ ("timestamp", 0),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("action", "A"),
                                         ("prefix", "2011:db8::/32"), 
                                         ("as_path", "0 10"), ("asn", 10)])
    messages = route.process(different_peers_update1)
    assert messages == [ expected_different_peers_update1 ]

    # The same prefix is seen from peer_as 1
    different_peers_update2 = InternalMessage(0, "collector", 1, "127.0.0.2",
                                              "2011:db8::/32", 10, "1 10")
    expected_different_peers_update2 = collections.OrderedDict([ ("timestamp", 0),
                                         ("collector", "collector"),
                                         ("peer_as", 1), ("peer_ip", "127.0.0.2"),
                                         ("action", "A"),
                                         ("prefix", "2011:db8::/32"), 
                                         ("as_path", "1 10"), ("asn", 10)])
    messages = route.process(different_peers_update2)
    assert messages == [ expected_different_peers_update2 ]

    # A more specific prefix is seen from peer_as 0
    different_peers_update3 = InternalMessage(1, "collector", 0, "127.0.0.1",
                                              "2011:db8:10::/48", 11, "0 11")
    expected_different_peers_update3 = collections.OrderedDict([ ("timestamp", 1),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("action", "A"),
                                         ("prefix", "2011:db8:10::/48"), 
                                         ("as_path", "0 11"), ("asn", 11)])
    expected_different_peers_hijack3 = collections.OrderedDict([ ("timestamp", 1),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("type", "U"),
                                         ("announce", collections.OrderedDict([ ("prefix", "2011:db8:10::/48"), 
                                             ("asn", 11), ("as_path", "0 11") ])),
                                         ("conflict_with", collections.OrderedDict([ ("prefix", "2011:db8::/32"),
                                             ("asn", 10) ])), ("asn", 10) ] )
    messages = route.process(different_peers_update3)
    assert messages == [ expected_different_peers_update3 ]
    assert hijack.process(different_peers_update3) == [ expected_different_peers_hijack3 ]

    # A more specific prefix is seen from peer_as 1
    different_peers_update4 = InternalMessage(1, "collector", 1, "127.0.0.2",
                                              "2011:db8:10::/48", 11, "1 11")
    expected_different_peers_update4 = collections.OrderedDict([ ("timestamp", 1),
                                         ("collector", "collector"),
                                         ("peer_as", 1), ("peer_ip", "127.0.0.2"),
                                         ("action", "A"),
                                         ("prefix", "2011:db8:10::/48"), 
                                         ("as_path", "1 11"), ("asn", 11)])
    expected_different_peers_hijack4 = collections.OrderedDict([ ("timestamp", 1),
                                         ("collector", "collector"),
                                         ("peer_as", 1), ("peer_ip", "127.0.0.2"),
                                         ("type", "U"),
                                         ("announce", collections.OrderedDict([ ("prefix", "2011:db8:10::/48"), 
                                             ("asn", 11), ("as_path", "1 11") ])),
                                         ("conflict_with", collections.OrderedDict([ ("prefix", "2011:db8::/32"),
                                             ("asn", 10) ])), ("asn", 10) ] )
    messages = route.process(different_peers_update4)
    assert messages == [ expected_different_peers_update4 ]
    assert hijack.process(different_peers_update4) == [ expected_different_peers_hijack4 ]


    # A withdraw is received from the /32 on peer_as 0
    different_peers_withdraw5 = InternalMessage(2, "collector", 0, "127.0.0.1",
                                                "2011:db8::/32", 10, "0 10")
    expected_different_peers_withdraw5 = collections.OrderedDict([("timestamp", 2),
                                           ("collector", "collector"),
                                           ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                           ("action", "W"),
                                           ("prefix", "2011:db8::/32"), ("asn", 10)])
    route_messages, hijack_messages =  withdraw.process(different_peers_withdraw5)
    assert route_messages == [ expected_different_peers_withdraw5 ]
    assert hijack_messages == []

    # A withdraw is received from the /32 on peer_as 1
    different_peers_withdraw6 = InternalMessage(2, "collector", 1, "127.0.0.2",
                                                "2011:db8::/32", 10, "1 10")
    expected_different_peers_withdraw6 = collections.OrderedDict([("timestamp", 2),
                                           ("collector", "collector"),
                                           ("peer_as", 1), ("peer_ip", "127.0.0.2"),
                                           ("action", "W"),
                                           ("prefix", "2011:db8::/32"), ("asn", 10)])
    route_messages, hijack_messages =  withdraw.process(different_peers_withdraw6)
    assert route_messages == [ expected_different_peers_withdraw6 ]
    assert hijack_messages == []

    # A withdraw is received from the /48 on peer_as 0
    different_peers_withdraw6= InternalMessage(3, "collector", 0, "127.0.0.1",
                                                 "2011:db8:10::/48", 11, "0 11")
    expected_different_peers_withdraw6 = collections.OrderedDict([("timestamp", 3),
                                          ("collector", "collector"),
                                          ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                          ("action", "W"),
                                          ("prefix", "2011:db8:10::/48"), ("asn", 11)])
    expected_different_peers_withdraw6_hijack = collections.OrderedDict([("timestamp", 3),
                                                  ("collector", "collector"),
                                                  ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                                  ("type", "W"),
                                                  ("withdraw", collections.OrderedDict([("prefix", "2011:db8:10::/48"), ("asn", 11)])),
                                                  ("asn", 10)])
    route_messages, hijack_messages = withdraw.process(different_peers_withdraw6)
    assert route_messages == [ expected_different_peers_withdraw6 ]
    assert hijack_messages == [ expected_different_peers_withdraw6_hijack]

    # A withdraw is received from the /48 on peer_as 1
    different_peers_withdraw7= InternalMessage(3, "collector", 1, "127.0.0.2",
                                                 "2011:db8:10::/48", 11, "1 11")
    expected_different_peers_withdraw7 = collections.OrderedDict([("timestamp", 3),
                                          ("collector", "collector"),
                                          ("peer_as", 1), ("peer_ip", "127.0.0.2"),
                                          ("action", "W"),
                                          ("prefix", "2011:db8:10::/48"), ("asn", 11)])
    expected_different_peers_withdraw7_hijack = collections.OrderedDict([("timestamp", 3),
                                                  ("collector", "collector"),
                                                  ("peer_as", 1), ("peer_ip", "127.0.0.2"),
                                                  ("type", "W"),
                                                  ("withdraw", collections.OrderedDict([("prefix", "2011:db8:10::/48"), ("asn", 11)])),
                                                  ("asn", 10)])
    route_messages, hijack_messages = withdraw.process(different_peers_withdraw7)
    assert route_messages == [ expected_different_peers_withdraw7 ]
    assert hijack_messages == [ expected_different_peers_withdraw7_hijack]

    assert len(rib.nodes()) == 0

  def test_hijacks_untracked(self):
    """Check if hijacks from an untracked AS are correctly processed."""

    # Setup the internal objects
    rib = EmulatedRIB()
    route = Route(rib)
    hijack = Hijack(rib, "U")
    withdraw = Withdraw(rib)

    # Process the /32 update
    untracked_update1 = InternalMessage(0, "collector", 0, "127.0.0.1",
                                              "2011:db8::/32", 10, "0 10")
    expected_untracked_update1 = collections.OrderedDict([ ("timestamp", 0),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("action", "A"),
                                         ("prefix", "2011:db8::/32"), 
                                         ("as_path", "0 10"), ("asn", 10)])
    messages = route.process(untracked_update1)
    assert messages == [ expected_untracked_update1 ]
    assert len(rib.nodes()) == 1

    # Process the /48 update
    untracked_update2 = InternalMessage(1, "collector", 0, "127.0.0.1",
                                              "2011:db8:10::/48", 11, "0 11")
    expected_untracked_hijack2 = collections.OrderedDict([ ("timestamp", 1),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("type", "U"),
                                         ("announce", collections.OrderedDict([ ("prefix", "2011:db8:10::/48"), 
                                             ("asn", 11), ("as_path", "0 11") ])),
                                         ("conflict_with", collections.OrderedDict([ ("prefix", "2011:db8::/32"),
                                             ("asn", 10) ])), ("asn", 10) ] )
    assert hijack.process(untracked_update2) == [ expected_untracked_hijack2 ]
    assert len(rib.nodes()) == 2

    # Process the /32 withdraw
    untracked_update3 = InternalMessage(2, "collector", 0, "127.0.0.1",
                                              "2011:db8::/32", 10, "0 10")
    expected_untracked_update3 = collections.OrderedDict([ ("timestamp", 2),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("action", "W"),
                                         ("prefix", "2011:db8::/32"), 
                                         ("asn", 10)])
    route_messages, hijack_messages = withdraw.process(untracked_update3)
    assert route_messages == [ expected_untracked_update3 ]
    assert hijack_messages == []
    assert len(rib.nodes()) == 1

    # Process the /48 withdraw
    untracked_update4 = InternalMessage(3, "collector", 0, "127.0.0.1",
                                        "2011:db8:10::/48", 11, "0 11")
    expected_untracked_update4 = collections.OrderedDict([ ("timestamp", 3),
                                         ("collector", "collector"),
                                         ("peer_as", 0), ("peer_ip", "127.0.0.1"),
                                         ("type", "W"),
                                         ("withdraw", collections.OrderedDict([("prefix", "2011:db8:10::/48"), ("asn", 11)])),
                                         ("asn", 10)])
    route_messages, hijack_messages = withdraw.process(untracked_update4)
    assert route_messages == []
    assert hijack_messages == [ expected_untracked_update4 ]
    assert len(rib.nodes()) == 0
