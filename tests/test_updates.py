import collections

from tabi.parallel.core import InternalMessage, Route, RouteInformation
from tabi.parallel.rib import EmulatedRIB


# Abstracted BGP UPDATE messages
update4_1 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "1.2.3.0/24", 64497, "64496 64499 64497")
update4_2 = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "1.2.3.0/24", 64500, "64496 64499 64500")

update6   = InternalMessage(2807, "collector", 64496, "127.0.0.1",
                            "2001:db8::/32", 64497, "64496 64499 64497")

# Expected output messages
expected_message4 = collections.OrderedDict([ ("timestamp", 2807),          
                                              ("collector", "collector"),          
                                              ("peer_as", 64496),              
                                              ("peer_ip", "127.0.0.1"),              
                                              ("action", "A"),                     
                                              ("prefix", "1.2.3.0/24"),                
                                              ("as_path", "64496 64499 64497"),              
                                              ("asn", 64497) ])  
expected_message6 = collections.OrderedDict([ ("timestamp", 2807),          
                                              ("collector", "collector"),          
                                              ("peer_as", 64496),              
                                              ("peer_ip", "127.0.0.1"),              
                                              ("action", "A"),                     
                                              ("prefix", "2001:db8::/32"),                
                                              ("as_path", "64496 64499 64497"),              
                                              ("asn", 64497) ])  

class TestRoute:

  def test_update_ipv4_message(self):
    """Check the format of the output message with the IPv4 prefix."""

    route = Route(EmulatedRIB())
    assert route.message(update4_1) == expected_message4

  def test_update_ipv6_message(self):
    """Check the format of the output message with the IPv6 prefix."""

    route = Route(EmulatedRIB())
    assert route.message(update6) == expected_message6

  def test_update4_process(self, update=update4_1, test_prefix="1.2.3.0/24"):
    """Check if IPv4 UPDATES are correcty processed."""

    rib = EmulatedRIB()
    rib.set_access_time(2807)

    # Process
    route = Route(rib)
    message = route.process(update)
  
    # Compare the message that was returned
    if update == update4_1:
      assert message == [ expected_message4 ]
    elif update == update6:
      assert message == [ expected_message6 ]
    else:
      assert None == "Unknown abstracted BGP UPDATE !"

    # Retrieve the node from the radix tee
    node = rib.search_exact(test_prefix)

    # The node is in the tree
    assert node != None

    # Verify the internal structure integrity
    route_key = dict()
    route_key[RouteInformation(64497, 64496, "127.0.0.1")] = 2807
    assert node.data.get("routes_information", None) == route_key

  def test_update6_process(self):
    """Check if IPv6 UPDATES are correcty processed."""

    self.test_update4_process(update6, "2001:db8::/32")

  def test_update4_origins_process(self):
    """Check if IPv4 UPDATES from several origins are correcty processed."""

    rib = EmulatedRIB()
    rib.set_access_time(2807)

    # Process then retrieve the node from the radix tee
    route = Route(rib)
    route.process(update4_1)

    # Process the same UPDATE and pretend that it was inserted later
    route = Route(rib)
    route.process(update4_2)
    node = rib.search_exact("1.2.3.0/24")

    # Verify the internal structure integrity
    route_keys = dict()
    route_keys[RouteInformation(64497, 64496, "127.0.0.1")] = 2807
    route_keys[RouteInformation(64500, 64496, "127.0.0.1")] = 2807
    assert node.data.get("routes_information", None) == route_keys
