from tabi.parallel.rib import EmulatedRIB

class TestEmulatedRib:

  def test_update_data(self):
    """Check update_data() behavior."""

    rib = EmulatedRIB()
    rib.set_access_time(2807)

    node = rib.radix.add("192.168.0.0/24")
    rib.update_data(node, "value", "key")

    assert [ x.prefix for x in rib.nodes() ] == ["192.168.0.0/24"]
    assert [ x.data for x in rib.nodes() ] == [ {"key": { "value": 2807 } } ]

  def test_update(self):
    """Check update() behavior."""

    rib = EmulatedRIB()
    rib.set_access_time(2807)

    rib.update("192.168.0.0/24", "value", "key")

    assert [ x.prefix for x in rib.nodes() ] == ["192.168.0.0/24"]
    assert [ x.data for x in rib.nodes() ] == [ {"key": { "value": 2807 } } ]

  def test_delete(self):
    """Check delete() behavior."""

    rib = EmulatedRIB()
    rib.update("192.168.0.0/24", "value", "key")

    assert len(rib.nodes()) == 1

    rib.delete("192.168.0.0/24")

    assert len(rib.nodes()) == 0

  def test_search_all_containing(self):
    """Check search_all_containing() behavior."""

    rib = EmulatedRIB()
    rib.update("192.168.0.0/24", "value", "key")
    rib.update("192.168.0.0/16", "value", "key")

    nodes = rib.search_all_containing("192.168.0.0/32")

    assert len(nodes) == 2
    assert [ x.prefix for x in nodes ] == [ "192.168.0.0/24", "192.168.0.0/16" ]

  def test_search_exact(self):
    """Check search_exact() behavior."""

    rib = EmulatedRIB()
    rib.update("192.168.0.0/24", "value", "key")
    rib.update("192.168.0.0/16", "value", "key")

    node = rib.search_exact("192.168.0.0/24")

    assert node.prefix == "192.168.0.0/24"

  def test_search_exact(self):
    """Check search_exact() behavior."""

    rib = EmulatedRIB()
    rib.update("192.168.0.0/24", "value", "key")
    rib.update("192.168.0.0/16", "value", "key")

    node = rib.search_exact("192.168.0.0/24")

    assert node.prefix == "192.168.0.0/24"
