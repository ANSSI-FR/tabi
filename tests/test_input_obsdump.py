from tabi.parallel.input.mabo import MaboTableDumpV2Document, TableDumpV2Element, MaboUpdateDocument
from tabi.parallel.core import InternalMessage


# JSON documents
json_TableDumpV2 = { "entries": [ { "peer_ip": "1.2.3.4", "peer_as": 1234.0,
                                    "originated_timestamp": 0, "as_path": "1234 5678"},
                                  { "peer_ip": "5.6.7.8", "peer_as": 5678.0,
                                    "originated_timestamp": 1, "as_path": "5678 910112"},
                                  { "peer_ip": "8.9.10.11", "peer_as": 89101112.0,
                                    "originated_timestamp": 1, "as_path": "89101112 13141516"},
                                  { "peer_ip": "8.9.10.11", "peer_as": 89101112.0,
                                    "originated_timestamp": 1, "as_path": "89101112 {123,456}"} ],
                     "type": "table_dump_v2", 
                     "timestamp": 2807, "prefix": "10.11.12.0/24"}

json_update1 = { "type": "update", "timestamp": 0, "peer_as": 1234.0, "peer_ip": "1.2.3.4",
                 "as_path": "1234 5678",
                 "announce": [ "0.0.0.0/0", "::/0"], "withdraw": []}
json_update2 = { "type": "update", "timestamp": 0, "peer_as": 1234.0, "peer_ip": "1.2.3.4",
                 "as_path": "1234 {5678,91011}",
                 "announce": [ "::/0"], "withdraw": []}
json_update3 = { "type": "update", "timestamp": 0, "peer_as": 1234.0, "peer_ip": "1.2.3.4",
                 "announce": [], "withdraw": [ "0.0.0.0/0", "::/0" ]}
json_update4 = { "type": "update", "timestamp": 0, "peer_as": 1234.0, "peer_ip": "1.2.3.4",
                 "as_path": "1234 5678",
                 "announce": ["1.1.1.1/32"], "withdraw":  [ "2.2.2.2/32" ]}


class TestInputObsdump:

  def test_TableDumpV2(self):
    """Check that a TableDumpV2 JSON document from mabo is correctly abstracted."""

    # Get the abstract BGP message
    abstracted = MaboTableDumpV2Document("collector", json_TableDumpV2)

    # Check each element
    elements = abstracted.elements()
    assert len(elements) == 5

    element1 = elements.pop(0)
    assert element1 == TableDumpV2Element(asn=5678, as_path="1234 5678", peer_as=1234, peer_ip="1.2.3.4")

    element2 = elements.pop(0)
    assert element2 == TableDumpV2Element(asn=910112, as_path="5678 910112", peer_as=5678, peer_ip="5.6.7.8")

    element3 = elements.pop(0)
    assert element3 == TableDumpV2Element(asn=13141516, as_path="89101112 13141516", peer_as=89101112, peer_ip="8.9.10.11")

    element4 = elements.pop(0)
    assert element4 == TableDumpV2Element(asn=123, as_path="89101112 {123,456}", peer_as=89101112, peer_ip="8.9.10.11")

    element5 = elements.pop(0)
    assert element5 == TableDumpV2Element(asn=456, as_path="89101112 {123,456}", peer_as=89101112, peer_ip="8.9.10.11")

    # There is no withdraws
    assert abstracted.withdraws() == []

    # Check announces
    assert list(abstracted.announces()) == [ InternalMessage(timestamp=2807, collector="collector",
                                               peer_as=1234, peer_ip="1.2.3.4",
                                               prefix="10.11.12.0/24", asn=5678, as_path="1234 5678"),
                                             InternalMessage(timestamp=2807, collector="collector",
                                               peer_as=5678, peer_ip="5.6.7.8",
                                               prefix="10.11.12.0/24", asn=910112, as_path="5678 910112"),
                                             InternalMessage(timestamp=2807, collector="collector",
                                               peer_as=89101112, peer_ip="8.9.10.11",
                                               prefix="10.11.12.0/24", asn=13141516, as_path="89101112 13141516"),
                                             InternalMessage(timestamp=2807, collector="collector",
                                               peer_as=89101112, peer_ip="8.9.10.11",
                                               prefix="10.11.12.0/24", asn=123, as_path="89101112 {123,456}"),
                                             InternalMessage(timestamp=2807, collector="collector",
                                               peer_as=89101112, peer_ip="8.9.10.11",
                                               prefix="10.11.12.0/24", asn=456, as_path="89101112 {123,456}") ]
  
  def test_update1(self):
    """Check the abstraction of an UPDATE JSON document containing announces"""

    # Get the abstract BGP message
    abstracted = MaboUpdateDocument("collector", json_update1)

    # Check each announces
    messages = list(abstracted.announces())
    assert len(messages) == 2
    assert messages.pop(0)== InternalMessage(timestamp=0, collector="collector",
                                             peer_as=1234, peer_ip="1.2.3.4",
                                             prefix="0.0.0.0/0", asn=5678, as_path="1234 5678")
    assert messages.pop(0)== InternalMessage(timestamp=0, collector="collector",
                                             peer_as=1234, peer_ip="1.2.3.4",
                                             prefix="::/0", asn=5678, as_path="1234 5678")

    # There is no withraws
    assert list(abstracted.withdraws()) == []

  def test_update2(self):
    """Check the abstraction of an UPDATE JSON document containing an AS_SET."""

    # Get the abstract BGP message
    abstracted = MaboUpdateDocument("collector", json_update2)

    # Check each announces
    messages = list(abstracted.announces())
    assert len(messages) == 2
    assert messages.pop(0)== InternalMessage(timestamp=0, collector="collector",
                                             peer_as=1234, peer_ip="1.2.3.4",
                                             prefix="::/0", asn=5678, as_path="1234 {5678,91011}")
    assert messages.pop(0)== InternalMessage(timestamp=0, collector="collector",
                                             peer_as=1234, peer_ip="1.2.3.4",
                                             prefix="::/0", asn=91011, as_path="1234 {5678,91011}")

    # There is no withraws
    assert list(abstracted.withdraws()) == []

  def test_update3(self):
    """Check the abstraction of an UPDATE JSON document containing withdraws"""

    # Get the abstract BGP message
    abstracted = MaboUpdateDocument("collector", json_update3)

    # There is no announces
    assert list(abstracted.announces()) == []

    # Check each withdraw
    messages = list(abstracted.withdraws())
    assert len(messages) == 2
    assert messages.pop(0)== InternalMessage(timestamp=0, collector="collector",
                                             peer_as=1234, peer_ip="1.2.3.4",
                                             prefix="0.0.0.0/0", asn=None, as_path=None)
    assert messages.pop(0)== InternalMessage(timestamp=0, collector="collector",
                                             peer_as=1234, peer_ip="1.2.3.4",
                                             prefix="::/0", asn=None, as_path=None)

  def test_update4(self):
    """Check the abstraction of an UPDATE JSON document containing withdraws & announces"""

    # Get the abstract BGP message
    abstracted = MaboUpdateDocument("collector", json_update4)

    # Check announces
    assert list(abstracted.announces()) == [ InternalMessage(timestamp=0, collector="collector",
                                               peer_as=1234, peer_ip="1.2.3.4",
                                               prefix="1.1.1.1/32", asn=5678, as_path="1234 5678") ]

    # Check withdraws
    assert list(abstracted.withdraws()) == [ InternalMessage(timestamp=0, collector="collector",
                                               peer_as=1234, peer_ip="1.2.3.4",
                                               prefix="2.2.2.2/32", asn=None, as_path=None) ]
