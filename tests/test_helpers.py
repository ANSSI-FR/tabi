from tabi.parallel.helpers import *
import random, sys, tempfile

class TestHelpers:

    def test_check_ris_filenames(self):
        """Check that RIS filenames are correclty processed and sorted."""

        # Incorrect names are discarded
        assert check_ris_filenames(["a", "b"]) == ([], ["a", "b"])
        assert check_ris_filenames(["/tmp/q/wer/ty/bview.20151010.1246", "b"]) == (["/tmp/q/wer/ty/bview.20151010.1246"], ["b"])

        # 'bview' must appear before 'updates' if sorting is required
        filenames_sorted   = [ "bview.20151010.1246.gz", "updates.20151010.1246.gz" ]
        filenames_unsorted = [ "updates.20151010.1246.gz", "bview.20151010.1246.gz" ]
        assert check_ris_filenames(filenames_unsorted, sort=False) == (filenames_unsorted, [])
        assert check_ris_filenames(filenames_unsorted, sort=True)  == (filenames_sorted, [])

        # Older files must appear after newer ones if sorting is required
        filenames_sorted   = [ "updates.19850203.1234", "bview.20151010.1246.gz", "updates.20151010.1246.gz" ]
        filenames_unsorted = [ "bview.20151010.1246.gz", "updates.20151010.1246.gz", "updates.19850203.1234", "garbage" ]
        assert check_ris_filenames(filenames_unsorted, sort=False) == (filenames_unsorted[:-1], ["garbage"])
        assert check_ris_filenames(filenames_unsorted, sort=True)  == (filenames_sorted, ["garbage"])

    def test_parse_ases_ini(self):
        """Check that the fonction can parse a list of integers stored in a file."""

        # Try to open a non existing file
        non_existing_filename = "%x" % random.randint(0, sys.maxint)
        try:
          parse_ases_ini(non_existing_filename)
          assert False
        except Exception, e:
          if not isinstance(e, CriticalException):
            assert False

        # Try to open a non existing file
        fd, filename = tempfile.mkstemp()
        os.write(fd, "bgp")
        os.close(fd)
        try:
          parse_ases_ini(filename)
          assert False
        except Exception, e:
            pass

    def test_split_ases_list(self):
        """Check if an ASes list is correctly splitted."""

        # Try to split the empty list
        assert split_ases_list([], 0) == [[]]
        assert split_ases_list([], 1) == [[]]
        assert split_ases_list([], 2) == [[]]

        # Try to split a list
        asn_list = range(10)
        assert split_ases_list(asn_list, 2) == [range(5), range(5, 10)]
        assert split_ases_list(asn_list, 3) == [range(4), range(4, 8), range(8, 10)]
        assert split_ases_list(asn_list, 4) == [range(3), range(3, 6), range(6, 9), [9]]

    def test_get_packed_addr(self):
        """Check if IP addresses are correctly packed."""

        # Invalid IP prefixes
        invalid_prefixes = [ ("bgp", 2807), ("2001:db8::/64", 42), ("192.168.0.0", "bgp") ]
        for prefix,plen in invalid_prefixes:
            try:
              get_packed_addr(prefix, plen)
              assert False
            except Exception, e:
              if not isinstance(e, CriticalException):
                assert False
              print e

        # IPv4 prefixes
        invalid_ipv4_prefixes = [ ("192.168.0.1", 69), ("192.168.0.1", -1), ("192.168.0.0/bgp", None) ]
        for prefix,plen in invalid_ipv4_prefixes:
            try:
              get_packed_addr(prefix, plen)
              assert False
            except Exception, e:
              if not isinstance(e, CriticalException):
                assert False
              print e

        prefix = "192.168.0.1/24"
        if get_packed_addr(prefix) != ("\xc0\xa8\x00\x01", 24):
            assert False

        # IPv6 prefixes
        invalid_ipv6_prefixes = [ ("2001:db8::", 169), ("2001:db8::", -1), ("2001:db8::/bgp", None) ]
        for prefix,plen in invalid_ipv6_prefixes:
            try:
              get_packed_addr(prefix, plen)
              assert False
            except Exception, e:
              if not isinstance(e, CriticalException):
                assert False
              print e

        prefix = "2001:db8::/48"
        if get_packed_addr(prefix) != ("\x20\x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48):
            print get_packed_addr(prefix)
            assert False

    def test_get_as_origin(self):
        """Check if AS_PATH are correctly parsed."""

        # Invalid AS_PATH
        invalid_as_path = [ "", "{", "{}", "1 {bgp}", "1 {2 3}", "@", "}{", "}" ]
        for as_path in invalid_as_path:
            try:
              get_as_origin(as_path)
              assert False
            except Exception, e:
              print e
              if not isinstance(e, CriticalException):
                assert False

        # Valid AS_PATH
        invalid_as_path = [ "1", "1 1 2", "1 { 3}", "1 {4}", "1 {5, 5}"]
        expected_results = [[1], [2], [3], [4], [5, 5] ]
        for as_path in invalid_as_path:
            result = expected_results.pop(0)
            try:
              if get_as_origin(as_path) != result:
                assert False
            except Exception, e:
              if not isinstance(e, CriticalException):
                assert False
              print e
