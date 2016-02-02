# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

# Helper functions

import os
import re
import sys
import time
import json
import socket
import logging
import contextlib
import subprocess

from gzip import GzipFile

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def default_opener(f):
    if isinstance(f, basestring):
        g = open(f, "r")
        try:
            yield g
        finally:
            g.close()
    elif hasattr(f, "open"):
        g = f.open()
        try:
            yield g
        finally:
            g.close()
    else:
        yield f


def gunzip_fork(filename, output):
    """
    Call gunzip.
    Return the subprocess handle.
    """

    # Check if files exists
    if not os.path.exists(filename):
        message = "gunzip_fork(): gzip file does not exist: %s" % filename
        critical_error(message)

    # Call the external command
    try:
        if output is None:
            output = subprocess.PIPE
        else:
            output = open(output, "w")
        sp = subprocess.Popen(["gunzip", "-c", filename], stdout=output,
                              stderr=subprocess.PIPE)
    except OSError, e:
        critical_error("gunzip_fork() %s" % e)
    finally:
        if output != subprocess.PIPE:
            output.close()
    return sp


def mabo_fork(filename, output=None):
    """
    Call MABO_PATH on a given MRT dump.
    Return the subprocess handle.
    """
    MABO_PATH = os.getenv("MABO_PATH", "mabo")

    # Check if files exists
    if not os.path.exists(filename):
        message = "mabo_fork(): MRT file does not exist: %s" % filename
        critical_error(message)

    # Call the external command
    try:
        if output is None:
            output = subprocess.PIPE
        else:
            output = open(output, "w")
        sp = subprocess.Popen([MABO_PATH, "dump", filename],
                              stdout=output, stderr=subprocess.PIPE)
    except OSError, e:
        critical_error("mabo_fork() %s: %s" % (MABO_PATH, e))
    finally:
        if output != subprocess.PIPE:
            output.close()
    return sp


def process_iterator(sp, input):
    """
    Iter over 'input' while the process 'sp' is active.
    """
    buf = []
    while sp.returncode is None:
        sp.poll()
        line = input.readline()
        # EOF (but sp may not be finished yet)
        if line == "":
            time.sleep(0.01)
            continue

        # readline() usually returns a full line (with \n), if not,
        # seek at the beginning of the line and try again.
        if line[-1] != "\n":
            buf.append(line)
            time.sleep(0.01)
            continue
        # yield the line if complete
        buf.append(line[:-1])
        yield "".join(buf)
        buf = []


@contextlib.contextmanager
def gzip_opener(mrt_file, tmp_file=None):
    """
    Open a file compressed using gzip.

    :param tmp_file: name of a file used to store the decompressed content.
    """
    if tmp_file is None:
        yield GzipFile(mrt_file)
    else:
        sp = gunzip_fork(mrt_file, tmp_file)
        try:
            with open(tmp_file, "r") as inp:
                yield process_iterator(sp, inp)
        except:
            sp.poll()
            if sp.returncode is None:
                sp.kill()
        finally:
            sp.wait()
            for line in sp.stderr:
                logger.error("gzip_opener: gunzip: %s", line.strip())


class CriticalException(Exception):
    pass


def parse_json_line_file(f):
    """
    Parse a file containing a json object per line and provide a generator.
    """
    for line in f:
        yield json.loads(line)


def check_ris_filenames(files, sort=True):
    """Sort RIS filenames according to their dates."""

    # The regexp that matches RIS filenames
    re_str = "(.*/)?(updates|bview).([0-9]{8}).([0-9]{4})"
    m = re.compile(re_str)

    # Prepare the key that will be used to sort the filenames
    to_sort = []
    invalid_filenames = []
    for filename in files:
        f = m.search(filename)
        if f:
            # Convert date, times and first letter to an integer
            key = int(f.group(3) + f.group(4))
            key += 1000*key + ord(f.group(2)[0])
            to_sort += [(key, filename)]
        else:
            invalid_filenames += [filename]

    # Sort based on the key and return the list
    if sort:
        to_sort.sort(lambda x, y: cmp(x[0], y[0]))

    return map(lambda (x, y): y, to_sort), invalid_filenames


def critical_error(message):
    """Critcal errors are logged, then the program stops."""

    critical_message = "Exiting due to a critical error: %s" % message
    logging.critical(critical_message)

    sys.exit(1)


def check_python_radix():
    """Check if py-radix is ok."""

    import radix

    # Check if search_best() is patched
    r = radix.Radix()
    r.add("10.0.0.0/8")
    r.add("10.0.0.0/16")
    if r.search_best("10.0.0.0/12").prefix != "10.0.0.0/8":
        # In buggy versions, r.search_best().prefix is equal to 10.0.0.0/16
        message = "search_best() is broken !\n"
        message += "  Please upgrade py-radix."
        raise CriticalException(message)

    # Check if the search_covering() method exists
    r = radix.Radix()
    try:
        r.search_covering("192.168.0.0/24")
    except AttributeError:
        message = "search_covering() does not exist !\n"
        message += "  Please upgrade py-radix."
        raise CriticalException(message)

    # Check if the search_covered() method exists
    r = radix.Radix()
    try:
        r.search_covered("192.168.0.0/24")
    except AttributeError:
        message = "search_covered() does not exist !\n"
        message += "  Please upgrade py-radix."
        raise CriticalException(message)


def get_packed_addr(prefix_arg, plen=None):
    """Return the binary representation of a prefix."""

    if plen is None:
        tmp = prefix_arg.split("/")
        if len(tmp) != 2:
            message = "get_packed_addr() - %s is not a\
                      valid prefix !" % prefix_arg
            raise CriticalException(message)
        prefix, plen = tmp

    elif plen and "/" in prefix_arg:
        message = "get_packed_addr() - %s contains '/' and\
                  plen is defined !" % prefix_arg
        raise CriticalException(message)

    else:
        prefix = prefix_arg

    # Check if the plen is an integer
    try:
        plen = int(plen)
    except ValueError:
        raise CriticalException("get_packed_addr() - %s is not\
                                an integer !" % plen)

    # Check if it is an IPv4 prefix
    try:
        packed_prefix = socket.inet_pton(socket.AF_INET, prefix)
        if plen < 0 or plen > 32:
            raise CriticalException("get_packed_addr() - %s is not a valid\
                                    IPv4 prefix length integer !" % plen)
        return packed_prefix, plen
    except socket.error:
        pass

    # Check if it is an IPv6 prefix
    try:
        packed_prefix = socket.inet_pton(socket.AF_INET6, prefix)
        if plen < 0 or plen > 128:
            raise CriticalException("get_packed_addr() - %s is not a valid\
                                    IPv6 prefix length integer !" % plen)
        return packed_prefix, plen
    except:
        raise CriticalException("get_packed_addr() - %s is not a valid\
                                IP prefix !" % prefix_arg)


def get_as_origin(as_path):
    """Extract the origin AS from an AS_PATH and return a list."""

    # Simple sanity check
    if not len(as_path):
        raise CriticalException("get_as_origin(): the AS_PATH can't be empty!")

    # Get the last element of the list
    splitted_as_path = as_path.split(" ")
    as_origin = splitted_as_path[-1]

    # Check if the last AS is a valid integer
    try:
        return [int(as_origin)]
    except ValueError:
        pass

    # Check if there is an AS_SET
    if as_path[-1] != "}":
        raise CriticalException("get_as_origin(): no AS_SET in %s !" % as_path)

    # Retrieve the string between { and }
    start_bracket_index = None
    end_bracket_index = None
    try:
        start_bracket_index = as_path.index("{")
        end_bracket_index = as_path.index("}")
    except:
        pass

    if not start_bracket_index or not end_bracket_index or start_bracket_index >= end_bracket_index:
        raise CriticalException("get_as_origin(): icomplete AS_SET "
                                "in %s !" % as_path)

    # Process the AS_SET
    as_set = as_path[start_bracket_index:end_bracket_index+1]
    if len(as_set) and "{" == as_set[0] and "}" == as_set[-1]:
        as_set = as_set[1:-1]
        splitted_as_set = as_set.split(",")

        ret_list = []
        for tmp_as_origin in splitted_as_set:
            # Check if as_origin is a valid integer
            try:
                ret_list += [int(tmp_as_origin)]
            except:
                message = "get_as_origin(): "
                message += "'%s' seems invalid in "\
                           "AS_PATH: %s" % (tmp_as_origin, as_path)
                raise CriticalException(message)

        return ret_list

    else:
        raise CriticalException("get_as_origin(): invalid "
                                "AS_PATH %s !" % as_path)
