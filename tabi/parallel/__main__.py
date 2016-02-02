#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.
#
# Francois Contat   <francois.contat@ssi.gouv.fr>
# Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>

# At least if someone uses the print function it will raise an error and not
# write to stdout.
from __future__ import print_function

import cProfile
import logging
import sys
import os
import optparse
import time
import multiprocessing
import datetime
import collections
import traceback

import tabi.parallel.helpers
import tabi.parallel.writers
import tabi.parallel.mrtprocess


def send_all(process_list, string):
    """Send a string to every processs in process_list."""
    for p in process_list:
        p["pipe"].send(string)


def main():

    # Parameters
    processes = []
    asn_list = []
    start_date = datetime.datetime.now()

    # Is the version of python radix OK ?
    try:
        tabi.parallel.helpers.check_python_radix()
    except tabi.parallel.helpers.CriticalException, message:
        tabi.parallel.helpers.critical_error(message)

    # Parse command line options
    usage = "usage: %prog [options] collector_id output_directory filenames*"
    parser = optparse.OptionParser(usage)
    parser.add_option("-f", "--file", action="store_true", dest="file",
                      default=False, help="files' content comes from mabo")
    parser.add_option("-p", "--pipe", dest="pipe",
                      help="Read the MRT filenames used as input from "
                            "this pipe")
    parser.add_option("-d", "--disable", action="store_true",
                      dest="disable_checks", default=False,
                      help="disable checks of the filenames' "
                           "RIS format")
    parser.add_option("-j", "--jobs", dest="jobs", type="int",
                      default=1,
                      help="Number of jobs that will process the files")
    parser.add_option("-a", "--ases", dest="ases",
                      help="File containing the ASes to monitor")
    parser.add_option("-s", "--stats", action="store_true", dest="stats",
                      default=False,
                      help="Enable code profiling")
    parser.add_option("-m", "--mode", dest="output_mode",
                      default="combined", choices=["legacy", "combined", "live"],
                      help="Select the output mode: legacy, combined or live")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      default=False,
                      help="Turn on verbose output")
    parser.add_option("-l", "--log", action="store_true", dest="log",
                      default=False,
                      help="Messages are written to a log file.")

    (options, args) = parser.parse_args()

    if not args:
        sys.exit(parser.get_usage())

    # Start the code profiling in the main process if enabled by configuration
    stats = None
    if options.stats:
        stats = cProfile.Profile()
        stats.enable()

    # Check the number of parameters
    if (options.pipe is None and len(args) < 3) or len(args) < 2:
        message = "At least three parameters are required if the pipe option "\
                  "is not specified: the collector ID, the output direcory,"\
                  "and a file to"\
                  " parse."
        tabi.parallel.helpers.critical_error(message)

    # Collector ID, output directory & filenames
    collector_id = args[0]
    output_directory = args[1]  # XXX: should be escaped
    args = args[2:]

    # Check if the number of jobs is valid
    if options.jobs < 1:
        message = "The number of jobs must be 1 or more."
        tabi.parallel.helpers.critical_error(message)

    if options.ases:
        # Retrieve the list of ASes that will be monitored
        try:
            asn_list = tabi.parallel.helpers.parse_ases_ini(options.ases)
        except tabi.parallel.helpers.CriticalException, e:
            tabi.parallel.helpers.critical_error(e)

        tmp_l = tabi.parallel.helpers.split_ases_list(asn_list, options.jobs)
    else:
        # otherwise set None
        asn_list = None
        tmp_l = [None for _ in range(options.jobs)]

    # Create the directory where results will be stored
    directory = tabi.parallel.helpers.get_directoryname(options, args)
    tabi.parallel.helpers.create_results_directory(output_directory,
                                                        directory)

    # Logging configuration
    logger = logging.getLogger("tabi")
    logger.propagate = False  # do not propagate message to the root logger
    logger.setLevel(logging.DEBUG if options.verbose else logging.INFO)
    log_format = "%(asctime)-15s %(name)s [%(process)s] "
    log_format += "%(levelname)s %(message)s"
    formatter = logging.Formatter(log_format)

    # Write to a file
    if options.log:
        filename = "./results/%s/output.log" % output_directory
        log_file_handler = logging.FileHandler(filename, mode="w+")
        log_file_handler.setFormatter(formatter)
        logger.addHandler(log_file_handler)

    # Write to the console
    else:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

    # Log that the no_name directory will be used
    if directory == "no_name":
        logger.info("Using the directory 'no_name' to store the results.")

    # Use mabo files instead of MRT files
    if options.file:
        logger.info("Parsing files as mabo output")

    # Configure and start processes that will parse data from MRT dumps
    all_results_pipes = []
    for job_id in range(options.jobs):

        # Parameters that will be used to create directories
        tmp_parameters = {}
        tmp_parameters["monitored_ases"] = asn_list
        tmp_parameters["ases"] = tmp_l[job_id]
        tmp_parameters["job_id"] = job_id
        tmp_parameters["num_jobs"] = options.jobs
        tmp_parameters["collector_id"] = collector_id
        tmp_parameters["stats"] = options.stats
        tmp_parameters["logger"] = logger

        # Pipe used to send results to a WriterProcess
        results_parent_pipe, results_child_pipe = multiprocessing.Pipe()
        tmp_parameters["results_pipe"] = results_child_pipe
        all_results_pipes += [results_parent_pipe]

        # Only allow the first process to report default route
        tmp_parameters["report_default_route"] = job_id == 0

        # Prepare and start the process that does the main job
        parent_pipe, child_pipe = multiprocessing.Pipe()
        process = tabi.parallel.mrtprocess.MRTProcess(child_pipe, tmp_parameters)
        process.start()

        processes += [{"process": process, "pipe": parent_pipe,
                       "routes": set()}]
        if options.ases:
            logger.info("Process(%d) will process %d AS",
                        job_id, len(tmp_parameters["ases"]))
        else:
            message = "No AS list provided ASes will be dispatched "\
                      "between jobs."
            logger.info(message)

    # Configure and start the process that will write results to the disk
    tmp_parameters = {}
    tmp_parameters["output_directory"] = output_directory
    tmp_parameters["directory"] = directory
    tmp_parameters["ases"] = asn_list
    tmp_parameters["logger"] = logger

    if options.output_mode == "legacy":
        process_writer = tabi.parallel.writers.LegacyWriterProcess(all_results_pipes,
                                                              tmp_parameters)
    elif options.output_mode == "combined":
        process_writer = tabi.parallel.writers.CombinedWriterProcess(all_results_pipes,
                                                                tmp_parameters)
    else:
        process_writer = tabi.parallel.writers.LiveWriterProcess(all_results_pipes,
                                                            tmp_parameters)
    process_writer.start()

    if options.pipe is not None:
        pipe_filename = options.pipe
        if pipe_filename == "-":
            pipe_filename = "/dev/stdin"

    # Files specified in arguments are first introduced in the MRT files queue.
    if not options.disable_checks:
        args, garbage = tabi.parallel.helpers.check_ris_filenames(args)
        if garbage:
            message = "Some filenames do not have the RIS naming scheme: %s"
            tabi.parallel.helpers.critical_error(message % garbage)

    pending_mrt_files = collections.deque(args)

    try:
        # The main loop that parses MRT dumps
        i = 0
        while True:

            # If enabled, read the input pipe for new MRT files to process
            if options.pipe is not None and len(pending_mrt_files) == 0:
                # Reopen the pipe after every read in order to avoid blocking
                # the main process
                try:
                    input_pipe = open(pipe_filename, "r")
                except IOError:
                    message = "Cannot reopen the pipe %s" % pipe_filename
                    tabi.parallel.helpers.critical_error(message)

                data = input_pipe.read()
                # the pipe was opened by a writer but nothing were written
                if len(data) == 0:
                    continue

                filenames = data.split()
                for filename in filenames:
                    if filename != '':
                        if not options.disable_checks:
                            filenames, garbage = check_ris_filenames([filename],
                                                                     sort=False)
                            if garbage:
                                message = "Some filenames do not have the "\
                                          "RIS naming scheme: %s" % garbage
                                tabi.parallel.helpers.critical_error(message)
                            pending_mrt_files.append(filename)

                input_pipe.close()

            if len(pending_mrt_files) == 0:
                break

            # Take the next MRT file to process in the FIFO queue
            mrt_file = pending_mrt_files.popleft()
            logger.info("Parsing %s", mrt_file)

            try:
                output_file_pattern = "/tmp/_parse_bgp_%s_%d.json"
                temp_output_file = output_file_pattern % (os.getpid(), i)
                if options.file:
                    if mrt_file.endswith(".gz"):
                        # JSON gzipped, we fork gunzip
                        sp = tabi.parallel.helpers.gunzip_fork(mrt_file,
                                                          temp_output_file)
                    else:
                        # Raw JSON, nothing to do
                        sp = None
                        temp_output_file = mrt_file
                else:
                    # MRT file, fork mabo
                    sp = tabi.parallel.helpers.mabo_fork(mrt_file,
                                                       temp_output_file)

                access_time = time.time()
                timestamp = None

                # First send the access time
                send_all(processes, "ACCESS %f" % access_time)

                # Send filename to process
                send_all(processes, "PROCESS %s" % temp_output_file)

                # Wait for mabo to finish if needed
                if sp is not None:
                    sp.wait()
                    # Log error mabo error messages
                    if not options.file and sp.stderr:
                        for line in sp.stderr:
                            logger.error(line.strip())

                # Remove nodes that were not accessed while parsing a full view
                if "bview" in mrt_file:
                    send_all(processes, "BVIEW_END")

                # Sync the processes with the current process
                send_all(processes, "SYNC_PING")

                # Wait for the processes to send the SYNC_PONG command
                for p in processes:
                    p["pipe"].recv()  # SYNC_PONG

                i += 1

            except KeyboardInterrupt:
                # Kill mabo if it is running
                if sp is not None and sp.returncode is None:
                    sp.kill()
                # Raise the exception again to stop the workers
                raise

            finally:
                # Cleanup the temporary file
                if not options.file or mrt_file.endswith(".gz"):
                    os.unlink(temp_output_file)

        # Send the 'STOP' message to all process
        send_all(processes, "STOP")

        # Receive the routes from every process
        for p in processes:
            p["routes"] = set(p["pipe"].recv())

    except KeyboardInterrupt:
        # Kill the workers
        logger.info("Keyboard interrupt received, halting workers...")
        for p in processes:
            p["process"].terminate()
        process_writer.terminate()

    except Exception, e:
        # Report exceptions and the corresponding trace
        logger.error("Exception catched: %s" % e)
        etype, evalue, etrace = sys.exc_info()
        traceback_str = traceback.format_exception(etype, evalue, etrace)
        logger.error(traceback_str)

    finally:
        # Wait for the processes to terminate
        for p in processes:
            p["process"].join()

    # Wait for the writer process to terminate
    process_writer.join()

    # Get the number of prefixes inserted
    routes_inserted = set()
    for p in processes:
        routes_inserted |= p["routes"]

    # Add some stats to the output
    logger.info("Number of unique prefixes at the end: %d",
                len(routes_inserted))
    logger.info("Execution time: %s" % (datetime.datetime.now()-start_date))

    # Dump the profiling data
    if stats is not None:
        stats.disable()
        filename = "main.{}.pstats".format(os.getpid())
        logger.info("Dump main profiling stats in %s", filename)
        stats.dump_stats(filename)


if __name__ == "__main__":
    main()
