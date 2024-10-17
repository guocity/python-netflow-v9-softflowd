#!/usr/bin/env python3

"""
Reference analyzer script for NetFlow Python package.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""

import argparse
import contextlib
import functools
import gzip
import ipaddress
import json
import logging
import os.path
import socket
import sys
import csv  # Added for CSV functionality
from collections import namedtuple
from datetime import datetime

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}

Pair = namedtuple('Pair', ['src', 'dest'])

logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def printv(message, *args_, **kwargs):
    if args.verbose:
        print(message.format(*args_, **kwargs))


@functools.lru_cache(maxsize=None)
def resolve_hostname(ip: str) -> str:
    if args.no_dns:
        # If no DNS resolution is requested, simply return the IP string
        return ip
    # else resolve the IP address to a hostname and return the hostname
    return socket.getfqdn(ip)


def fallback(d, keys, default=None):
    for k in keys:
        if k in d:
            return d[k]
    if default is not None:
        return default
    raise KeyError(", ".join(keys))


def human_size(size_bytes):
    # Calculate a human readable size of the flow
    if size_bytes < 1024:
        return "%dB" % size_bytes
    elif size_bytes / 1024. < 1024:
        return "%.2fK" % (size_bytes / 1024.)
    elif size_bytes / 1024. ** 2 < 1024:
        return "%.2fM" % (size_bytes / 1024. ** 2)
    else:
        return "%.2fG" % (size_bytes / 1024. ** 3)


def human_duration(seconds):
    # Calculate human readable duration times
    if seconds < 60:
        # seconds
        return "%d sec" % seconds
    if seconds / 60 > 60:
        # hours
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return "%d:%02d:%02d hours" % (hours, minutes, secs)
    # minutes
    minutes = seconds // 60
    secs = seconds % 60
    return "%02d:%02d min" % (minutes, secs)


class Connection:
    """Connection model for two flows.
    The direction of the data flow can be seen by looking at the size.

    'src' describes the peer which sends more data towards the other. This
    DOES NOT have to mean that 'src' was the initiator of the connection.
    """

    def __init__(self, flow1, flow2):
        if not flow1 or not flow2:
            raise Exception("A connection requires two flows")

        # Assume the size that sent the most data is the source
        # TODO: this might not always be right, maybe use earlier timestamp?
        size1 = fallback(flow1, ['IN_BYTES', 'IN_OCTETS'], default=0)
        size2 = fallback(flow2, ['IN_BYTES', 'IN_OCTETS'], default=0)
        if size1 >= size2:
            src = flow1
            dest = flow2
        else:
            src = flow2
            dest = flow1

        # TODO: this next approach uses the lower port as the service identifier
        # port1 = fallback(flow1, ['L4_SRC_PORT', 'SRC_PORT'])
        # port2 = fallback(flow2, ['L4_SRC_PORT', 'SRC_PORT'])
        #
        # src = flow1
        # dest = flow2
        # if port1 > port2:
        #     src = flow2
        #     dest = flow1

        self.src_flow = src
        self.dest_flow = dest
        ips = self.get_ips(src)
        self.src = ips.src
        self.dest = ips.dest
        # Use fallback with default ports to prevent KeyError
        self.src_port = fallback(src, ['L4_SRC_PORT', 'SRC_PORT'], default=0)
        self.dest_port = fallback(dest, ['L4_DST_PORT', 'DST_PORT'], default=0)
        self.size = fallback(src, ['IN_BYTES', 'IN_OCTETS'], default=0)

        # Duration is given in milliseconds
        self.duration = src.get('LAST_SWITCHED', 0) - src.get('FIRST_SWITCHED', 0)
        if self.duration < 0:
            # 32 bit int has its limits. Handling overflow here
            # TODO: Should be handled in the collection phase
            self.duration = (2 ** 32 - src.get('FIRST_SWITCHED', 0)) + src.get('LAST_SWITCHED', 0)

    def __repr__(self):
        return "<Connection from {} to {}, size {}>".format(
            self.src, self.dest, self.human_size)

    @staticmethod
    def get_ips(flow):
        # IPv4
        if flow.get('IP_PROTOCOL_VERSION') == 4 or \
                'IPV4_SRC_ADDR' in flow or 'IPV4_DST_ADDR' in flow:
            return Pair(
                ipaddress.ip_address(flow.get('IPV4_SRC_ADDR', '0.0.0.0')),
                ipaddress.ip_address(flow.get('IPV4_DST_ADDR', '0.0.0.0'))
            )

        # IPv6
        return Pair(
            ipaddress.ip_address(flow.get('IPV6_SRC_ADDR', '::')),
            ipaddress.ip_address(flow.get('IPV6_DST_ADDR', '::'))
        )

    @property
    def human_size(self):
        return human_size(self.size)

    @property
    def human_duration(self):
        duration = self.duration // 1000  # uptime in milliseconds, floor it
        return human_duration(duration)

    @property
    def hostnames(self):
        # Resolve the IPs of this flows to their hostname
        src_hostname = resolve_hostname(str(self.src))
        dest_hostname = resolve_hostname(str(self.dest))
        return Pair(src_hostname, dest_hostname)

    @property
    def service(self):
        # Resolve ports to their services, if known
        if isinstance(self.src_port, int) and self.src_port > 0:
            with contextlib.suppress(OSError, ValueError):
                return socket.getservbyport(self.src_port)
        if isinstance(self.dest_port, int) and self.dest_port > 0:
            with contextlib.suppress(OSError, ValueError):
                return socket.getservbyport(self.dest_port)
        return "N/A"

    @property
    def total_packets(self):
        return self.src_flow.get("IN_PKTS", 0) + self.dest_flow.get("IN_PKTS", 0)


if __name__ == "netflow.analyzer":
    logger.error("The analyzer is currently meant to be used as a CLI tool only.")
    logger.error("Use 'python3 -m netflow.analyzer -h' in your console for additional help.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Output a basic analysis of NetFlow data")
    parser.add_argument("-f", "--file", dest="file", type=str, default=sys.stdin,
                        help="The file to analyze (defaults to stdin if not provided)")
    parser.add_argument("-p", "--packets", dest="packets_threshold", type=int, default=10,
                        help="Number of packets representing the lower bound in connections to be processed")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Enable verbose output.")
    parser.add_argument("--match-host", dest="match_host", type=str, default=None,
                        help="Filter output by matching on the given host (matches source or destination)")
    parser.add_argument("-n", "--no-dns", dest="no_dns", action="store_true",
                        help="Disable DNS resolving of IP addresses")
    parser.add_argument("-c", "--csv", dest="csv_output", type=str, default=None,
                        help="Path to output CSV file with headers: Timestamp, Service, Size, Duration, Packets, Source IP, Source Host, Destination IP, Destination Host")
    args = parser.parse_args()

    # Sanity check for IP address
    if args.match_host:
        try:
            match_host = ipaddress.ip_address(args.match_host)
        except ValueError:
            exit("IP address '{}' is neither IPv4 nor IPv6".format(args.match_host))

    # Using a file and using stdin differ in their further usage for gzip.open
    file = args.file
    mode = "rb"  # reading files
    if file != sys.stdin and not os.path.exists(file):
        exit("File {} does not exist!".format(file))

    if file == sys.stdin:
        file = sys.stdin.buffer
        mode = "rt"  # reading from stdin

    data = {}

    with gzip.open(file, mode) as gzipped:
        # "for line in" lazy-loads all lines in the file
        for line in gzipped:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON line: {}. Error: {}".format(line, e))
                continue

            if len(entry.keys()) != 1:
                logger.warning("The line does not have exactly one timestamp key: \"{}\"".format(list(entry.keys())))

            try:
                ts = list(entry)[0]  # timestamp from key
            except KeyError:
                logger.error("Saved line \"{}\" has no timestamp key!".format(line))
                continue

            if "header" not in entry[ts]:
                logger.error("No header dict in entry {}".format(ts))
                raise ValueError

            if entry[ts]["header"]["version"] == 10:
                logger.warning("Skipped IPFIX entry, because analysis of IPFIX is not yet implemented")
                continue

            data[ts] = entry[ts]

    # Go through data and dissect every flow saved inside the dump

    # The following dict holds flows which are looking for a peer, to analyze a duplex 'Connection'.
    # For each flow, the destination address is looked up. If the peer is not in the list of pending peers,
    # insert this flow, waiting for its peer. If found, take the waiting peer and create a Connection object.
    pending = {}
    skipped = 0
    skipped_threshold = args.packets_threshold

    first_line = True  # print header line before first line

    # Setup CSV writing if requested
    csv_file = None
    csv_writer = None
    if args.csv_output:
        try:
            csv_file = open(args.csv_output, mode='w', newline='')
            csv_writer = csv.writer(csv_file)
            # Write CSV header
            csv_writer.writerow(["Timestamp", "Service", "Size", "Duration", "Packets",
                                 "Source IP", "Source Host", "Destination IP", "Destination Host"])
        except IOError as e:
            logger.error("Failed to open CSV file {} for writing: {}".format(args.csv_output, e))
            sys.exit(1)

    for key in sorted(data):
        try:
            timestamp = datetime.fromtimestamp(float(key)).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError) as e:
            logger.error("Invalid timestamp '{}': {}".format(key, e))
            continue
        client = data[key].get("client", {})
        flows = data[key].get("flows", [])

        for flow in sorted(flows, key=lambda x: x.get("FIRST_SWITCHED", 0)):
            first_switched = flow.get("FIRST_SWITCHED", 0)

            if first_switched - 1 in pending:
                # TODO: handle fitting, yet mismatching (here: 1 second) pairs
                pass

            # Find the peer for this connection
            if "IPV4_SRC_ADDR" in flow or flow.get("IP_PROTOCOL_VERSION") == 4:
                local_peer = flow.get("IPV4_SRC_ADDR", "0.0.0.0")
                remote_peer = flow.get("IPV4_DST_ADDR", "0.0.0.0")
            else:
                local_peer = flow.get("IPV6_SRC_ADDR", "::")
                remote_peer = flow.get("IPV6_DST_ADDR", "::")

            # Match on host filter passed in as argument
            if args.match_host and not any([local_peer == args.match_host, remote_peer == args.match_host]):
                # If a match_host is given but neither local_peer nor remote_peer match
                continue

            if first_switched not in pending:
                pending[first_switched] = {}

            # Match peers
            if remote_peer in pending[first_switched]:
                # The destination peer put itself into the pending dict, getting and removing entry
                peer_flow = pending[first_switched].pop(remote_peer)
                if len(pending[first_switched]) == 0:
                    del pending[first_switched]
            else:
                # Flow did not find a matching, pending peer - inserting itself
                pending[first_switched][local_peer] = flow
                continue

            try:
                con = Connection(flow, peer_flow)
            except KeyError as e:
                logger.error("Missing expected key when creating Connection: {}".format(e))
                continue

            if con.total_packets < skipped_threshold:
                skipped += 1
                continue

            if first_line:
                print("{:19} | {:14} | {:8} | {:9} | {:7} | Involved hosts".format("Timestamp", "Service", "Size",
                                                                                   "Duration", "Packets"))
                print("-" * 100)
                first_line = False

            output_line = "{timestamp} | {service:<14} | {size:8} | {duration:9} | {packets:7} | " \
                          "Between {src_host} ({src}) and {dest_host} ({dest})" \
                .format(timestamp=timestamp, service=con.service.upper(),
                        src_host=con.hostnames.src, src=con.src,
                        dest_host=con.hostnames.dest, dest=con.dest,
                        size=con.human_size, duration=con.human_duration,
                        packets=con.total_packets)

            print(output_line)

            # Write to CSV if enabled
            if csv_writer:
                csv_writer.writerow([
                    timestamp,
                    con.service.upper(),
                    con.human_size,
                    con.human_duration,
                    con.total_packets,
                    str(con.src),
                    con.hostnames.src,
                    str(con.dest),
                    con.hostnames.dest
                ])

    if skipped > 0:
        print("{skipped} connections skipped, because they had less than {skipped_threshold} packets "
              "(this value can be set with the -p flag).".format(skipped=skipped, skipped_threshold=skipped_threshold))

    if csv_file:
        csv_file.close()
        print("CSV output written to {}".format(args.csv_output))

    if not args.verbose:
        # Exit here if no debugging session was wanted
        exit(0)

    if len(pending) > 0:
        print("\nThere are {pending} first_switched entries left in the pending dict!".format(pending=len(pending)))
        all_noise = True
        for first_switched, flows in sorted(pending.items(), key=lambda x: x[0]):
            for peer, flow in flows.items():
                # Ignore all pings, SYN scans and other noise to find only those peers left over which need a fix
                if flow.get("IN_PKTS", 0) < skipped_threshold:
                    continue
                all_noise = False

                src = flow.get("IPV4_SRC_ADDR") or flow.get("IPV6_SRC_ADDR") or "0.0.0.0"
                src_host = resolve_hostname(src)
                src_text = "{}".format(src) if src == src_host else "{} ({})".format(src_host, src)
                dst = flow.get("IPV4_DST_ADDR") or flow.get("IPV6_DST_ADDR") or "0.0.0.0"
                dst_host = resolve_hostname(dst)
                dst_text = "{}".format(dst) if dst == dst_host else "{} ({})".format(dst_host, dst)
                proto = flow.get("PROTOCOL", "UNKNOWN")
                size = flow.get("IN_BYTES", 0)
                packets = flow.get("IN_PKTS", 0)
                src_port = flow.get("L4_SRC_PORT", 0)
                dst_port = flow.get("L4_DST_PORT", 0)

                print("From {src_text}:{src_port} to {dst_text}:{dst_port} with "
                      "proto {proto} and size {size}"
                      " ({packets} packets)".format(src_text=src_text, src_port=src_port, dst_text=dst_text,
                                                    dst_port=dst_port, proto=IP_PROTOCOLS.get(proto, 'UNKNOWN'),
                                                    size=human_size(size), packets=packets))

        if all_noise:
            print("They were all noise!")
