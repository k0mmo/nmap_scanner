# !/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    print(type(nmproc.stdout))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed

# print scan results from a nmap report
def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format, nmap_report.version, nmap_report.started)

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address
        print("Nmap scan report for " + target_IP + "\n")
        print(("Host is {0}.".format(host.status)))
        print("_____________________________________\n")
        print("  PORT    STATE         SERVICE\n")


        for serv in host.services:
            pserv = "{0:>5s}/{1:3s} {2:12} {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += ' ({0})'.format(serv.banner)
            print(pserv)
    print(nmap_report.summary)

if __name__ == "__main__":
    print(" ")
    print("Enter ip address:\n")
    target_IP = input(">>> ")
    report = do_scan(target_IP, "-sV")
    if report:
        print(" ")
        print("========================================================\n")
        print_scan(report)
        print(" ")
        print("========================================================\n")
    else:
        print("no results returned")
