#!/usr/bin/env python3
import requests
from colorama import Fore, Back, Style
import sys


def severity(cve):
    severity = cve['severity']
    if severity == 'HIGH':
        return Fore.RED + Style.BRIGHT + severity.ljust(6) + Style.RESET_ALL
    elif severity == 'MEDIUM':
        return Fore.YELLOW + severity.ljust(6) + Style.RESET_ALL
    elif severity == 'LOW':
        return Style.DIM + severity.ljust(6) + Style.RESET_ALL


def summary(cve, max_l=140):
    summary = cve['summary']
    if len(summary) > max_l:
        summary = summary[0:max_l] + " ..."
    return Style.DIM + summary + Style.RESET_ALL


def vector(cve):
    return cve['vector'].replace('ADJACENT_', '').ljust(10)


def print_header():
    print("%s %s %s %s %s" % ('CVE'.ljust(16), 'IMPACT'.ljust(
        6), 'SCORE', 'VECTOR'.ljust(10), 'SUMMARY'))
    print("---              -----  ----- ------     -------")


def print_cve(cve):
    print("%s %s %s %s %s" % (cve['cve'].ljust(16),
                              severity(cve), ("%.1f" % cve['score']).ljust(5), vector(cve), summary(cve)))


if len(sys.argv) != 3:
    print("usage: %s <product> <version>" % sys.argv[0])
    quit()

query = {
    "product": sys.argv[1],
    "version": sys.argv[2]
}

r = requests.post('http://localhost:8000/cve/search', json=query)

cves = [cve for cve in r.json()]

cves.sort(key=lambda x: x['cve'], reverse=True)
num_cves = len(cves)

print()

if num_cves > 50:
    print("50 most recent CVEs (%d total) for '%s %s'\n" %
          (num_cves, query['product'], query['version']))

    print_header()
    for cve in cves[:50]:
        print_cve(cve)

    highs = 0
    meds = 0
    lows = 0
    for cve in cves[50:]:
        if cve['severity'] == 'HIGH':
            highs += 1
        elif cve['severity'] == 'MEDIUM':
            meds += 1
        elif cve['severity'] == 'LOW':
            lows += 1

    print("\n%d more CVEs, %d high, %d medium and %d low impact." %
          (num_cves - 50, highs, meds, lows))
else:
    print("%d results for '%s %s'\n" %
          (num_cves, query['product'], query['version']))

    print_header()
    for cve in cves:
        print_cve(cve)

print()
