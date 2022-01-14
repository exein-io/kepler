#!/usr/bin/env python3
import requests
from colorama import Fore, Back, Style
import subprocess
import re


def severity(cve):
    severity = cve['severity']
    if severity == 'HIGH':
        return Fore.RED + Style.BRIGHT + severity + Style.RESET_ALL
    elif severity == 'MEDIUM':
        return Fore.YELLOW + severity + Style.RESET_ALL
    elif severity == 'LOW':
        return Style.DIM + severity + Style.RESET_ALL


output = subprocess.check_output(
    ['apt', 'list', '--installed']).decode('utf-8')

packages = []

for line in output.split("\n"):
    line = line.strip()
    if len(line) > 0 and line != 'Listing...':
        matches = re.findall(r'^(.+)/.+\s+(\d:?~?[\d\.\-]*).+$', line)
        matches = matches[0]
        package, version = matches
        version = version.split(':')
        if len(version) == 2:
            version = version[1]
        else:
            version = version[0]

        packages.append((package, version))


for (package, version) in packages:
    cves = []
    package = package.replace("-dev", "").split(':')[0]
    for vendor in ["gnu", "canonical", package]:
        query = {
            "vendor": vendor,
            "product": package,
            "version": version,
        }

        r = requests.post('http://localhost:8000/cve/search', json=query)

        cves.extend([cve for cve in r.json()])

    if len(cves) > 0:
        pv = "%s v%s" % (package, version)

        names = []
        for cve in cves:
            names.append("%s %s (%s)" %
                         (cve['cve'], severity(cve), cve['vector']))

        names.sort(reverse=True)

        print("%s : %s" % (Style.BRIGHT + pv.ljust(25) +
              Style.RESET_ALL, ', '.join(names)))
