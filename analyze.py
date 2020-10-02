#! /usr/bin/env python3

import os
import json
import shutil
import tempfile


def print_category(header, issues, base_path):
    """
    Organize and display the output of each issue.
    """
    print()
    print()
    print('=' * len(header))
    print(header)
    print('=' * len(header))

    for f in {z['file'] for z in issues}:
        out = (' ' + 'File: ' + f[len(base_path):])
        print()
        print('-' * len(out))
        print(out)
        print('-' * len(out))

        for issue in issues:
            if issue['file'] == f:
                pad = ('     ')
                print()
                print(pad + 'Line Number: ' + issue['line'])
                print(pad + 'Confidence: ' + issue['confidence'])
                print(pad + 'Description: ' + issue['details'])
                print(pad + 'Code: "' + issue['code'] + '"')
                print(pad + 'GOSec Rule: ' + issue['rule_id'])


def analyze(results_file, base_path):
    """
    Parse and print the results from gosec audit.
    """
    # Load gosec json Results File
    with open(results_file) as f:
        issues = json.load(f)['Issues']

    if not issues:
        print("Security Check: No Issues Detected!")
        return ([], [], [])

    else:
        high_risk = list()
        medium_risk = list()
        low_risk = list()

        # Sort Issues
        for issue in issues:
            if issue['severity'] == 'HIGH':
                high_risk.append(issue)
            elif issue['severity'] == 'MEDIUM':
                medium_risk.append(issue)
            elif issue['severity'] == 'LOW':
                low_risk.append(issue)

        # Print Summary
        print()
        print('Security Issue Summary:')
        print('  Found ' + str(len(high_risk)) + ' High Risk Issues')
        print('  Found ' + str(len(medium_risk)) + ' Medium Risk Issues')
        print('  Found ' + str(len(low_risk)) + ' Low Risk Issues')

        # Print Issues In Order of Importance
        if high_risk:
            header = ('=        High Security Risk Issues          =')
            print_category(header, high_risk, base_path)

        if medium_risk:
            header = ('=        Medium Security Risk Issues        =')
            print_category(header, medium_risk, base_path)

        if low_risk:
            header = ('=         Low Security Risk Issues          =')
            print_category(header, low_risk, base_path)

        return (high_risk, medium_risk, low_risk)


# Build Test Enviroment
base_path = os.getcwd()
test_path = tempfile.mkdtemp()
results_file = test_path + '/results.json'
os.chdir(test_path)

# Run Test
os.system('curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s 2.0.0')
os.system('./bin/gosec -fmt=json -out=' + results_file + ' ' + base_path + '/...')

# Parse Results
analyze(results_file, base_path)

# Close Test Enviroment
shutil.rmtree(test_path)
