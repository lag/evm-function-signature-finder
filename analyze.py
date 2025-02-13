
import json
import pickle
from pybloom_live import BloomFilter

with open("functions-filter.pkl", "rb") as f:bf_loaded = pickle.load(f)

signatures = {}
for line in open('signatures.txt'):
    signature = line.rstrip()
    signatures[signature] = set()

for line in open('resolved.txt'):
    signature,function = line.rstrip().split(' ')
    if signature in signatures:
        signatures[signature].add(function)
    else:
        print(f'{signature} not in signatures')

for signature in signatures:
    functions = list(signatures[signature])
    functions.sort(key=lambda x: x.count(','))

    results = [[],[]]
    for item in functions:
        if item in bf_loaded:
            results[0].append(item)
        else:
            results[1].append(item)

    signatures[signature] = results

with open('resolved_functions.json','w') as f:
    json.dump(signatures,f,indent=4)

