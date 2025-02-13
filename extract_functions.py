import json
import math
import os
import pickle
import re
from pybloom_live import BloomFilter

bf = BloomFilter(capacity=1_500_000, error_rate=0.000001)

sig_extract = re.compile(r'^([A-Za-z_]\w*)(\([^)]*\))$')

function_counts = {}
argument_counts = {}

spam_signatures = set({
    'watch_tg_invmru',
    'join_tg_invmru_',
    '_SIMONdotBLACK_',
    'niceFunctionHerePlzClick',
    'sign_szabo_'
})

def is_spam(signature):
    for spam in spam_signatures:
        if spam in signature:
            return True
    return False

for line in open('full_out.txt','r'):
    signature,hex_signature = line.rstrip().split('\t')
    match = sig_extract.match(signature)
    if match:
        bf.add(signature)
        if '_' in match.group(1):
            last_element = match.group(1).split('_')[-1]
            try:
                if int(last_element) > 10:
                    continue
            except:
                pass
        if is_spam(match.group(1)):
            continue
        function_counts[match.group(1)] = function_counts.get(match.group(1), 0) + 1
        argument_counts[match.group(2)] = argument_counts.get(match.group(2), 0) + 1

with open("functions-filter.pkl", "wb") as f:
    pickle.dump(bf, f)

print(len(function_counts))
top_functions = sorted(function_counts.items(), key=lambda x: x[1], reverse=True)

for function, count in top_functions[:50]:
    print(f"{function}: {count}")

print(len(argument_counts))
top_arguments = sorted(argument_counts.items(), key=lambda x: x[1], reverse=True)

for argument, count in top_arguments[:50]:
    print(f"{argument}: {count}")

longest_argument = max(argument_counts.keys(), key=len)
longest_function = max(function_counts.keys(), key=len)
print('Longest argument:',len(longest_argument))
print('Longest function:',len(longest_function))

function_lengths = sorted([len(function) for function in function_counts.keys()])
argument_lengths = sorted([len(argument) for argument in argument_counts.keys()])

cutoff = 0.99
functions_count = math.ceil(len(function_lengths) * cutoff)
arguments_count = math.ceil(len(argument_lengths) * cutoff)

function_lengths = function_lengths[functions_count]
argument_lengths = argument_lengths[arguments_count]

print(function_lengths)
print(argument_lengths)

bytes_required = (function_lengths * functions_count) + (argument_lengths * arguments_count)

print('Bytes required:',bytes_required)
print(f'Hashes: {functions_count * arguments_count:,}')

with open('funcs.txt', 'w') as f:
    for function in top_functions:
        if len(function[0]) <= function_lengths:
            f.write(function[0] + '\n')

with open('args.txt', 'w') as f:
    for argument in top_arguments:
        if len(argument[0]) <= argument_lengths:
            f.write(argument[0] + '\n')


