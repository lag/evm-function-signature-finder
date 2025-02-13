
# EVM Function Signature Bruter

To get started, run `python get_bytecode.py` and enter a contract Ethereum mainnet address (or leave blank for an example address).

This will download the bytecode and save it as `{contract_address}.hex`.

Next, run `python pull_signatures.py` to pull the function signatures from the bytecode and save it sorted into `signatures.txt`. They MUST be sorted and MUST be hex without the 0x prefix.

Now let's generate the functions and arguments to use in the signature generation.

Run `python extract_functions.py` to generate the functions and arguments. This reads from the `full_out.txt` file which contains all function signatures and arguments from 4bytes.directory.

(If you don't have a full_out.txt file, you can use the `getsiglists.py` and `get_from_pages.py` file to get it from 4bytes.directory. Be kind to their servers.)

With the current `full_out.txt`, it computes the following:
- The longest reasonable function name is 35 characters.
- The longest argument is 96 characters.
- 868,354 unique function names
- 27,696 unique arguments
- 24,049,932,384 total hashes to compute

These are values the longest function and argument after trimming off the longest 1%. (There is a lot of spam in the directory.)

It also generates a bloom filter of all the functions and arguments to later be used to filter/prioritize certain function signatures. This uses `pip install pybloom-live`.

Now let's generate the signatures.

You'll need to compile the `brutesearch.cu` file.

```
nvcc signature_finder.cu -o signatureFinder -O3
```

Now run the signature finder with the needed parameters.

```
./signatureFinder --funclength 35 --arglength 96 --funcs=funcs.txt --args=args.txt --signatures=signatures.txt
```

This will generate a `results.txt` file with the results. On my mid-tier gaming PC, it takes around 20 seconds to complete. Your mileage can and will vary.

There be a bit of spam in the terminal, but all results are exported at the end. The indexes also may print out of order. That is fine.

After this is done running, run the analysis script.

```
python analyze.py
```

This will generate a `resolved_functions.json` file with the results.

You will see results like this:
```json
{
    "081812fc": [
        [
            "getApproved(uint256)"
        ],
        [
            "BatchCreateSaleAvgPrice(address,address,string,string,string,uint256,uint256,uint256[],uint256[],address)"
        ]
    ],
    "095ea7b3": [
        [
            "approve(address,uint256)"
        ],
        [
            "mintPlantByPermission(uint256,bytes,bytes,uint256,uint256)",
            "issuance(uint256,address,address,address,uint256,uint256,bytes32,bytes32[])",
            "getReferralAccount(address,address,address,bytes,uint256,uint256,uint256,uint256,bytes,bytes)",
            "botMagic(uint32,uint8,uint16,uint256,int256,bytes32,bytes32,uint256,address,bytes,address,address)"
        ]
    ]
}
```

The first array are functions that exist within 4bytes.directory and the remainder are the auto-generated ones.

The rest requires manually verifying the functions. Sadly, there is no easy way to do all of the decompiling for these EVM contracts. There are some tools out there, but none are perfect.