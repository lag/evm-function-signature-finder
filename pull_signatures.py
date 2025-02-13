#!/usr/bin/env python3
import argparse
import math

# Define an Instruction class to hold disassembled bytecode information.
class Instruction:
    def __init__(self, address, opcode, name, operand=None):
        self.address = address
        self.opcode = opcode
        self.name = name
        self.operand = operand

    def __repr__(self):
        if self.operand:
            return f"{self.address:04x}: {self.name} {self.operand.hex()}"
        return f"{self.address:04x}: {self.name}"

# A partial mapping of EVM opcodes to their mnemonic names.
EVM_OPCODES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0a: "EXP",
    0x0b: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1a: "BYTE",
    0x20: "SHA3",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3a: "GASPRICE",
    0x3b: "EXTCODESIZE",
    0x3c: "EXTCODECOPY",
    0x3d: "RETURNDATASIZE",
    0x3e: "RETURNDATACOPY",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "DIFFICULTY",
    0x45: "GASLIMIT",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5a: "GAS",
    0x5b: "JUMPDEST",
    0xf3: "RETURN",
    0xfd: "REVERT",
    0xff: "SELFDESTRUCT",
}

def get_opcode_name(op):
    # Check for PUSH operations (0x60 to 0x7f)
    if 0x60 <= op <= 0x7f:
        return f"PUSH{op - 0x5f}"
    # Add handling for DUP and SWAP:
    if 0x80 <= op <= 0x8f:
        return f"DUP{op - 0x7f}"
    if 0x90 <= op <= 0x9f:
        return f"SWAP{op - 0x8f}"
    return EVM_OPCODES.get(op, f"UNKNOWN_{op:02x}")

def immediate_bytes_for_opcode(op):
    if 0x60 <= op <= 0x7f:
        # PUSH1 (0x60) has 1 immediate byte, PUSH32 (0x7f) has 32 immediate bytes.
        return op - 0x5f
    return 0

def parse_bytecode(bytecode):
    """
    Walk through raw bytecode and return a list of Instruction objects.
    """
    instructions = []
    pc = 0
    while pc < len(bytecode):
        op = bytecode[pc]
        name = get_opcode_name(op)
        imm_bytes = immediate_bytes_for_opcode(op)
        operand = None
        if imm_bytes > 0:
            if pc + 1 + imm_bytes <= len(bytecode):
                operand = bytecode[pc+1:pc+1+imm_bytes]
            else:
                operand = bytecode[pc+1:]
            instructions.append(Instruction(pc, op, name, operand))
            pc += 1 + imm_bytes
        else:
            instructions.append(Instruction(pc, op, name))
            pc += 1
    return instructions

def detect_functions(instructions):
    """
    Detect function dispatch patterns:
    Look for the pattern: PUSH4 <signature> -> EQ -> PUSH2 <jumpdest> -> JUMPI
    Returns a list of functions as dictionaries.
    """
    functions = []
    # We must have at least 4 instructions remaining, so iterate until len(instructions) - 3.
    for i in range(len(instructions) - 3):
        inst1 = instructions[i]
        inst2 = instructions[i+1]
        inst3 = instructions[i+2]
        inst4 = instructions[i+3]
        # Check that the first instruction is a PUSH with exactly 4 immediate bytes.
        if inst1.name.startswith("PUSH") and inst1.operand and len(inst1.operand) == 4:
            if inst2.name == "EQ":
                # Next, check if we have a push instruction for jump destination.
                if inst3.name.startswith("PUSH") and inst3.operand and len(inst3.operand) in (1, 2):
                    if inst4.name == "JUMPI":
                        selector = inst1.operand.hex()
                        jumpdest = int.from_bytes(inst3.operand, byteorder='big')
                        functions.append({
                            "selector": selector,
                            "jumpdest": jumpdest,
                            "dispatcher_index": i
                        })
    return functions

def decompile(bytecode_filename):
    # Read the raw bytecode from file.
    try:
        with open(bytecode_filename, "r") as f:
            bytecode = f.read()
        bytecode = bytes.fromhex(bytecode)
    except FileNotFoundError:
        print(f"Error: file {bytecode_filename} not found.")
        return

    instructions = parse_bytecode(bytecode)
    functions = detect_functions(instructions)

    with open('signatures.txt','w') as f:
        if not functions:
            print("No function dispatch patterns detected.")
        else:
            for func in sorted(functions, key=lambda x: x['selector']):
                print(f" Function selector: 0x{func['selector']} | Jump destination: {func['jumpdest']}")
                f.write(f"{func['selector']}\n")

if __name__ == "__main__":
    decompile('0x5af0d9827e0c53e4799bb226655a1de152a425a5.hex')