# -*- coding: utf-8 -*-
# NESAnalyzer.py -- Ghidra headless post-analysis script for NES PRG-ROM (Jython)
#
# Runs after Ghidra's auto-analysis. Exports:
#   - $NES_DISASM_OUT/functions.json
#   - $NES_DISASM_OUT/register_accesses.json
#   - $NES_DISASM_OUT/bank_NN.asm
#   - $NES_DISASM_OUT/call_graph.json
#
# Environment variables:
#   NES_RESET       - RESET vector address (hex, no 0x prefix)
#   NES_NMI         - NMI vector address
#   NES_IRQ         - IRQ vector address
#   NES_DISASM_OUT  - output directory path
#   NES_BANK_IDX    - bank index for output naming

# @category NES
# @menupath Analysis.NES Analyzer

import os
import json

from ghidra.program.flatapi import FlatProgramAPI
from java.io import File


HW_REG_NAMES = {
    0x2000: "PPUCTRL",    0x2001: "PPUMASK",    0x2002: "PPUSTATUS",
    0x2003: "OAMADDR",    0x2004: "OAMDATA",    0x2005: "PPUSCROLL",
    0x2006: "PPUADDR",    0x2007: "PPUDATA",
    0x4000: "SQ1_VOL",    0x4001: "SQ1_SWEEP",  0x4002: "SQ1_LO",    0x4003: "SQ1_HI",
    0x4004: "SQ2_VOL",    0x4005: "SQ2_SWEEP",  0x4006: "SQ2_LO",    0x4007: "SQ2_HI",
    0x4008: "TRI_LINEAR", 0x400A: "TRI_LO",     0x400B: "TRI_HI",
    0x400C: "NOISE_VOL",  0x400E: "NOISE_LO",   0x400F: "NOISE_HI",
    0x4010: "DMC_FREQ",   0x4011: "DMC_RAW",    0x4012: "DMC_START", 0x4013: "DMC_LEN",
    0x4014: "OAMDMA",     0x4015: "APU_STATUS",  0x4016: "JOY1",     0x4017: "FRAME_CNT",
}


def run():
    out_dir = os.environ.get("NES_DISASM_OUT")
    reset_hex = os.environ.get("NES_RESET", "")
    nmi_hex = os.environ.get("NES_NMI", "")
    irq_hex = os.environ.get("NES_IRQ", "")
    bank_idx_str = os.environ.get("NES_BANK_IDX", "0")

    if not out_dir:
        println("ERROR: NES_DISASM_OUT env var not set")
        return

    out_path = File(out_dir)
    if not out_path.exists():
        out_path.mkdirs()

    api = FlatProgramAPI(currentProgram, monitor)
    af = currentProgram.getAddressFactory()
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()

    # Mark interrupt vectors as entry points and create functions
    vec_hexes = [reset_hex, nmi_hex, irq_hex]
    vec_names = ["RESET_HANDLER", "NMI_HANDLER", "IRQ_HANDLER"]
    for i in range(len(vec_hexes)):
        h = vec_hexes[i]
        if h and h.strip():
            try:
                addr_val = int(h, 16)
                a = af.getAddress("0x%04X" % addr_val)
                if a is not None:
                    api.createFunction(a, vec_names[i])
                    println("Created entry: %s @ %s" % (vec_names[i], str(a)))
            except Exception as e:
                println("WARNING: Could not parse vector address: %s (%s)" % (h, str(e)))

    # Run standard analysis
    analyzeAll(currentProgram)

    # Collect all functions
    functions = {}
    func_iter = listing.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        addr_str = "0x" + str(func.getEntryPoint()).upper()
        callers = []
        callees = []

        for caller in func.getCallingFunctions(monitor):
            callers.append("0x" + str(caller.getEntryPoint()).upper())
        for callee in func.getCalledFunctions(monitor):
            callees.append("0x" + str(callee.getEntryPoint()).upper())

        # Collect source ASM for this function
        src_asm = []
        body = func.getBody()
        func_instrs = listing.getInstructions(body, True)
        while func_instrs.hasNext():
            fi = func_instrs.next()
            src_asm.append("$%04X:  %-6s %s" % (
                fi.getAddress().getOffset(),
                fi.getMnemonicString(),
                fi.getDefaultOperandRepresentation(0)
            ))

        info = {
            "name": func.getName(),
            "start": addr_str,
            "end": "0x" + str(func.getBody().getMaxAddress()).upper(),
            "callers": callers,
            "callees": callees,
            "source_asm": "\n".join(src_asm),
        }
        functions[addr_str] = info

    # Collect hardware register accesses
    reg_accesses = []
    instr_iter = listing.getInstructions(True)
    while instr_iter.hasNext():
        instr = instr_iter.next()
        mnem = instr.getMnemonicString().upper()
        is_write = mnem in ("STA", "STX", "STY")
        is_read = mnem in ("LDA", "LDX", "LDY", "BIT")

        if not is_write and not is_read:
            continue

        for op in range(instr.getNumOperands()):
            ref = instr.getAddress(op)
            if ref is None:
                continue
            ref_addr = ref.getOffset()
            if ref_addr in HW_REG_NAMES:
                access = {
                    "address": "0x%s" % str(instr.getAddress()).upper(),
                    "hw_address": "0x%04X" % ref_addr,
                    "hw_name": HW_REG_NAMES[ref_addr],
                    "type": "PPU" if ref_addr < 0x4000 else "APU",
                    "access": "write" if is_write else "read",
                    "mnemonic": mnem,
                }
                reg_accesses.append(access)

    # Export disassembly for this single bank
    nes_bank_idx = int(bank_idx_str) if bank_idx_str else 0

    # Get the loaded memory range — find the block containing our code,
    # not the zero-page register block Ghidra creates for 6502
    blocks = memory.getBlocks()
    code_block = None
    for blk in blocks:
        if blk.getStart().getOffset() >= 0x8000:
            code_block = blk
            break
    if code_block is None:
        # Fallback to largest block
        largest_size = 0
        for blk in blocks:
            if blk.getSize() > largest_size:
                largest_size = blk.getSize()
                code_block = blk
    if code_block is None:
        println("ERROR: No suitable memory block found")
        return
    bank_start = code_block.getStart().getOffset()
    bank_end = code_block.getEnd().getOffset() + 1
    println("Memory block: %s $%04X-$%04X (%d bytes)" % (
        code_block.getName(), bank_start, bank_end - 1, bank_end - bank_start))

    sb = ["; NES PRG Bank %02d -- $%04X-$%04X\n" % (nes_bank_idx, bank_start, bank_end - 1)]

    start_a = af.getAddress("0x%04X" % bank_start)
    if start_a is not None:
        # Get all function entry addresses
        func_addrs = set()
        all_funcs = listing.getFunctions(True)
        while all_funcs.hasNext():
            func_addrs.add(all_funcs.next().getEntryPoint().getOffset())

        bank_iter = listing.getInstructions(start_a, True)
        while bank_iter.hasNext():
            instr = bank_iter.next()
            instr_addr = instr.getAddress().getOffset()
            if instr_addr >= bank_end:
                break
            # Emit function label if this is a function entry
            if instr_addr in func_addrs:
                f = listing.getFunctionAt(instr.getAddress())
                if f is not None:
                    sb.append("%s:" % f.getName())
            sb.append("    %-6s %s" % (
                instr.getMnemonicString(),
                instr.getDefaultOperandRepresentation(0)
            ))

    bank_path = os.path.join(out_dir, "bank_%02d.asm" % nes_bank_idx)
    with open(bank_path, "w") as fh:
        fh.write("\n".join(sb))

    # Write JSON outputs
    funcs_path = os.path.join(out_dir, "functions.json")
    with open(funcs_path, "w") as fh:
        json.dump(functions, fh, indent=2)

    regs_path = os.path.join(out_dir, "register_accesses.json")
    with open(regs_path, "w") as fh:
        json.dump(reg_accesses, fh, indent=2)

    # call_graph.json: flat list of edges
    edges = []
    for addr_str, info in functions.items():
        for to_addr in info.get("callees", []):
            edges.append({"from": addr_str, "to": to_addr})

    cg_path = os.path.join(out_dir, "call_graph.json")
    with open(cg_path, "w") as fh:
        json.dump(edges, fh, indent=2)

    println("NESAnalyzer: bank %d -- exported %d functions, %d register accesses" % (
        nes_bank_idx, len(functions), len(reg_accesses)))


try:
    run()
except Exception as e:
    import traceback
    println("FATAL ERROR in NESAnalyzer.py: " + str(e))
    println(traceback.format_exc())
