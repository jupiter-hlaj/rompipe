// NESAnalyzer.java — Ghidra headless post-analysis script for NES PRG-ROM
//
// Runs after Ghidra's auto-analysis. Exports:
//   - $NES_DISASM_OUT/functions.json       — function boundaries + call graph
//   - $NES_DISASM_OUT/register_accesses.json — all NES hardware register access sites
//   - $NES_DISASM_OUT/bank_NN.asm          — per-bank disassembly listings
//   - $NES_DISASM_OUT/call_graph.json      — caller/callee pairs
//
// Environment variables consumed:
//   NES_RESET       — RESET vector address (hex, no 0x prefix)
//   NES_NMI         — NMI vector address
//   NES_IRQ         — IRQ vector address
//   NES_DISASM_OUT  — output directory path

//@category NES
//@menupath Analysis.NES Analyzer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.flatapi.FlatProgramAPI;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class NESAnalyzer extends GhidraScript {

    // NES hardware register ranges
    private static final long PPU_BASE  = 0x2000L;
    private static final long PPU_END   = 0x4000L;
    private static final long APU_BASE  = 0x4000L;
    private static final long APU_END   = 0x4018L;

    private static final Map<Long, String> HW_REG_NAMES = new LinkedHashMap<>();
    static {
        HW_REG_NAMES.put(0x2000L, "PPUCTRL");
        HW_REG_NAMES.put(0x2001L, "PPUMASK");
        HW_REG_NAMES.put(0x2002L, "PPUSTATUS");
        HW_REG_NAMES.put(0x2003L, "OAMADDR");
        HW_REG_NAMES.put(0x2004L, "OAMDATA");
        HW_REG_NAMES.put(0x2005L, "PPUSCROLL");
        HW_REG_NAMES.put(0x2006L, "PPUADDR");
        HW_REG_NAMES.put(0x2007L, "PPUDATA");
        HW_REG_NAMES.put(0x4000L, "SQ1_VOL");
        HW_REG_NAMES.put(0x4001L, "SQ1_SWEEP");
        HW_REG_NAMES.put(0x4002L, "SQ1_LO");
        HW_REG_NAMES.put(0x4003L, "SQ1_HI");
        HW_REG_NAMES.put(0x4004L, "SQ2_VOL");
        HW_REG_NAMES.put(0x4005L, "SQ2_SWEEP");
        HW_REG_NAMES.put(0x4006L, "SQ2_LO");
        HW_REG_NAMES.put(0x4007L, "SQ2_HI");
        HW_REG_NAMES.put(0x4008L, "TRI_LINEAR");
        HW_REG_NAMES.put(0x400AL, "TRI_LO");
        HW_REG_NAMES.put(0x400BL, "TRI_HI");
        HW_REG_NAMES.put(0x400CL, "NOISE_VOL");
        HW_REG_NAMES.put(0x400EL, "NOISE_LO");
        HW_REG_NAMES.put(0x400FL, "NOISE_HI");
        HW_REG_NAMES.put(0x4010L, "DMC_FREQ");
        HW_REG_NAMES.put(0x4011L, "DMC_RAW");
        HW_REG_NAMES.put(0x4012L, "DMC_START");
        HW_REG_NAMES.put(0x4013L, "DMC_LEN");
        HW_REG_NAMES.put(0x4014L, "OAMDMA");
        HW_REG_NAMES.put(0x4015L, "APU_STATUS");
        HW_REG_NAMES.put(0x4016L, "JOY1");
        HW_REG_NAMES.put(0x4017L, "FRAME_CNT");
    }

    @Override
    public void run() throws Exception {
        String outDir     = System.getenv("NES_DISASM_OUT");
        String resetHex   = System.getenv("NES_RESET");
        String nmiHex     = System.getenv("NES_NMI");
        String irqHex     = System.getenv("NES_IRQ");

        if (outDir == null) {
            println("ERROR: NES_DISASM_OUT env var not set");
            return;
        }

        Files.createDirectories(Paths.get(outDir));

        FlatProgramAPI api = new FlatProgramAPI(currentProgram, monitor);
        AddressFactory af  = currentProgram.getAddressFactory();
        Listing listing    = currentProgram.getListing();
        Memory memory      = currentProgram.getMemory();

        // Mark interrupt vectors as entry points and create functions
        String[] vecHexes  = {resetHex, nmiHex, irqHex};
        String[] vecNames  = {"RESET_HANDLER", "NMI_HANDLER", "IRQ_HANDLER"};
        for (int i = 0; i < vecHexes.length; i++) {
            if (vecHexes[i] != null && !vecHexes[i].isEmpty()) {
                try {
                    long addr = Long.parseLong(vecHexes[i], 16);
                    Address a = af.getAddress(String.format("0x%04X", addr));
                    if (a != null) {
                        api.createFunction(a, vecNames[i]);
                        println("Created entry: " + vecNames[i] + " @ " + a);
                    }
                } catch (NumberFormatException e) {
                    println("WARNING: Could not parse vector address: " + vecHexes[i]);
                }
            }
        }

        // Run standard analysis
        analyzeAll(currentProgram);

        // Collect all functions
        Map<String, Map<String, Object>> functions = new LinkedHashMap<>();
        FunctionIterator funcIter = listing.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String addrStr = "0x" + func.getEntryPoint().toString().toUpperCase();
            List<String> callers = new ArrayList<>();
            List<String> callees = new ArrayList<>();

            for (Function caller : func.getCallingFunctions(monitor)) {
                callers.add("0x" + caller.getEntryPoint().toString().toUpperCase());
            }
            for (Function callee : func.getCalledFunctions(monitor)) {
                callees.add("0x" + callee.getEntryPoint().toString().toUpperCase());
            }

            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name",    func.getName());
            info.put("start",   addrStr);
            info.put("end",     "0x" + func.getBody().getMaxAddress().toString().toUpperCase());
            info.put("callers", callers);
            info.put("callees", callees);
            functions.put(addrStr, info);
        }

        // Collect hardware register accesses
        List<Map<String, String>> regAccesses = new ArrayList<>();
        InstructionIterator instrIter = listing.getInstructions(true);
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            String mnem = instr.getMnemonicString().toUpperCase();
            boolean isWrite = mnem.equals("STA") || mnem.equals("STX") || mnem.equals("STY");
            boolean isRead  = mnem.equals("LDA") || mnem.equals("LDX") || mnem.equals("LDY") || mnem.equals("BIT");

            if (!isWrite && !isRead) continue;

            for (int op = 0; op < instr.getNumOperands(); op++) {
                Address ref = instr.getAddress(op);
                if (ref == null) continue;
                long refAddr = ref.getOffset();
                if (HW_REG_NAMES.containsKey(refAddr)) {
                    Map<String, String> access = new LinkedHashMap<>();
                    access.put("address",    "0x" + instr.getAddress().toString().toUpperCase());
                    access.put("hw_address", String.format("0x%04X", refAddr));
                    access.put("hw_name",    HW_REG_NAMES.get(refAddr));
                    access.put("type",       refAddr < 0x4000 ? "PPU" : "APU");
                    access.put("access",     isWrite ? "write" : "read");
                    access.put("mnemonic",   mnem);
                    regAccesses.add(access);
                }
            }
        }

        // Export per-bank disassembly listings
        long baseAddr    = 0x8000L;
        int  bankSz16kb  = 0x4000;
        MemoryBlock[] blocks = memory.getBlocks();
        // Find the total PRG size from the memory block
        long totalSize = 0;
        for (MemoryBlock b : blocks) {
            totalSize = Math.max(totalSize, b.getEnd().getOffset() - baseAddr + 1);
        }
        int numBanks = (int) Math.max(1, (totalSize + bankSz16kb - 1) / bankSz16kb);

        for (int bankIdx = 0; bankIdx < numBanks; bankIdx++) {
            long bankStart = baseAddr + (long) bankIdx * bankSz16kb;
            long bankEnd   = bankStart + bankSz16kb;
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("; NES PRG Bank %02d — $%04X–$%04X\n", bankIdx, bankStart, bankEnd - 1));
            sb.append(String.format(".org $%04X\n\n", bankStart));

            Address startA = af.getAddress(String.format("0x%04X", bankStart));
            Address endA   = af.getAddress(String.format("0x%04X", bankEnd - 1));
            if (startA == null) continue;

            InstructionIterator bankIter = listing.getInstructions(startA, true);
            while (bankIter.hasNext()) {
                Instruction instr = bankIter.next();
                if (instr.getAddress().getOffset() >= bankEnd) break;
                sb.append(String.format("$%04X:  %-6s %s\n",
                    instr.getAddress().getOffset(),
                    instr.getMnemonicString(),
                    instr.getDefaultOperandRepresentation(0)));
            }

            Path bankPath = Paths.get(outDir, String.format("bank_%02d.asm", bankIdx));
            Files.writeString(bankPath, sb.toString());
        }

        // Write JSON outputs
        writeJson(Paths.get(outDir, "functions.json"), toJson(functions));
        writeJson(Paths.get(outDir, "register_accesses.json"), toJson(regAccesses));

        // call_graph.json: flat list of edges
        List<Map<String, String>> edges = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> e : functions.entrySet()) {
            String from = e.getKey();
            List<String> callees = (List<String>) e.getValue().get("callees");
            for (String to : callees) {
                Map<String, String> edge = new LinkedHashMap<>();
                edge.put("from", from);
                edge.put("to", to);
                edges.add(edge);
            }
        }
        writeJson(Paths.get(outDir, "call_graph.json"), toJson(edges));

        println(String.format("NESAnalyzer: exported %d functions, %d register accesses, %d banks",
            functions.size(), regAccesses.size(), numBanks));
    }

    private static void writeJson(Path path, String json) throws IOException {
        Files.writeString(path, json);
    }

    // Minimal JSON serializer (avoids external deps in Ghidra context)
    private static String toJson(Object obj) {
        if (obj instanceof Map) {
            StringBuilder sb = new StringBuilder("{\n");
            Map<?, ?> map = (Map<?, ?>) obj;
            int i = 0;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                sb.append("  ").append(jsonStr(e.getKey().toString()))
                  .append(": ").append(toJson(e.getValue()));
                if (++i < map.size()) sb.append(",");
                sb.append("\n");
            }
            return sb.append("}").toString();
        } else if (obj instanceof List) {
            StringBuilder sb = new StringBuilder("[\n");
            List<?> list = (List<?>) obj;
            for (int i = 0; i < list.size(); i++) {
                sb.append("  ").append(toJson(list.get(i)));
                if (i < list.size() - 1) sb.append(",");
                sb.append("\n");
            }
            return sb.append("]").toString();
        } else if (obj instanceof Boolean) {
            return obj.toString();
        } else if (obj instanceof Number) {
            return obj.toString();
        } else if (obj == null) {
            return "null";
        } else {
            return jsonStr(obj.toString());
        }
    }

    private static String jsonStr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "") + "\"";
    }
}
