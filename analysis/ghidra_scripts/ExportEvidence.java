// Deterministic, bounded static evidence export for JAQ. The imported program is never executed.
// @category JAQ

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

public class ExportEvidence extends GhidraScript {
    private static final int MAX_RECORDS = 100000;
    private static final int MAX_TEXT = 65536;
    private static final int MAX_DECOMPILED_FUNCTIONS = 2000;
    private static final long MAX_TOTAL_TEXT = 128L * 1024L * 1024L;

    private static final class Record {
        final String type;
        final String raw;
        final String normalized;
        final String location;
        final String source;
        final String relationKind;
        final String relationSource;
        final String relationTarget;

        Record(String type, String raw, String normalized, String location, String source) {
            this(type, raw, normalized, location, source, "", "", "");
        }

        Record(String type, String raw, String normalized, String location, String source,
                String relationKind, String relationSource, String relationTarget) {
            this.type = type;
            this.raw = bounded(raw);
            this.normalized = bounded(normalized);
            this.location = location;
            this.source = source;
            this.relationKind = relationKind;
            this.relationSource = relationSource;
            this.relationTarget = relationTarget;
        }

        String json() {
            String relation = relationKind.isEmpty() ? "" :
                ",\"relationships\":{\"kind\":\"" + escape(relationKind)
                + "\",\"source_address\":\"" + escape(relationSource)
                + "\",\"target_address\":\"" + escape(relationTarget) + "\"}";
            return "{\"type\":\"" + escape(type) + "\","
                + "\"raw_value\":\"" + escape(raw) + "\","
                + "\"normalized_value\":\"" + escape(normalized) + "\","
                + "\"artifact_location\":\"" + escape(location) + "\","
                + "\"analyzer\":{\"name\":\"ghidra\",\"version\":\"12.1.3\"},"
                + "\"provenance\":{\"source\":\"" + escape(source) + "\"}"
                + relation + "}";
        }
    }

    private final List<Record> records = new ArrayList<>();
    private long totalTextChars = 0;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("ExportEvidence requires one controller-selected output path");
        }

        add("pe.metadata.format", currentProgram.getExecutableFormat(), currentProgram.getExecutableFormat(), "program", "program-info");
        add("pe.metadata.language", currentProgram.getLanguageID().toString(), currentProgram.getLanguageID().toString(), "program", "program-info");
        add("pe.metadata.compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(), currentProgram.getCompilerSpec().getCompilerSpecID().toString(), "program", "program-info");
        add("pe.metadata.image_base", currentProgram.getImageBase().toString(), currentProgram.getImageBase().toString(), "program", "program-info");

        exportMemoryBlocks();
        exportSymbols();
        exportFunctions();
        exportReferences();
        exportStrings();

        Collections.sort(records, Comparator
            .comparing((Record r) -> r.type)
            .thenComparing(r -> r.location)
            .thenComparing(r -> r.normalized)
            .thenComparing(r -> r.raw));

        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0], false), StandardCharsets.UTF_8))) {
            for (Record record : records) {
                writer.write(record.json());
                writer.newLine();
            }
        }
    }

    private void exportMemoryBlocks() {
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            String value = block.getName() + " start=" + block.getStart() + " end=" + block.getEnd()
                + " size=" + block.getSize() + " r=" + block.isRead() + " w=" + block.isWrite()
                + " x=" + block.isExecute() + " initialized=" + block.isInitialized();
            String kind = block.getName().equalsIgnoreCase(".rsrc") ? "pe.resource.section" : "pe.section.memory";
            add(kind, value, value, "va:" + block.getStart(), "memory-block");
        }
    }

    private void exportSymbols() throws Exception {
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext() && !isFull()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            String type = symbol.isExternal() ? "pe.import.symbol" : "ghidra.symbol";
            String location = symbol.getAddress() == null ? "external" : "va:" + symbol.getAddress();
            add(type, symbol.getName(true), symbol.getName(true), location, "symbol-table");
        }
        AddressIterator entries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext() && !isFull()) {
            monitor.checkCancelled();
            Address entry = entries.next();
            add("ghidra.entrypoint", entry.toString(), entry.toString(), "va:" + entry, "symbol-table");
        }
    }

    private void exportFunctions() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int decompiled = 0;
        try {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !isFull()) {
                monitor.checkCancelled();
                Function function = functions.next();
                String address = function.getEntryPoint().toString();
                add("ghidra.function", function.getSignature().getPrototypeString(), function.getName(),
                    "va:" + address, "function-manager");

                List<Function> callees = new ArrayList<>();
                Set<Function> called = function.getCalledFunctions(monitor);
                for (Function callee : called) {
                    callees.add(callee);
                }
                Collections.sort(callees, Comparator
                    .comparing((Function f) -> f.getEntryPoint().toString())
                    .thenComparing(Function::getName));
                for (Function callee : callees) {
                    String target = callee.getEntryPoint().toString();
                    String value = address + " -> " + target + " " + callee.getName();
                    addRelation("ghidra.call", value, value, "va:" + address,
                        "function-callgraph", "call", "va:" + address, "va:" + target);
                }

                if (decompiled < MAX_DECOMPILED_FUNCTIONS) {
                    DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                    if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        add("ghidra.decompilation", result.getDecompiledFunction().getC(),
                            function.getName(), "va:" + address, "decompiler");
                    }
                    decompiled++;
                }
            }
        } finally {
            decompiler.dispose();
        }
    }

    private void exportReferences() throws Exception {
        ReferenceIterator references = currentProgram.getReferenceManager().getReferenceIterator(currentProgram.getMinAddress());
        while (references.hasNext() && !isFull()) {
            monitor.checkCancelled();
            Reference reference = references.next();
            String value = reference.getFromAddress() + " -> " + reference.getToAddress()
                + " type=" + reference.getReferenceType();
            addRelation("ghidra.reference", value, value, "va:" + reference.getFromAddress(),
                "reference-manager", "reference", "va:" + reference.getFromAddress(),
                "va:" + reference.getToAddress());
        }
    }

    private void exportStrings() throws Exception {
        for (Data data : DefinedStringIterator.forProgram(currentProgram)) {
            if (isFull()) {
                break;
            }
            monitor.checkCancelled();
            StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
            String value = instance.getStringValue();
            if (value != null) {
                add("pe.string.defined", value, value, "va:" + data.getAddress(), "defined-data");
            }
        }
    }

    private void add(String type, String raw, String normalized, String location, String source) {
        append(new Record(type, raw == null ? "" : raw, normalized == null ? "" : normalized,
            location == null ? "program" : location, source));
    }

    private void addRelation(String type, String raw, String normalized, String location, String source,
            String kind, String relationSource, String relationTarget) {
        append(new Record(type, raw == null ? "" : raw, normalized == null ? "" : normalized,
            location == null ? "program" : location, source, kind, relationSource, relationTarget));
    }

    private void append(Record record) {
        long cost = escapedLength(record.raw) + escapedLength(record.normalized)
            + escapedLength(record.location) + escapedLength(record.source)
            + escapedLength(record.relationSource) + escapedLength(record.relationTarget);
        if (isFull()) {
            return;
        }
        if (cost > MAX_TOTAL_TEXT - totalTextChars) {
            totalTextChars = MAX_TOTAL_TEXT;
            return;
        }
        if (!isFull()) {
            records.add(record);
            totalTextChars += cost;
        }
    }

    private boolean isFull() {
        return records.size() >= MAX_RECORDS || totalTextChars >= MAX_TOTAL_TEXT;
    }

    private static String bounded(String value) {
        if (value == null || value.length() <= MAX_TEXT) {
            return value == null ? "" : value;
        }
        return value.substring(0, MAX_TEXT) + "\n[truncated by JAQ]";
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20 || Character.isSurrogate(c)) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private static long escapedLength(String value) {
        long length = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '"' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') {
                length += 2;
            } else if (c < 0x20 || Character.isSurrogate(c)) {
                length += 6;
            } else if (c <= 0x7f) {
                length += 1;
            } else if (c <= 0x7ff) {
                length += 2;
            } else {
                length += 3;
            }
        }
        return length;
    }
}
