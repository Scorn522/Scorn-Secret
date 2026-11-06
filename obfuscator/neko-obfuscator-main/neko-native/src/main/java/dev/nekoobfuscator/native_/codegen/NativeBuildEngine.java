package dev.nekoobfuscator.native_.codegen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Builds native libraries from generated C source files using zig cc.
 */
public final class NativeBuildEngine {
    private static final Logger log = LoggerFactory.getLogger(NativeBuildEngine.class);

    private final String zigPath;

    public NativeBuildEngine(String zigPath) {
        this.zigPath = zigPath;
    }

    public Map<String, byte[]> build(String cSource, String headerSource, List<String> targets) throws IOException {
        return build(
            new CCodeGenerator.GeneratedSourceSet(
                new CCodeGenerator.GeneratedSourceFile("neko_native.c", cSource),
                List.of(),
                cSource
            ),
            headerSource,
            targets
        );
    }

    public Map<String, byte[]> build(CCodeGenerator.GeneratedSourceSet sourceSet, String headerSource, List<String> targets) throws IOException {
        Path tempDir = workspaceBuildDir();
        Map<String, byte[]> results = new LinkedHashMap<>();
        Files.createDirectories(tempDir);
        {
            Path hdrFile = tempDir.resolve("neko_native.h");
            Path manifestFile = tempDir.resolve("neko_native_build_manifest.properties");
            Files.writeString(hdrFile, headerSource);
            List<Path> sourceFiles = new ArrayList<>();
            for (CCodeGenerator.GeneratedSourceFile sourceFile : sourceSet.allSources()) {
                Path sourcePath = tempDir.resolve(sourceFile.fileName());
                Files.writeString(sourcePath, sourceFile.source());
                sourceFiles.add(sourcePath);
            }
            Path implementationHeader = null;
            List<Path> implementationHeaders = new ArrayList<>();
            for (CCodeGenerator.GeneratedSourceFile headerFile : sourceSet.allImplementationHeaders()) {
                Path headerPath = tempDir.resolve(headerFile.fileName());
                Files.writeString(headerPath, headerFile.source());
                implementationHeaders.add(headerPath);
                if (sourceSet.implementationHeader() != null
                    && headerFile.fileName().equals(sourceSet.implementationHeader().fileName())) {
                    implementationHeader = headerPath;
                }
            }
            Properties manifest = new Properties();
            manifest.setProperty("generated.c.path", sourceFiles.get(0).toString());
            manifest.setProperty("generated.c.count", Integer.toString(sourceFiles.size()));
            manifest.setProperty("generated.c.paths", sourceFiles.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
            for (int i = 0; i < sourceFiles.size(); i++) {
                manifest.setProperty("generated.c." + i + ".path", sourceFiles.get(i).toString());
            }
            if (implementationHeader != null) {
                manifest.setProperty("generated.impl.header.path", implementationHeader.toString());
            }
            manifest.setProperty("generated.impl.header.count", Integer.toString(implementationHeaders.size()));
            manifest.setProperty("generated.impl.header.paths", implementationHeaders.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
            for (int i = 0; i < implementationHeaders.size(); i++) {
                manifest.setProperty("generated.impl.header." + i + ".path", implementationHeaders.get(i).toString());
            }
            manifest.setProperty("generated.impl.sliced.header.count", Integer.toString(sourceSet.implementationHeaders().size()));
            manifest.setProperty("generated.header.path", hdrFile.toString());
            manifest.setProperty("debug.build", Boolean.toString(System.getenv("NEKO_NATIVE_DEBUG") != null));
            manifest.setProperty("icache.audit.build", Boolean.toString(System.getenv("NEKO_NATIVE_ICACHE_AUDIT") != null));
            manifest.setProperty("handle.audit.build", Boolean.toString(System.getenv("NEKO_NATIVE_HANDLE_AUDIT") != null));
            manifest.setProperty("opt.diagnostics.build", Boolean.toString(System.getenv("NEKO_NATIVE_OPT_DIAGNOSTICS") != null));

            // Find JNI headers
            String javaHome = System.getProperty("java.home");
            Path jniInclude = Path.of(javaHome, "include");
            Path jniPlatformInclude = findPlatformInclude(jniInclude);

            for (String target : targets) {
                String zigTarget = mapTarget(target);
                String ext = target.contains("WINDOWS") ? ".dll" : target.contains("MACOS") ? ".dylib" : ".so";
                String libName = "libneko_" + target.toLowerCase() + ext;
                Path outputLib = tempDir.resolve(libName);
                Path objectDir = Files.createDirectories(tempDir.resolve("obj").resolve(target.toLowerCase(Locale.ROOT)));

                /* NEKO_NATIVE_DEBUG=1 keeps function symbols + frame pointers
                 * + DWARF in libneko so that gdb / addr2line can resolve
                 * trampoline / dispatcher / impl_fn frames after a crash.
                 * Default off (size-optimized release build). */
                boolean debugBuild = System.getenv("NEKO_NATIVE_DEBUG") != null;
                boolean icacheAuditBuild = System.getenv("NEKO_NATIVE_ICACHE_AUDIT") != null;
                boolean handleAuditBuild = System.getenv("NEKO_NATIVE_HANDLE_AUDIT") != null;
                boolean optDiagnosticsBuild = System.getenv("NEKO_NATIVE_OPT_DIAGNOSTICS") != null;
                List<String> commonCompileArgs = new ArrayList<>(List.of(
                    zigPath, "cc",
                    "-c",
                    debugBuild ? "-O1" : "-O3",
                    "-std=c11", "-w",
                    "-fvisibility=hidden",
                    "-target", zigTarget,
                    "-I", jniInclude.toString()
                ));
                if (!target.contains("WINDOWS")) {
                    commonCompileArgs.add("-fPIC");
                }
                if (!debugBuild) {
                    /* Pick a modern microarch baseline so generated translated
                     * methods get AVX/BMI2/FMA, not SSE2. The baselines are
                     * ten-plus years old (Intel Haswell 2013 / Apple M1 / armv8-a)
                     * and apply uniformly to every translated method, not
                     * benchmark-specific. */
                    String archFlag = switch (target) {
                        case "LINUX_X64", "WINDOWS_X64", "MACOS_X64" -> "-march=x86_64_v3";
                        case "LINUX_AARCH64" -> "-march=armv8-a";
                        case "MACOS_AARCH64" -> "-mcpu=apple_m1";
                        default -> null;
                    };
                    if (archFlag != null) {
                        commonCompileArgs.add(archFlag);
                    }
                    /* -fno-plt removes one indirection on libc calls;
                     * -fno-semantic-interposition lets the compiler inline
                     * across same-DSO references; -fmerge-all-constants
                     * deduplicates string literals to shrink .rodata;
                     * -funroll-loops lets the inner reduction loops vectorize
                     * on AVX2. All generic — they apply to every translated
                     * method, not benchmark-specific. */
                    commonCompileArgs.addAll(List.of(
                        "-fno-plt",
                        "-fno-semantic-interposition",
                        "-fmerge-all-constants",
                        "-funroll-loops"
                    ));
                }
                if (debugBuild) {
                    commonCompileArgs.addAll(List.of("-g", "-fno-omit-frame-pointer"));
                }
                if (icacheAuditBuild) {
                    commonCompileArgs.add("-DNEKO_ICACHE_AUDIT=1");
                }
                if (handleAuditBuild) {
                    commonCompileArgs.add("-DNEKO_HANDLE_AUDIT=1");
                }
                if (jniPlatformInclude != null) {
                    commonCompileArgs.addAll(List.of("-I", jniPlatformInclude.toString()));
                }
                String targetKey = "target." + target + '.';
                manifest.setProperty(targetKey + "zig.target", zigTarget);
                manifest.setProperty(targetKey + "library.path", outputLib.toString());
                Path optDiagnosticsDir = null;
                if (optDiagnosticsBuild) {
                    optDiagnosticsDir = Files.createDirectories(tempDir.resolve("opt-diagnostics").resolve(target.toLowerCase(Locale.ROOT)));
                    manifest.setProperty(targetKey + "opt.diagnostics.dir", optDiagnosticsDir.toString());
                }
                List<CompileJob> jobs = new ArrayList<>();
                for (int i = 0; i < sourceFiles.size(); i++) {
                    Path sourceFile = sourceFiles.get(i);
                    Path objectFile = objectDir.resolve(stripExtension(sourceFile.getFileName().toString()) + ".o");
                    List<String> compileCmd = new ArrayList<>(commonCompileArgs);
                    if (optDiagnosticsBuild) {
                        Path optRecordFile = optDiagnosticsDir.resolve(stripExtension(sourceFile.getFileName().toString()) + ".opt.yaml");
                        compileCmd.add("-fsave-optimization-record");
                        compileCmd.add("-foptimization-record-file=" + optRecordFile);
                        manifest.setProperty(targetKey + "compile." + i + ".opt.record.path", optRecordFile.toString());
                    }
                    compileCmd.addAll(List.of("-o", objectFile.toString(), sourceFile.toString()));
                    jobs.add(new CompileJob(i, sourceFile, objectFile, compileCmd));
                    manifest.setProperty(targetKey + "compile." + i + ".source.path", sourceFile.toString());
                    manifest.setProperty(targetKey + "compile." + i + ".object.path", objectFile.toString());
                    manifest.setProperty(targetKey + "compile." + i + ".command.line", String.join(" ", compileCmd));
                }

                List<String> linkCmd = new ArrayList<>(List.of(
                    zigPath, "cc",
                    "-shared",
                    "-target", zigTarget,
                    "-o", outputLib.toString()
                ));
                if (!debugBuild) {
                    linkCmd.add("-s");
                }
                for (CompileJob job : jobs) {
                    linkCmd.add(job.objectFile().toString());
                }
                manifest.setProperty(targetKey + "command.line", String.join(" ", linkCmd));
                manifest.setProperty(targetKey + "link.command.line", String.join(" ", linkCmd));

                log.info("Building native for {} from {} C source file(s)", target, sourceFiles.size());
                log.info("Native build manifest for {}: {}", target, manifestFile);
                List<CommandResult> compileResults = runCompileJobs(jobs);
                int compileExitCode = compileResults.stream().mapToInt(CommandResult::exitCode).filter(code -> code != 0).findFirst().orElse(0);
                for (CommandResult compileResult : compileResults) {
                    String prefix = targetKey + "compile." + compileResult.index() + '.';
                    manifest.setProperty(prefix + "exit.code", Integer.toString(compileResult.exitCode()));
                    manifest.setProperty(prefix + "compiler.output", compileResult.output());
                    manifest.setProperty(prefix + "elapsed.ms", Long.toString(compileResult.elapsedMillis()));
                }

                int exitCode = compileExitCode;
                String output = compileResults.stream()
                    .map(result -> "[compile " + result.index() + "]\n" + result.output())
                    .collect(Collectors.joining("\n"));
                if (compileExitCode == 0) {
                    log.info("Linking native for {}: {}", target, String.join(" ", linkCmd));
                    CommandResult linkResult = runCommand(-1, linkCmd);
                    exitCode = linkResult.exitCode();
                    output = output + "\n[link]\n" + linkResult.output();
                    manifest.setProperty(targetKey + "link.exit.code", Integer.toString(linkResult.exitCode()));
                    manifest.setProperty(targetKey + "link.output", linkResult.output());
                    manifest.setProperty(targetKey + "link.elapsed.ms", Long.toString(linkResult.elapsedMillis()));
                }
                manifest.setProperty(targetKey + "exit.code", Integer.toString(exitCode));
                manifest.setProperty(targetKey + "compiler.output", output);

                if (exitCode == 0 && Files.exists(outputLib)) {
                    results.put("neko/native/" + libName, Files.readAllBytes(outputLib));
                    manifest.setProperty(targetKey + "library.size.bytes", Long.toString(Files.size(outputLib)));
                    log.info("Built {} ({} bytes)", libName, Files.size(outputLib));
                } else {
                    log.warn("Failed to build for {}: exit={}\n{}", target, exitCode, output);
                }
                try (OutputStream out = Files.newOutputStream(manifestFile)) {
                    manifest.store(out, "Neko native build manifest");
                }
            }
        }
        return results;
    }

    private List<CommandResult> runCompileJobs(List<CompileJob> jobs) throws IOException {
        int workers = Math.max(1, Math.min(jobs.size(), Runtime.getRuntime().availableProcessors()));
        List<CompileJob> submissionOrder = new ArrayList<>(jobs);
        submissionOrder.sort(Comparator
            .comparingLong((CompileJob job) -> sourceSize(job.sourceFile())).reversed()
            .thenComparingInt(CompileJob::index));
        ExecutorService executor = Executors.newFixedThreadPool(workers);
        try {
            CompletionService<CommandResult> completion = new ExecutorCompletionService<>(executor);
            for (CompileJob job : submissionOrder) {
                completion.submit(() -> runCommand(job.index(), job.command()));
            }
            List<CommandResult> results = new ArrayList<>(jobs.size());
            for (int i = 0; i < jobs.size(); i++) {
                try {
                    results.add(completion.take().get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while compiling native sources", e);
                } catch (ExecutionException e) {
                    throw new IOException("Failed to compile native source", e.getCause());
                }
            }
            results.sort(Comparator.comparingInt(CommandResult::index));
            return results;
        } finally {
            executor.shutdownNow();
        }
    }

    private long sourceSize(Path sourceFile) {
        try {
            return Files.size(sourceFile);
        } catch (IOException ignored) {
            return 0L;
        }
    }

    private CommandResult runCommand(int index, List<String> command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        long started = System.nanoTime();
        Process proc = pb.start();
        String output = new String(proc.getInputStream().readAllBytes());
        int exitCode;
        try {
            exitCode = proc.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            exitCode = -1;
        }
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        return new CommandResult(index, exitCode, output, elapsedMillis);
    }

    private Path workspaceBuildDir() throws IOException {
        Path root = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path dir = root.resolve("build").resolve("neko-native-work");
        Files.createDirectories(dir);
        return dir.resolve("run-" + Long.toUnsignedString(System.nanoTime()));
    }

    private String mapTarget(String target) {
        return switch (target) {
            case "LINUX_X64" -> "x86_64-linux-gnu";
            case "LINUX_AARCH64" -> "aarch64-linux-gnu";
            case "WINDOWS_X64" -> "x86_64-windows-gnu";
            case "MACOS_X64" -> "x86_64-macos-none";
            case "MACOS_AARCH64" -> "aarch64-macos-none";
            default -> target.toLowerCase();
        };
    }

    private Path findPlatformInclude(Path jniInclude) {
        String os = System.getProperty("os.name").toLowerCase();
        String platform = os.contains("win") ? "win32" : os.contains("mac") ? "darwin" : "linux";
        Path p = jniInclude.resolve(platform);
        return Files.isDirectory(p) ? p : null;
    }

    private String stripExtension(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot >= 0 ? fileName.substring(0, dot) : fileName;
    }

    private record CompileJob(int index, Path sourceFile, Path objectFile, List<String> command) {}

    private record CommandResult(int index, int exitCode, String output, long elapsedMillis) {}

}
