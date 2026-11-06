"""Build the standalone Windows native library; never deploy or launch Minecraft."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "native-local"
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def run(args, **kwargs):
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace", creationflags=FLAGS, **kwargs)
    if result.returncode:
        print(result.stdout[-16000:], flush=True)
        result.check_returncode()


def tool(variable, name, fallback):
    selected = os.environ.get(variable) or shutil.which(name) or str(fallback)
    path = Path(selected)
    if not path.is_file():
        raise RuntimeError(f"Missing {name}; set {variable} to its full path")
    return path.resolve()


def cmake_tools():
    directory = ROOT / ".tooling"
    cmake = directory / "cmake/data/bin/cmake.exe"
    ninja = directory / "bin/ninja.exe"
    if not cmake.is_file() or not ninja.is_file():
        run([sys.executable, "-m", "pip", "install", "--target", directory,
             "cmake==4.4.4", "ninja==1.13.2"])
    return cmake, ninja


def configure_keys():
    config = ROOT / "build/local-config"
    key_file = config / "package-secrets.json"
    config.mkdir(parents=True, exist_ok=True)
    if key_file.is_file():
        keys = json.loads(key_file.read_text(encoding="utf-8"))
    else:
        keys = {name: secrets.token_hex(32) for name in ("outer", "class")}
        key_file.write_text(json.dumps(keys), encoding="utf-8")
    for name in ("outer", "class"):
        value = keys.get(name)
        if not isinstance(value, str) or len(value) != 64 or len(bytes.fromhex(value)) != 32:
            raise RuntimeError("Invalid local packaging configuration")
    header = config / "himitsu/local_test_build.hpp"
    header.parent.mkdir(parents=True, exist_ok=True)
    content = ("#pragma once\nnamespace himitsu::local_test {\n"
               f'inline constexpr char outer_secret[] = "{keys["outer"]}";\n'
               f'inline constexpr char class_secret[] = "{keys["class"]}";\n'
               "}\n")
    if not header.is_file() or header.read_text(encoding="utf-8") != content:
        header.write_text(content, encoding="utf-8")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("configure", "build", "check", "bridge-check"):
        raise RuntimeError("Usage: build_native.py configure|build|check|bridge-check")
    mode = sys.argv[1]
    if mode == "build":
        cmake, _ = cmake_tools()
        run([cmake, "--build", BUILD, "--parallel", "4"])
        return
    zig = tool("HIMITSU_ZIG", "zig", Path(r"D:\桌面\MOD\.build-tools\zig-windows-x86_64-0.13.0\zig.exe"))
    java = Path(os.environ.get("JAVA_HOME", ""))
    if not (java / "include/jni.h").is_file():
        raise RuntimeError("JAVA_HOME must point to a JDK 17 installation")
    if mode == "bridge-check":
        output = ROOT / "build/bridge-binding-check.dll"
        output.parent.mkdir(parents=True, exist_ok=True)
        run([zig, "c++", "-target", "x86_64-windows-gnu", "-std=c++20", "-O2", "-shared",
             "-I", java / "include", "-I", java / "include/win32",
             ROOT / "native/tests/bridge_binding_test.cpp", "-o", output])
        return
    if mode == "configure":
        configure_keys()
        cmake, ninja = cmake_tools()
        run([cmake, "-S", ROOT / "native", "-B", BUILD, "-G", "Ninja",
             f"-DCMAKE_MAKE_PROGRAM={ninja}", f"-DCMAKE_C_COMPILER={zig}",
             "-DCMAKE_C_COMPILER_ARG1=cc", f"-DCMAKE_CXX_COMPILER={zig}",
             "-DCMAKE_CXX_COMPILER_ARG1=c++", "-DCMAKE_C_FLAGS=-target x86_64-windows-gnu",
             "-DCMAKE_CXX_FLAGS=-target x86_64-windows-gnu", "-DCMAKE_BUILD_TYPE=Release",
             "-DHIMITSU_LLVM_OBFUSCATION=OFF", "-DHIMITSU_LOCAL_TEST=ON"])
    else:
        output = ROOT / "build/local-shutdown-test.exe"
        output.parent.mkdir(parents=True, exist_ok=True)
        run([zig, "c++", "-target", "x86_64-windows-gnu", "-std=c++20", "-O2",
             "-D_WIN32_WINNT=0x0A00", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX",
             "-I", ROOT / "native/include", "-I", java / "include",
             "-I", java / "include/win32", ROOT / "native/tests/local_shutdown_test.cpp",
             ROOT / "native/src/core/runtime_state.cpp", "-o", output])
        run([output], timeout=15)


if __name__ == "__main__":
    main()
