#!/usr/bin/env python3
"""
Build Z3 4.12+ static library for hexcore-rellic.

Usage:
    python _build_z3.py [--z3-src C:\\z3]

Prerequisites:
    - VS2022 with MSVC 14.44 toolset
    - LLVM/Clang 21 as host compiler (clang-cl in PATH)
    - CMake 3.21+ and Ninja in PATH
    - Run from VS Developer Command Prompt

Copyright (c) HikariSystem. All rights reserved.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Build Z3 static lib')
    parser.add_argument('--z3-src', required=True, help='Path to Z3 source')
    parser.add_argument('--output', default='deps/z3', help='Output directory')
    args = parser.parse_args()

    z3_src = Path(args.z3_src)
    if not (z3_src / 'CMakeLists.txt').exists():
        print(f'ERROR: Z3 source not found at {z3_src}')
        sys.exit(1)

    build_dir = Path('z3-build')
    output_dir = Path(args.output)

    # Configure
    print('Configuring Z3 build...')
    subprocess.check_call([
        'cmake', '-G', 'Ninja',
        '-S', str(z3_src),
        '-B', str(build_dir),
        '-DCMAKE_C_COMPILER=clang-cl',
        '-DCMAKE_CXX_COMPILER=clang-cl',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DBUILD_SHARED_LIBS=OFF',
        '-DZ3_BUILD_LIBZ3_SHARED=OFF',
        '-DZ3_BUILD_EXECUTABLE=OFF',
        '-DZ3_BUILD_TEST_EXECUTABLES=OFF',
        '-DZ3_BUILD_PYTHON_BINDINGS=OFF',
        '-DZ3_BUILD_DOTNET_BINDINGS=OFF',
        '-DZ3_BUILD_JAVA_BINDINGS=OFF',
    ])

    # Build
    print('Building Z3...')
    subprocess.check_call(['cmake', '--build', str(build_dir)])

    # Copy to output
    output_dir.mkdir(parents=True, exist_ok=True)
    include_dst = output_dir / 'include'
    lib_dst = output_dir / 'lib'

    if include_dst.exists():
        shutil.rmtree(include_dst)
    if lib_dst.exists():
        shutil.rmtree(lib_dst)

    # Copy headers
    include_dst.mkdir(parents=True, exist_ok=True)
    src_include = z3_src / 'src' / 'api'
    for header in ['z3.h', 'z3_api.h', 'z3_ast_containers.h',
                    'z3_algebraic.h', 'z3_polynomial.h', 'z3_rcf.h',
                    'z3_fixedpoint.h', 'z3_optimization.h', 'z3_fpa.h',
                    'z3_spacer.h', 'z3_macros.h', 'z3_v1.h']:
        src = src_include / header
        if src.exists():
            shutil.copy2(src, include_dst)
    # C++ header
    cpp_header = z3_src / 'src' / 'api' / 'c++' / 'z3++.h'
    if cpp_header.exists():
        shutil.copy2(cpp_header, include_dst)

    # Copy lib
    lib_dst.mkdir(parents=True, exist_ok=True)
    for ext in ['.lib', '.a']:
        lib_file = build_dir / 'src' / f'libz3{ext}'
        if lib_file.exists():
            shutil.copy2(lib_file, lib_dst)
            print(f'  Copied {lib_file.name}')

    print(f'\nZ3 installed to {output_dir}')

if __name__ == '__main__':
    main()
