#!/bin/bash -ex

# Requires Latest release of Solana's custom LLVM
#https://github.com/solana-labs/llvm-builder/releases

LLVM_DIR=/Users/sladuca/solana-llvm-builder/osx/out/deploy/bin/

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o noop.o -c noop.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -o noop.so noop.o
rm noop.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o noro.o -c noro.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic elf.ld -o noro.so noro.o
rm noro.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o empty_rodata.o -c empty_rodata.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -o empty_rodata.so empty_rodata.o
rm empty_rodata.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o unresolved_syscall.o -c unresolved_syscall.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -o unresolved_syscall.so unresolved_syscall.o
rm unresolved_syscall.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o entrypoint.o -c entrypoint.c
"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o syscall.o -c syscall.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -entry entrypoint -o multiple_file.so entrypoint.o syscall.o
rm entrypoint.o
rm syscall.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o relative_call.o -c relative_call.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -entry entrypoint -o relative_call.so relative_call.o
rm relative_call.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o scratch_registers.o -c scratch_registers.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -entry entrypoint -o scratch_registers.so scratch_registers.o
rm scratch_registers.o

"$LLVM_DIR"clang -Werror -target bpf -O2 -fno-builtin -fPIC -o pass_stack_reference.o -c pass_stack_reference.c
"$LLVM_DIR"ld.lld -z notext --verbose -shared --Bdynamic -entry entrypoint -o pass_stack_reference.so pass_stack_reference.o
rm pass_stack_reference.o


"$LLVM_DIR"clang -Werror -g -target bpf -O2 -fno-builtin -fPIC -v -Xclang -target-feature -Xclang +dwarfris -o binarysearch.o -c binarysearch.c
# "$LLVM_DIR"clang -Werror -g -O2 -fno-builtin -fPIC -v -o binarysearch.o -c binarysearch.c
# "$LLVM_DIR"clang -Werror -g -target bpf -O2 -fno-builtin -fPIC -v -o binarysearch.o -c binarysearch.c
# cp binarysearch.o binarysearch.debug
# "$LLVM_DIR"llvm-objcopy  --only-keep-debug binarysearch.debug
# "$LLVM_DIR"llvm-strip binarysearch.o
"$LLVM_DIR"ld.lld -z notext --verbose --Bdynamic -entry entrypoint -o binarysearch.so binarysearch.o
# "$LLVM_DIR"llvm-objcopy --add-gnu-debuglink binarysearch.debug binarysearch.so
