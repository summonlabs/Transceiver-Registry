# Downstream consumer example

This directory is an **independent CMake project**. It is not referenced anywhere
in the Transceiver Registry build (no `add_subdirectory`), it never reads the
repository's build tree, and it links the library the way an unrelated product
would: through an installed package found with `find_package(TransceiverRegistry
REQUIRED)` and the imported target `TransceiverRegistry::trxreg`.

`main.cpp` registers a source and a module, publishes one capability and one
telemetry sample, and then takes three compatibility decisions whose outcomes are
fixed by rules it publishes itself:

| rules published | expected outcome |
| --- | --- |
| allow rule only (priority 10) | `COMPATIBLE` |
| allow + deny rule (priority 100) | `INCOMPATIBLE` |
| both retired | `UNKNOWN` (closure open) |

The program returns 0 only when every decision is one of the four modelled
outcomes and matches the expectation above; it prints one line per step.

## Building against an installed package

Install the library first (from the repository root, in a build directory of your
choice):

```sh
cmake --install <build dir> --prefix <install prefix>
```

Then, with `<dir>` any scratch build directory outside the repository:

```sh
cmake -S examples/downstream -B <dir> -DCMAKE_PREFIX_PATH=<install prefix>
cmake --build <dir>
<dir>/trxreg_downstream
```

On Windows with a multi-configuration generator the executable lands in a
configuration subdirectory, for example
`<dir>/Release/trxreg_downstream.exe`.

`CMAKE_PREFIX_PATH` is the only thing this project needs: the installed package
carries the headers, the library, and its own dependency on `Threads`.
