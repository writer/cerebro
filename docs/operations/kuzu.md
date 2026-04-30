# Kuzu graph store: portable CGO builds

The `github.com/kuzudb/go-kuzu` driver bakes a `${SRCDIR}`-relative `-Wl,-rpath` into the linked
binary. `${SRCDIR}` resolves to the **build host's** `$GOPATH/pkg/mod/github.com/kuzudb/go-kuzu@vX.Y.Z/lib/dynamic/<os-arch>`
directory, so a binary copied from the build host to a different machine (or container layer) loses
its dynamic loader path and fails at startup with a `dyld: Library not loaded: @rpath/libkuzu.dylib`
or `error while loading shared libraries: libkuzu.so` error.

`make build-portable` (a thin wrapper around `scripts/build_with_kuzu.sh`) avoids this by:

1. Locating `libkuzu.{dylib,so}` in the resolved `go list -m` directory for the platform.
2. Copying it next to `bin/cerebro`.
3. Re-running `go build` with `CGO_LDFLAGS` overridden to use a `$ORIGIN`-relative
   (`@loader_path` on macOS) rpath, taking precedence over the rpath emitted by the
   driver's `#cgo` directive.

The resulting `bin/` directory contains a self-contained `cerebro` plus its libkuzu and can be
shipped to any host with the same OS/arch without further rpath fixups. CI release builds and
Docker images should call `make build-portable` instead of plain `go build`.

If you need to override the platform staging (e.g. cross-compile), set:

* `CGO_LDFLAGS="-Wl,-rpath,/opt/cerebro/lib"` and place `libkuzu.{dylib,so}` at that absolute path.
* `LD_LIBRARY_PATH=/opt/cerebro/lib` (Linux) / `DYLD_LIBRARY_PATH=/opt/cerebro/lib` (macOS) at run time.
