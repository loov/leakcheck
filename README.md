# leakcheck

leakcheck analyses program syscalls and checks whether:

* [x] Files are properly closed
* [x] Open files are not deleted
* [x] Connections are closed properly
* [x] Servers are stopped properly
* [x] With `-temponly`, whether tests use only temp directory for tests.

Currently supported:

* [x] Linux 64
* [x] Linux 32
* [ ] Mac
* [ ] Windows

## Using with Go test

This can be used together with Go tests:

```
# checking for proper connection and file use
go test -exec leakcheck .

# additionally checking that all files are created in temp
go test -exec "leakcheck -temponly" .
```