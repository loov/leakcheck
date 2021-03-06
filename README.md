# leakcheck

leakcheck analyses program syscalls and checks whether:

* [x] Files are properly closed
* [x] Open files are not deleted
* [x] Connections are closed properly
* [x] Servers are stopped properly
* [x] With `-temp`, whether tests use only temp directory for tests.

Currently supported:

* [x] Linux amd64
* [x] Linux 386
* [ ] Mac
* [ ] Windows

## Using with Go test

This can be used together with Go tests:

```
# checking for proper connection and file use
go test -exec leakcheck .

# additionally checking that all files are created in temp
go test -exec "leakcheck -temp" .
```