# leakcheck

leakcheck analyses program syscalls and checks whether:

* [x] Files are properly closed
* [ ] Open files are not deleted
* [ ] Connections are closed properly
* [ ] Servers are stopped properly
* [ ] With `-temponly`, whether tests use only temp directory for tests.

Currently supported:

* [x] Linux
* [ ] Mac
* [ ] Windows