A Minecraft server supporting versions 1.8.X and, by chance, others.

For now the focus is on getting 1.8.X to work properly and then possibly later on top of that we'll switch on the protocol version and do different things for other/newer versions

Many servers allow for example 1.8-1.19 versions and would in that case use 1.8 as the base versions.
Here are two strategies I know for doing that:
* Switch everywhere on the client's protocol version and do different things based on that
* When the data comes in initially, make it compatible with what we expect for the base version (for example 1.8)
  So for a 1.19 packet that could mean changing a packet ID to match the 1.8 protocol. So the compatibility is ensured in one place instead of multiple ones.
  This way is said to be easier than the first because you don't have to switch on the protocol version all throughout the code.
So in the future this server could support versions on top of 1.8 as the base by making them compatible (this also should be configurable)

## Features

* [ ] Compression (std zlib writer)
* [ ] Configurable proper legacy packet handling
* [ ] Highly configurable
* [ ] High performance
* [ ] Support online-mode servers (i.e. encryption)
* [ ] Support 1.8
* [ ] Support other versions?
* [ ] Parallelize/multithread
* [ ] Allow more players to be handled than the amount of cores the server is running on by use of async/await

## References
* https://wiki.vg/
* https://wiki.vg/Protocol
* https://wiki.vg/Protocol_FAQ/
* https://wiki.vg/index.php?title=Protocol&oldid=7368
