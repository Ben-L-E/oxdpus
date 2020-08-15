# oxdpus
o**xdp**us is a toy tool that demonstrates some of the super powers of [XDP](https://www.iovisor.org/technology/xdp) - a high performance packet processing path built into the kernel.


## Requirements

To build oxdpus you have to satisify the following requirements:
- have a modern Linux kernel (>4.12) that supports XDP
- linux headers
- clang
- LLVM
- Go >1.12
- gobindata (to embed XDP bytecode inside Go binary)

This repository ships with a `Makefile` to facilitate the build process. The `make xdp` command compiles the XDP program and generates Go source code to reference the resulting bytecode. Once the XDP ELF object is produced, you can build the Go binary with `make go`. After compilation is done, the binary will be availalbe in `cmd/oxdpus/oxdpus`.

If your mere intention is to just build the Go binary without requiring modifications in the XDP program, then you'll only need the Go compiler since the XDP bytecode is already baked into the binary. 

## Usage

To see available CLI options, run `oxdpus --help`:

```
oxdpus --help
A toy tool that leverages the super powers of XDP to bring in-kernel IP filtering

Usage:
  oxdpus [command]

Available Commands:
  add         Appends a new IP address to the blacklist
  attach      Attaches the XDP program on the specified device
  detach      Removes the XDP program from the specified device
  help        Help about any command
  list        Shows all IP addresses registered in the blacklist
  remove      Removes an IP address from the blacklist

Flags:
  -h, --help   help for oxdpus

Use "oxdpus [command] --help" for more information about a command.
```

To attach the XDP program to the network interface:

```bash
$ oxdpus attach --dev=vethbd33820
INFO XDP program successfully attached to vethbd33820 device
```

The magic happens after you add a couple of IP addresses to the blacklist:

```bash
$ oxdpus add --ip=172.17.0.2
INFO 172.17.0.2 address added to the blacklist
$ oxdpus list
* 172.17.0.2
$ curl -v 172.17.0.2:80
*   Trying 172.17.0.2...
* TCP_NODELAY set
curl: (7) Failed to connect to 172.17.0.2 port 80: No route to host
```

You can remove the IP from the blacklist or even completely unload the program:

```bash
$ oxdpus remove --ip=172.17.0.2
INFO 172.17.0.2 address removed from the blacklist
$ oxdpus detach --dev=vethbd33820
INFO XDP program successfully unloaded from vethbd33820 device
```

You can optionally set a blacklist map number. This version of oxdpus is slightly slower than the original but supports up to 46 blacklist maps, each holding up to 65,536 IP addresses for a theoretical total max entries limit of 3,014,656 IP addresses. `oxdpus list` will show an aggregated list but `oxdpus remove` needs the map number if it was set when using `oxdpus add`. In addition, oxdpus will silently drop add requests once the per-map limit of 65,536 is reached (especially common with CIDR ranges) so you'll need to handle that manually.

```bash
$ oxdpus add --ip=172.17.0.2 --map=46
INFO 172.17.0.2 address added to the blacklist
$ oxdpus list
* 172.17.0.2
$ oxdpus remove --ip=172.17.0.2 --map=46
INFO 172.17.0.2 address removed from the blacklist
```

**IMPORTANT:** prior to compiling this version of oxdpus, you'll need to increase your `nofile` limit or you'll get a `too many open files` error when running oxdpus. The limit you set will be dependent on your system resources but here's an example:

```bash
echo "fs.file-max=4194304" >> /etc/sysctl.conf
echo "fs.nr_open=4194304" >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf
ulimit -n 4194304
sed -i "s/# End of file//" /etc/security/limits.conf
printf "\n* - nofile 4194304\nroot - nofile 4194304\n" >> /etc/security/limits.conf
ulimit -Hn
```

## Tutorial

To read more, check out the tutorial I wrote about [Processing Packets at Bare-metal Speed](https://sematext.com/blog/ebpf-and-xdp-for-processing-packets-at-bare-metal-speed/). 
