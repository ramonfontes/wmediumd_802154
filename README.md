# Introduction

This is the first attempt at implementing a wmediumd-like mechanism for `mac802154_hwsim`. The implementation will be developed while considering `tests/interference.sh` for testing.

Patches submitted to the Linux Kernel:
* [https://patchwork.kernel.org/project/linux-wpan/patch/20250603190506.6382-1-ramonreisfontes@gmail.com/](https://patchwork.kernel.org/project/linux-wpan/patch/20250603190506.6382-1-ramonreisfontes@gmail.com/)

## Wmediumd

This is a wireless medium simulation tool for Linux, based on the netlink API
implemented in the `mac802154_hwsim` kernel driver.  Unlike the default in-kernel
forwarding mode of `mac802154_hwsim`, wmediumd allows simulating frame loss and
delay.

This version is forked from an earlier version, hosted here:

    https://github.com/ramonfontes/wmediumd

# Prerequisites

First, you need a recent Linux kernel with the `mac802154_hwsim` module
available.

# Building

Build the required modules and binaries:
```
$ cd wmediumd_802154
$ make
$ sudo make install
```

# Loading the modified kernel module

If you're testing directly with a modified kernel module, you can load it manually:
``` 
$ cd hwsim
$ make
$ sudo modprobe mac802154_hwsim 
$ sudo rmmod mac802154_hwsim 
$ sudo insmod mac802154_hwsim.ko radios=3
```

# Using Wmediumd

Navigate to the test directory:
```
cd tests
```

## Terminal 1: Start the interference scenario

This script sets up the simulated interfaces and initializes the test environment:
```
sudo ./interference.sh
```

## Terminal 2: Launch wmediumd with the desired config

Start the wmediumd_802154 daemon using socket mode and your chosen config file:
```
sudo wmediumd_802154 -s -c tree_interference.cfg
```

This command launches wmediumd_802154, which connects to the mac802154_hwsim module via netlink and simulates interference and packet loss between IEEE 802.15.4 virtual devices according to the configuration in tree.cfg.

## Terminal 1: Pinging virtual devices

You can now test connectivity between the virtual sensors using IPv6 link-local addresses:

Ping from sensor0 to sensor1:

```
ping -c 2 fe80::2
PING fe80::2 (fe80::2) 56 data bytes
64 bytes from fe80::2%pan0: icmp_seq=1 ttl=64 time=2.33 ms
64 bytes from fe80::2%pan0: icmp_seq=2 ttl=64 time=1.77 ms

--- fe80::2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 1.770/2.051/2.332/0.281 ms

```

Ping from sensor1 to sensor2:
```
ping -c 2 fe80::3
PING fe80::3 (fe80::3) 56 data bytes
^C
--- fe80::3 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1054ms
```

# Running wmediumd_802154 with Mininet-WiFi

[This script](https://github.com/intrig-unicamp/mininet-wifi/blob/master/examples/wmediumd_interference_lowpan.py) allows you to run wmediumd_802154 with a custom 802.15.4 network topology.