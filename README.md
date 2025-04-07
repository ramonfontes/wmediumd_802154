# Introduction

This is the first attempt at implementing a wmediumd-like mechanism for `mac802154_hwsim`. The implementation will be developed while considering `tests/interference.sh` for testing.

Patches submitted to the Linux Kernel:
* [https://patchwork.kernel.org/project/linux-wpan/patch/20250325165312.26938-1-ramonreisfontes@gmail.com/](https://patchwork.kernel.org/project/linux-wpan/list/?series=&submitter=176431&state=*&q=&archive=&delegate=)

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
$ cd wmediumd802154
$ make
$ sudo make install
```

# Loading the modified kernel module

If you're testing directly with a modified kernel module, you can load it manually:
``` 
$ cd hwsim
$ sudo modprobe mac802154_hwsim 
$ sudo insmod mac802154_hwsim.ko
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
sudo wmediumd_802154 -s -c diamond.cfg
```


This command launches wmediumd_802154, which connects to the mac802154_hwsim module via netlink and simulates interference and packet loss between IEEE 802.15.4 virtual devices according to the configuration in diamond.cfg.