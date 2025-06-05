# Introduction

This is a wireless medium simulation tool for Linux, based on the netlink API
implemented in the `mac80211_hwsim` kernel driver.  Unlike the default in-kernel
forwarding mode of `mac80211_hwsim`, wmediumd allows simulating frame loss and
delay.

This version is forked from an earlier version, hosted here:

    https://github.com/cozybit/wmediumd

# Prerequisites

First, you need a recent Linux kernel with the `mac80211_hwsim` module
available.  If you do not have this module, you may be able to build it using
the [backports project](https://backports.wiki.kernel.org/index.php/Main_Page).

Wmediumd requires libnl3.0.

# Building
```
cd wmediumd && make
```

# Using Wmediumd

Starting wmediumd with an appropriate config file is enough to make frames
pass through wmediumd:
```
sudo modprobe mac802154_hwsim radios=2
sudo ./wmediumd/wmediumd -c tests/2node.cfg &
# run some hwsim test
```
However, please see the next section on some potential pitfalls.

A complete example using network namespaces is given at the end of
this document.

# Configuration

Wmediumd supports multiple ways of configuring the wireless medium.

## Perfect medium

With this configuration, all traffic flows between the configured interfaces, identified by their mac address:

```
ifaces :
{
	ids = [
		"02:00:00:00:00:00:00:00",
		"02:00:00:00:00:00:00:01",
		"02:00:00:00:00:00:00:02",
		"02:00:00:00:00:00:00:03"
	];
};
```

## Path loss model

The path loss model derives signal-to-noise and probabilities from the
coordinates of each node.  This is an example configuration file for it.

```
ifaces : {...};
model :
{
	type = "path_loss";
	positions = (
		(-50.0,   0.0),
		(  0.0,  40.0),
		(  0.0, -70.0),
		( 50.0,   0.0)
	);
	tx_powers = (15.0, 15.0, 15.0, 15.0);

	model_name = "log_distance";
	path_loss_exp = 3.5;
	xg = 0.0;
};
```

## Per-link loss probability model (TBD)

You can simulate a slightly more realistic channel by assigning fixed error
probabilities to each link.

```
ifaces : {...};

model:
{
	type = "prob";

	default_prob = 1.0;
	links = (
		(0, 2, 0.000000),
		(2, 3, 0.000000)
	);
};
```

The above configuration would assign 0% loss probability (perfect medium) to
all frames flowing between nodes 0 and 2, and 100% loss probability to all
other links.  Unless both directions of a link are configured, the loss
probability will be symmetric.

This is a very simplistic model that does not take into account that losses
depend on transmission rates and signal-to-noise ratio.  For that, keep reading.

## Per-link signal-to-noise ratio (SNR) model

You can model different signal-to-noise ratios for each link by including a
list of link tuples in the form of (sensor1, sensor2, snr).

```
ifaces : {...};

model:
{
	type = "snr"
	links = (
		(0, 1, 10),
		(0, 2, 0)
	);
	fading_coefficient = 1;
};
```
The snr will affect the maximum data rates that are successfully transmitted
over the link.

If only one direction of a link is configured, then the link will be
symmetric.  For asymmetric links, configure both directions, as in the
above example where the path between 0 and 2 is usable in only one
direction.

The packet loss error probabilities are derived from this snr.  See function
`get_error_prob_from_snr()`.  Or you can provide a packet-error-rate table like
the one in `tests/signal_table_ieee80211ax`
