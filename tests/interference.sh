#!/bin/bash
# 3 mesh nodes in a linear topology
# 4 additional mesh nodes exists to prevent transmission
# When enable_interference=true, ping always fails.
# (This test is not perfect because of random values)

num_nodes=2
session=wmediumd_802154
subnet=10.10.10
macfmt='02:00:00:00:00:00:00:%02x'

. func

if [[ $UID -ne 0 ]]; then
	echo "Sorry, run me as root."
	exit 1
fi

# we are now using a custom module
#modprobe -r mac802154_hwsim
#modprobe mac802154_hwsim

for i in $(seq 0 $((num_nodes-1))); do
    addrs[$i]=$(printf "$macfmt" "$i")
done

cat <<__EOM > diamond.cfg
ifaces :
{
	ids = [
		"02:00:00:00:00:00:00:00",
		"02:00:00:00:00:00:00:01"
	];
	enable_interference = true;
};

path_loss :
{
	positions = (
		(-70.0,   0.0),
		(  0.0,   0.0)
	);
	tx_powers = (15.0, 15.0);
	model_params = ("log_distance", 3.5, 0.0);
};
__EOM

tmux new -s $session -d

rm /tmp/netns.pid.* 2>/dev/null
i=0
for addr in ${addrs[@]}; do
	phy=`addr2phy $addr`
	dev=`ls /sys/class/ieee802154/$phy/net`
	phys[$i]=$phy
	devs[$i]=$dev

	ip=${subnet}.$((10 + i))

	# put this phy in own netns and tmux window, and start a mesh node
	win=$session:$((i+1)).0
	tmux new-window -t $session -n $ip

	# start netns
	pidfile=/tmp/netns.pid.$i
	tmux send-keys -t $win 'lxc-unshare -s NETWORK /bin/bash' C-m
	tmux send-keys -t $win 'echo $$ > '$pidfile C-m

	# wait for netns to exist
	while [[ ! -e $pidfile ]]; do
		echo "Waiting for netns $i -- $pidfile"
		sleep 0.5
	done

	tmux send-keys -t $session:0.0 'iwpan phy '$phy' set netns `cat '$pidfile'`' C-m

	# wait for phy to exist in netns
	while [[ -e /sys/class/ieee80211/$phy ]]; do
		echo "Waiting for $phy to move to netns..."
		sleep 0.5
	done

	# start wpan
	tmux send-keys -t $win '. func' C-m
	tmux send-keys -t $win 'ip link add link wpan'$i' name pan'$i' type lowpan' C-m
	tmux send-keys -t $win 'iwpan dev wpan'$i' set pan_id 0xbeef' C-m
	tmux send-keys -t $win 'ip link set wpan'$i' up' C-m
 	tmux send-keys -t $win 'ip link set pan'$i' up' C-m
	tmux send-keys -t $win 'ip -6 addr flush pan'$i'' C-m
 	tmux send-keys -t $win 'ip -6 addr add fe80::'$((i+1))'/64 dev pan'$i'' C-m

	tmux send-keys -t $win 'iwpan phy '$phy' interface add mon'$i' type monitor' C-m
	tmux send-keys -t $win 'ifconfig mon'$i' up' C-m
	

	i=$((i+1))
done

winct=$i

tmux send-keys -t $session:0.0 'wpan-hwsim edge add 0 1 >/dev/null 2>&1' C-m
tmux send-keys -t $session:0.0 'wpan-hwsim edge add 1 0 >/dev/null 2>&1' C-m

tmux select-window -t $session:1
#tmux send-keys -t $session:1 'sleep 2; ping -c 2 fe80::2' C-m
#tmux send-keys -t $session:1 'wireshark -i pan0 &' C-m
#tmux send-keys -t $session:2 'wireshark -i pan1 &' C-m

tmux select-window -t $session:2
tmux send-keys -t $session:2 'sleep 10; ping -c 2 fe80::1' C-m

# start wmediumd
win=$session:$((winct+1)).0
winct=$((winct+1))
#tmux new-window -a -t $session -n wmediumd_802154
#tmux send-keys -t $win '../wmediumd/wmediumd_802154 -s -c diamond.cfg' C-m

#tmux select-window -t $session:1
#tmux send-keys -t $session:1 'sleep 2; ping -c 5 fe80::1' C-m

tmux attach
