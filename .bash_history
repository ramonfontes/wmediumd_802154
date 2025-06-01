. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy166 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy166 set netns `cat /tmp/netns.pid.0`
iwpan phy phy167 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy169 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy168 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy168 set netns `cat /tmp/netns.pid.0`
iwpan phy phy169 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy171 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy170 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy170 set netns `cat /tmp/netns.pid.0`
iwpan phy phy171 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy171 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy170 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy170 set netns `cat /tmp/netns.pid.0`
iwpan phy phy171 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy173 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy172 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy172 set netns `cat /tmp/netns.pid.0`
iwpan phy phy173 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy175 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy174 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy174 set netns `cat /tmp/netns.pid.0`
iwpan phy phy175 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy177 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy176 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy176 set netns `cat /tmp/netns.pid.0`
iwpan phy phy177 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy179 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy178 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy178 set netns `cat /tmp/netns.pid.0`
iwpan phy phy179 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy181 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
EXIT
EXI
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy180 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy180 set netns `cat /tmp/netns.pid.0`
iwpan phy phy181 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy183 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy182 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy182 set netns `cat /tmp/netns.pid.0`
iwpan phy phy183 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy185 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy184 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy184 set netns `cat /tmp/netns.pid.0`
iwpan phy phy185 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy187 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy186 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy186 set netns `cat /tmp/netns.pid.0`
iwpan phy phy187 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy229 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy228 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy228 set netns `cat /tmp/netns.pid.0`
iwpan phy phy229 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy243 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy242 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy242 set netns `cat /tmp/netns.pid.0`
iwpan phy phy243 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy249 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy248 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy248 set netns `cat /tmp/netns.pid.0`
iwpan phy phy249 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
echo $$ > /tmp/netns.pid.1
. func
ip link add link wpan1 name pan1 type lowpan
iwpan dev wpan1 set pan_id 0xbeef
ip link set wpan1 up
ip link set pan1 up
ip -6 addr flush pan1
ip -6 addr add fe80::2/64 dev pan1
iwpan phy phy251 interface add mon1 type monitor
ifconfig mon1 up
sleep 10; ping -c 2 fe80::1
exit
lxc-unshare -s NETWORK /bin/bash
exit
echo $$ > /tmp/netns.pid.0
. func
ip link add link wpan0 name pan0 type lowpan
iwpan dev wpan0 set pan_id 0xbeef
ip link set wpan0 up
ip link set pan0 up
ip -6 addr flush pan0
ip -6 addr add fe80::1/64 dev pan0
iwpan phy phy250 interface add mon0 type monitor
ifconfig mon0 up
exit
lxc-unshare -s NETWORK /bin/bash
exit
iwpan phy phy250 set netns `cat /tmp/netns.pid.0`
iwpan phy phy251 set netns `cat /tmp/netns.pid.1`
wpan-hwsim edge add 0 1 >/dev/null 2>&1
wpan-hwsim edge add 1 0 >/dev/null 2>&1
exit
