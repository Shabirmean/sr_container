ip link add $1-int type veth peer name $1-ext
brctl addif br-em1 $1-ext
ip link set netns $1 dev $1-int
ip link set $1-ext up
ip netns exec $1 ip addr add 172.17.0."$2"/21 dev $1-int
ip netns exec $1 ip link set $1-int up
ip netns exec $1 ip route del default
ip netns exec $1 ip route add default via 172.17.0.2 dev $1-int
