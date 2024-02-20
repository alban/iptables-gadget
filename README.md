# iptables-gadget

iptables-gadget is a [gadget from Inspektor
Gadget](https://inspektor-gadget.io/). It uses iptables TRACE rules to be able
to follow a packet ￼as it goes through different iptables rules.

## How to use

Deploy a workload on minikube:
```bash
$ minikube start --cni=calico
$ kubectl apply -f examples/kubernetes.yaml
```

Install iptables TRACE rules:
```bash
$ minikube ssh
$ for link in $(sudo ip link|grep cali|awk '{print $2}'|cut -d@ -f1) ; do sudo iptables --append PREROUTING --table raw -i $link -p tcp --syn -m comment --comment iptables-gadget -j TRACE ; done
```

Run the iptables gadget:
```bash
$ export IG_EXPERIMENTAL=true
$ sudo -E ig run ghcr.io/alban/iptables-gadget:latest
```

Send some network traffic:
```bash
$ kubectl exec -ti -n gadget-demo hello -- wget http://wikipedia.org
```

Observe events:
```
RUNTIME.CONTAINERNAME PID    COMM IFNAME_IN       IFNAME_OUT TABLENAME CHAINNAME        COMMENT NETNS_IN   NETNS_OUT RULENUM IFINDEX_IN IFINDEX_OUT
                      836202 wget calia563e32a701            raw       PREROUTING       policy  4026532920 0         6       9          0
                      836202 wget calia563e32a701            mangle    PREROUTING       rule    4026532920 0         1       9          0
                      836202 wget calia563e32a701            mangle    cali-PREROUTING  rule    4026532920 0         3       9          0
                      836202 wget calia563e32a701            mangle    cali-from-host-… return  4026532920 0         1       9          0
                      836202 wget calia563e32a701            mangle    cali-PREROUTING  return  4026532920 0         5       9          0
                      836202 wget calia563e32a701            mangle    PREROUTING       policy  4026532920 0         2       9          0
                      836202 wget calia563e32a701            nat       PREROUTING       rule    4026532920 0         1       9          0
                      836202 wget calia563e32a701            nat       cali-PREROUTING  rule    4026532920 0         1       9          0
                      836202 wget calia563e32a701            nat       cali-fip-dnat    return  4026532920 0         1       9          0
                      836202 wget calia563e32a701            nat       cali-PREROUTING  return  4026532920 0         2       9          0
                      836202 wget calia563e32a701            nat       PREROUTING       rule    4026532920 0         2       9          0
                      836202 wget calia563e32a701            nat       KUBE-SERVICES    return  4026532920 0         6       9          0
                      836202 wget calia563e32a701            nat       PREROUTING       policy  4026532920 0         5       9          0

```
## Requirements

- ig v0.25.0
- Linux (unknown version)

## Limitations

* Inspektor Gadget cannot install iptables TRACE rules, so it is done with a
  wrapper script.
* Inspektor Gadget cannot list iptables rules, so the output is parsed with a
  wrapper script.

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
