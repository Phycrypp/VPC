#!/usr/bin/env python3
# vpcctl.py — Build-your-own VPC on a single Linux host using native tools.
#
# Requirements:
#   - Run as root (sudo) on Linux with: ip, iptables, bridge
#   - No third-party Python packages required.
#
# Concepts:
#   VPC -> Linux bridge (br-<vpc>), with recorded CIDR metadata for validation
#   Subnet -> Linux network namespace (ns-<vpc>-<subnet>)
#   Link   -> veth pair: veth-<vpc>-<subnet>-ns <-> veth-<vpc>-<subnet>-br
#   Router -> Host network stack does L3 routing across subnets (enable ip_forward). NAT via iptables.
#
# Disclaimer: Educational demo, not production networking.

import argparse
import os
import subprocess
import sys
import json
from pathlib import Path
from ipaddress import ip_network, ip_address

LOG_PREFIX = "[vpcctl]"

STATE_DIR = Path("/var/run/vpcctl")
STATE_DIR.mkdir(parents=True, exist_ok=True)

def meta_path(vpc):
    return STATE_DIR / f"{vpc}.json"

def load_vpc_meta(vpc):
    p = meta_path(vpc)
    if p.exists():
        return json.loads(p.read_text())
    return {}

def save_vpc_meta(vpc, data):
    p = meta_path(vpc)
    p.write_text(json.dumps(data, indent=2))

def sh(cmd, check=True, capture=False):
    print(f"{LOG_PREFIX} $ {cmd}")
    if capture:
        return subprocess.run(cmd, shell=True, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    else:
        return subprocess.run(cmd, shell=True, check=check)

def exists_netns(ns):
    out = sh("ip netns list", check=False, capture=True)
    return any(line.split()[0] == ns for line in out.strip().splitlines())

def exists_link(name):
    out = sh(f"ip link show {name}", check=False, capture=True)
    return ("does not exist" not in out) and ("Cannot find device" not in out)

def exists_bridge(br):
    out = sh(f"ip link show {br}", check=False, capture=True)
    return "does not exist" not in out and "state" in out

def ensure_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            val = f.read().strip()
    except FileNotFoundError:
        val = "0"
    if val != "1":
        print(f"{LOG_PREFIX} enabling net.ipv4.ip_forward")
        sh("sysctl -w net.ipv4.ip_forward=1", check=False)

def dev_up(dev):
    sh(f"ip link set dev {dev} up", check=False)

def dev_down(dev):
    sh(f"ip link set dev {dev} down", check=False)

def add_addr(dev, cidr):
    sh(f"ip addr add {cidr} dev {dev}", check=False)

def del_addr(dev, cidr):
    sh(f"ip addr del {cidr} dev {dev}", check=False)

def add_route_ns(ns, cidr, via=None, dev=None):
    if via:
        sh(f"ip netns exec {ns} ip route replace {cidr} via {via}", check=False)
    elif dev:
        sh(f"ip netns exec {ns} ip route replace {cidr} dev {dev}", check=False)
    else:
        sh(f"ip netns exec {ns} ip route replace {cidr}", check=False)

def add_route_host(cidr, via=None, dev=None):
    if via:
        sh(f"ip route replace {cidr} via {via}", check=False)
    elif dev:
        sh(f"ip route replace {cidr} dev {dev}", check=False)
    else:
        sh(f"ip route replace {cidr}", check=False)

def parse_gateway(cidr):
    net = ip_network(cidr, strict=False)
    gw = ip_address(int(net.network_address) + 1)
    return f"{gw}/{net.prefixlen}", str(gw)

def vpc_bridge_name(vpc):
    return f"br-{vpc}"

def subnet_ns_name(vpc, name):
    return f"ns-{vpc}-{name}"

def subnet_veth_names(vpc, name):
    ns_if = f"veth-{vpc}-{name}-ns"[:15]
    br_if = f"veth-{vpc}-{name}-br"[:15]
    return ns_if, br_if

def ensure_bridge(br):
    if not exists_bridge(br):
        sh(f"ip link add name {br} type bridge", check=True)
    dev_up(br)

def attach_to_bridge(br, dev):
    sh(f"ip link set {dev} master {br}", check=True)

def create_namespace(ns):
    if not exists_netns(ns):
        sh(f"ip netns add {ns}", check=True)

def delete_namespace(ns):
    if exists_netns(ns):
        sh(f"ip netns del {ns}", check=True)

def create_veth_pair(ns_if, br_if):
    if not exists_link(ns_if) and not exists_link(br_if):
        sh(f"ip link add {ns_if} type veth peer name {br_if}", check=True)

def move_to_ns(ns, dev):
    sh(f"ip link set {dev} netns {ns}", check=False)

def ns_dev_up(ns, dev):
    sh(f"ip netns exec {ns} ip link set dev {dev} up", check=False)

def ns_set_addr(ns, dev, cidr):
    sh(f"ip netns exec {ns} ip addr add {cidr} dev {dev}", check=False)

def ns_set_lo_up(ns):
    sh(f"ip netns exec {ns} ip link set lo up", check=False)

def ns_add_default_route(ns, via):
    sh(f"ip netns exec {ns} ip route replace default via {via}", check=False)

def ipt(cmd):
    sh(f"iptables {cmd}", check=False)

def ensure_chain(chain):
    out = sh("iptables -S", check=False, capture=True)
    if f":{chain} " not in out:
        ipt(f"-N {chain}")

def chain_insert_once(table_filter_cmd, grep_pat):
    out = sh("iptables -S -t nat", check=False, capture=True)
    if grep_pat not in out:
        ipt(table_filter_cmd)

def nat_enable(subnet_cidr, outbound_if, mark="VPCNAT"):
    ensure_chain(mark)
    chain_insert_once(f"-t nat -A POSTROUTING -s {subnet_cidr} -o {outbound_if} -j MASQUERADE",
                      f"-A POSTROUTING -s {subnet_cidr} -o {outbound_if} -j MASQUERADE")

def nat_disable(subnet_cidr, outbound_if):
    ipt(f"-t nat -D POSTROUTING -s {subnet_cidr} -o {outbound_if} -j MASQUERADE")

def apply_policy(ns, policy_path):
    """
    Apply a simple 'security group' to a subnet namespace.

    Policy JSON example:
    {
      "subnet": "10.0.1.0/24",
      "ingress": [
        {"port": 80, "protocol": "tcp", "action": "allow"},
        {"port": 22, "protocol": "tcp", "action": "deny"},
        {"protocol": "icmp", "action": "allow"}
      ]
    }
    """
    import json

    # Load and validate policy
    with open(policy_path, "r") as f:
        policy = json.load(f)

    ingress = policy.get("ingress") or []  # tolerate missing/null
    if not isinstance(ingress, list):
        raise ValueError("policy.ingress must be a list")

    chain = f"SG_{ns.replace('-', '_')}"

    # Create/flush the chain inside the namespace
    sh(f"ip netns exec {ns} iptables -N {chain} || true")
    sh(f"ip netns exec {ns} iptables -F {chain} || true")

    # Always allow established/related first
    sh(f"ip netns exec {ns} iptables -A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Apply rules
    for r in ingress:
        if not isinstance(r, dict):
            continue
        proto = (r.get("protocol") or "tcp").lower()
        action = (r.get("action") or "deny").lower()
        port = r.get("port")

        if proto not in ("tcp", "udp", "icmp"):
            continue

        target = "ACCEPT" if action == "allow" else "REJECT"

        if proto in ("tcp", "udp") and port:
            # numeric port only
            try:
                p = int(port)
            except Exception:
                continue
            sh(f"ip netns exec {ns} iptables -A {chain} -p {proto} --dport {p} -j {target}")
        else:
            # protocol without port (e.g., ICMP or blanket rule)
            sh(f"ip netns exec {ns} iptables -A {chain} -p {proto} -j {target}")

    # Default deny at end
    sh(f"ip netns exec {ns} iptables -A {chain} -j DROP")

    # Hook chain into INPUT if not already
    sh(f"ip netns exec {ns} iptables -C INPUT -j {chain} || ip netns exec {ns} iptables -A INPUT -j {chain}")

    print(f"[vpcctl] applied policy to {ns}: {policy_path}")

def create_vpc(args):
    vpc = args.vpc
    br  = vpc_bridge_name(vpc)
    ensure_ip_forwarding()
    ensure_bridge(br)
    vpc_meta = load_vpc_meta(vpc)
    if args.cidr:
        vpc_net = ip_network(args.cidr, strict=False)
        vpc_meta["cidr_block"] = str(vpc_net)
    if "cidr_block" not in vpc_meta and not args.cidr:
        print(f"{LOG_PREFIX} warning: VPC created without CIDR block; pass --cidr to record it")
    save_vpc_meta(vpc, vpc_meta)
    print(f"{LOG_PREFIX} VPC {vpc} ready: bridge={br}, cidr={vpc_meta.get('cidr_block', 'N/A')}")

def delete_vpc(args):
    vpc = args.vpc
    br = vpc_bridge_name(vpc)
    out = sh("ip -o link show", capture=True, check=False)
    for line in out.splitlines():
        if f"veth-{vpc}-" in line:
            name = line.split(":")[1].strip().split("@")[0]
            sh(f"ip link del {name}", check=False)
    ns_list = sh("ip netns list", capture=True, check=False)
    for line in ns_list.splitlines():
        ns = line.split()[0]
        if ns.startswith(f"ns-{vpc}-"):
            pidfile = f"/tmp/{ns}-http.pid"
            if os.path.exists(pidfile):
                try:
                    pid = open(pidfile).read().strip()
                    sh(f"kill {pid}", check=False)
                except Exception:
                    pass
                try:
                    os.remove(pidfile)
                except Exception:
                    pass
            delete_namespace(ns)
    if exists_link(br):
        dev_down(br)
        sh(f"ip link del {br}", check=False)
    print(f"{LOG_PREFIX} VPC {vpc} deleted.")
    try:
        meta_path(vpc).unlink(missing_ok=True)
    except Exception:
        pass

def add_subnet(args):
    vpc = args.vpc
    name = args.name
    cidr = args.cidr
    br = vpc_bridge_name(vpc)

    net = ip_network(cidr, strict=False)
    meta = load_vpc_meta(vpc)
    if "cidr_block" in meta:
        vpc_net = ip_network(meta["cidr_block"], strict=False)
        if not net.subnet_of(vpc_net):
            print(f"{LOG_PREFIX} ERROR: subnet {cidr} must be within VPC CIDR {vpc_net}")
            sys.exit(2)
    gw_cidr, gw_ip = parse_gateway(cidr)

    ns = subnet_ns_name(vpc, name)
    ns_if, br_if = subnet_veth_names(vpc, name)

    create_namespace(ns)
    ns_set_lo_up(ns)

    if not (exists_link(ns_if) or exists_link(br_if)):
        create_veth_pair(ns_if, br_if)

    move_to_ns(ns, ns_if)
    attach_to_bridge(br, br_if)
    ns_set_addr(ns, ns_if, f"{ip_address(int(net.network_address)+10)}/{net.prefixlen}")
    ns_dev_up(ns, ns_if)
    add_addr(br_if, gw_cidr)
    dev_up(br_if)
    ns_add_default_route(ns, gw_ip)

    print(f"{LOG_PREFIX} subnet {name} created in VPC {vpc}: ns={ns}, cidr={cidr}, ns_if={ns_if}, br_if={br_if}, gw={gw_ip}")

def list_all(args):
    print(f"{LOG_PREFIX} Bridges:")
    print(sh("ip -brief link show | awk '/^br-/{print $0}' || true", capture=True, check=False))
    print(f"{LOG_PREFIX} Netns:")
    print(sh("ip netns list", capture=True, check=False))
    print(f"{LOG_PREFIX} Links (veth-*):")
    print(sh("ip -o link show | grep veth- || true", capture=True, check=False))

def deploy_app(args):
    vpc = args.vpc
    subnet = args.subnet
    port = args.port
    ns = subnet_ns_name(vpc, subnet)
    cmd = f"ip netns exec {ns} nohup python3 -m http.server {port} >/tmp/{ns}-http.log 2>&1 & echo $! > /tmp/{ns}-http.pid"
    sh(cmd, check=True)
    print(f"{LOG_PREFIX} started http server in {ns} on port {port}")

def stop_app(args):
    vpc = args.vpc
    subnet = args.subnet
    ns = subnet_ns_name(vpc, subnet)
    pidfile = f"/tmp/{ns}-http.pid"
    if os.path.exists(pidfile):
        pid = open(pidfile).read().strip()
        sh(f"kill {pid}", check=False)
        try:
            os.remove(pidfile)
        except Exception:
            pass
        print(f"{LOG_PREFIX} stopped app in {ns}")
    else:
        print(f"{LOG_PREFIX} no pidfile found for {ns}")

def enable_nat(args):
    nat_enable(args.cidr, args.internet_interface)

def disable_nat(args):
    nat_disable(args.cidr, args.internet_interface)

def apply_sg(args):
    ns = subnet_ns_name(args.vpc, args.subnet)
    apply_policy(ns, args.policy)

def peer(args):
    vpc_a, vpc_b = args.vpc_a, args.vpc_b
    br_a, br_b = vpc_bridge_name(vpc_a), vpc_bridge_name(vpc_b)

    link_a = f"veth-peer-{vpc_a}"[:15]
    link_b = f"veth-peer-{vpc_b}"[:15]

    if not (exists_link(link_a) or exists_link(link_b)):
        create_veth_pair(link_a, link_b)

    attach_to_bridge(br_a, link_a)
    attach_to_bridge(br_b, link_b)
    dev_up(link_a); dev_up(link_b)

    def ll(v):
        h = abs(hash(v)) % 200 + 1
        return f"169.254.{h}.0/30", f"169.254.{h}.1", f"169.254.{h}.2"
    cidr, a_ip, b_ip = ll(vpc_a + vpc_b)
    add_addr(link_a, f"{a_ip}/{cidr.split('/')[-1]}")
    add_addr(link_b, f"{b_ip}/{cidr.split('/')[-1]}")

    print(f"{LOG_PREFIX} peering established between {vpc_a} <-> {vpc_b} via {link_a}<->{link_b} ({cidr})")
    print(f"{LOG_PREFIX} add routes with:")
    print(f"  vpc {vpc_a}: ./vpcctl.py route --cidr <prod-cidrs> --dev {link_a}")
    print(f"  vpc {vpc_b}: ./vpcctl.py route --cidr <demo-cidrs> --dev {link_b}")

def add_route(args):
    if args.via:
        add_route_host(args.cidr, via=args.via)
    else:
        add_route_host(args.cidr, dev=args.dev)

def inspect(args):
    vpc = args.vpc
    br = vpc_bridge_name(vpc)
    meta = load_vpc_meta(vpc)
    if meta:
        print(f"{LOG_PREFIX} VPC {vpc} meta: {meta}")
    print(sh(f"ip addr show dev {br}", capture=True, check=False))
    out = sh("ip -o link show | grep veth- || true", capture=True, check=False)
    print(out)

def teardown(args):
    delete_vpc(args)

def main():
    if os.geteuid() != 0:
        print(f"{LOG_PREFIX} please run as root (sudo).")
        sys.exit(1)

    p = argparse.ArgumentParser(description="vpcctl: build-your-own Linux VPC")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("create-vpc", help="Create a VPC bridge")
    sp.add_argument("--vpc", required=True, help="VPC name (letters/numbers/-)")
    sp.add_argument("--cidr", help="VPC CIDR block (e.g., 10.10.0.0/16)")
    sp.set_defaults(func=create_vpc)

    sp = sub.add_parser("delete-vpc", help="Delete a VPC and all resources")
    sp.add_argument("--vpc", required=True)
    sp.set_defaults(func=delete_vpc)

    sp = sub.add_parser("add-subnet", help="Add a subnet (namespace) to VPC")
    sp.add_argument("--vpc", required=True)
    sp.add_argument("--name", required=True, help="Subnet name, e.g., public, private")
    sp.add_argument("--cidr", required=True, help="CIDR like 10.0.1.0/24 (must fit inside VPC CIDR if defined)")
    sp.set_defaults(func=add_subnet)

    sp = sub.add_parser("deploy-app", help="Run a simple HTTP server in a subnet namespace")
    sp.add_argument("--vpc", required=True)
    sp.add_argument("--subnet", required=True)
    sp.add_argument("--port", type=int, default=8080)
    sp.set_defaults(func=deploy_app)

    sp = sub.add_parser("stop-app", help="Stop HTTP server in a subnet")
    sp.add_argument("--vpc", required=True)
    sp.add_argument("--subnet", required=True)
    sp.set_defaults(func=stop_app)

    sp = sub.add_parser("enable-nat", help="Enable MASQUERADE for a CIDR via outbound interface")
    sp.add_argument("--cidr", required=True)
    sp.add_argument("--internet-interface", required=True)
    sp.set_defaults(func=enable_nat)

    sp = sub.add_parser("disable-nat", help="Disable MASQUERADE for a CIDR via outbound interface")
    sp.add_argument("--cidr", required=True)
    sp.add_argument("--internet-interface", required=True)
    sp.set_defaults(func=disable_nat)

    sp = sub.add_parser("apply-policy", help="Apply security group policy JSON in subnet namespace")
    sp.add_argument("--vpc", required=True)
    sp.add_argument("--subnet", required=True)
    sp.add_argument("--policy", required=True)
    sp.set_defaults(func=apply_sg)

    sp = sub.add_parser("peer", help="Create peering link between two VPCs")
    sp.add_argument("--vpc-a", required=True)
    sp.add_argument("--vpc-b", required=True)
    sp.set_defaults(func=peer)

    sp = sub.add_parser("route", help="Add host route for CIDR via nexthop or dev")
    sp.add_argument("--cidr", required=True)
    sp.add_argument("--via", help="next-hop IP")
    sp.add_argument("--dev", help="device name")
    sp.set_defaults(func=add_route)

    sp = sub.add_parser("list", help="List bridges, netns, and veths")
    sp.set_defaults(func=list_all)

    sp = sub.add_parser("inspect", help="Inspect a VPC bridge and links")
    sp.add_argument("--vpc", required=True)
    sp.set_defaults(func=inspect)

    sp = sub.add_parser("teardown", help="Stop apps and delete a VPC")
    sp.add_argument("--vpc", required=True)
    sp.set_defaults(func=teardown)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

