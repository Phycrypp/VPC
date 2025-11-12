#!/usr/bin/env python3
# vpcctl.py — Build-your-own VPC on a single Linux host using native tools.
#
# Requirements:
#   - Run as root (sudo). Needs: ip, iptables, bridge.
#   - No third-party Python packages required.
#
# Model:
#   br-<vpc>  (Linux bridge) is the VPC "switch" + SVI (gateway on bridge)
#   ns-<vpc>-<subnet> (Linux netns) is a subnet with one demo host (.10)
#   veth-*-ns <-> veth-*-br connects the subnet to the VPC bridge
#   NAT (optional) via iptables MASQUERADE on host

import argparse, json, os, signal, subprocess, sys, tempfile
from pathlib import Path
from ipaddress import ip_network, ip_address

LOG_PREFIX = "[vpcctl]"
STATE_DIR  = Path("/var/run/vpcctl")
STATE_DIR.mkdir(parents=True, exist_ok=True)

# ---------- small helpers ----------

def _sx(v):        # short vpc id for names (first char)
    return v[:1]

def _s3(n):        # short subnet tag (first 3)
    return n[:3]

def sh(cmd, check=False, capture=False):
    """Run shell command; print it; return CompletedProcess."""
    print(f"{LOG_PREFIX} $ {cmd}")
    if capture:
        return subprocess.run(cmd, shell=True, check=check,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return subprocess.run(cmd, shell=True, check=check)

def preflight_host_routing():
    """Make host routing sane & idempotent."""
    sh("sysctl -w net.ipv4.ip_forward=1", check=False)
    # allow forwarding at filter table policy level
    sh("iptables -P FORWARD ACCEPT", check=False)
    # avoid bridge netfilter eating L2 frames
    sh("modprobe br_netfilter 2>/dev/null || true", check=False)
    sh("sysctl -w net.bridge.bridge-nf-call-iptables=0", check=False)
    sh("sysctl -w net.bridge.bridge-nf-call-ip6tables=0", check=False)
    sh("sysctl -w net.bridge.bridge-nf-call-arptables=0", check=False)
    # nice for host->ns curls via bridge
    sh("sysctl -w net.ipv4.conf.all.arp_accept=1", check=False)
    sh("sysctl -w net.ipv4.conf.default.arp_accept=1", check=False)

def ns_name(vpc, subnet):
    return f"ns-{vpc}-{subnet}"

def if_names(vpc, subnet):
    ns_if = f"veth-{_sx(vpc)}-{_s3(subnet)}-ns"
    br_if = f"veth-{_sx(vpc)}-{_s3(subnet)}-br"
    return ns_if, br_if

def bridge_name(vpc):
    return f"br-{vpc}"

def http_pidfile(vpc, subnet):
    return f"/tmp/ns-{vpc}-{subnet}-http.pid"

# ---------- core actions ----------

def create_vpc(args):
    preflight_host_routing()
    br = bridge_name(args.vpc)
    if sh(f"ip link show {br}", check=False).returncode != 0:
        sh(f"ip link add name {br} type bridge", check=True)
    sh(f"ip link set dev {br} up", check=False)
    print(f"{LOG_PREFIX} VPC {args.vpc} ready: bridge={br}, cidr={args.cidr}")

def delete_vpc(args):
    # alias that defers to teardown (kept for parity)
    teardown(args)

def add_subnet(args):
    """
    Create subnet namespace, attach to bridge, IP host .10, gateway .1 on BRIDGE.
    """
    preflight_host_routing()
    vpc, name, cidr = args.vpc, args.name, args.cidr
    br  = bridge_name(vpc)
    ns  = ns_name(vpc, name)
    ns_if, br_if = if_names(vpc, name)

    net  = ip_network(cidr, strict=False)
    mask = str(net.prefixlen)
    gw   = str(list(net.hosts())[0])            # first host = .1 SVI
    ns_ip = str(ip_address(net.network_address) + (10 if net.prefixlen <= 24 else 2))

    # ensure bridge exists & up
    if sh(f"ip link show {br}", check=False).returncode != 0:
        sh(f"ip link add name {br} type bridge", check=True)
    sh(f"ip link set dev {br} up", check=False)

    # namespace
    if sh(f"ip netns list | grep -w {ns}", check=False, capture=True).returncode != 0:
        sh(f"ip netns add {ns}", check=True)
    sh(f"ip netns exec {ns} ip link set lo up", check=False)

    # veth pair if absent
    if sh(f"ip link show {ns_if}", check=False).returncode != 0 and \
       sh(f"ip link show {br_if}", check=False).returncode != 0:
        sh(f"ip link add {ns_if} type veth peer name {br_if}", check=True)

    # connect & up
    sh(f"ip link set {ns_if} netns {ns}", check=False)
    sh(f"ip link set {br_if} master {br}", check=False)
    sh(f"bridge link set dev {br_if} hairpin on", check=False)
    sh(f"ip link set dev {br_if} up", check=False)

    # assign IP to ns end
    sh(f"ip netns exec {ns} ip addr flush dev {ns_if}", check=False)
    sh(f"ip netns exec {ns} ip addr add {ns_ip}/{mask} dev {ns_if}", check=True)
    sh(f"ip netns exec {ns} ip link set dev {ns_if} up", check=True)

    # **SVI is on the BRIDGE** (permanent)
    sh(f"ip addr add {gw}/{mask} dev {br} 2>/dev/null || true", check=False)
    sh(f"ip addr replace {gw}/{mask} dev {br}", check=False)

    # default route inside ns via bridge SVI
    sh(f"ip netns exec {ns} ip route replace default via {gw}", check=True)

    print(f"{LOG_PREFIX} subnet {name} created in VPC {vpc}: "
          f"ns={ns}, cidr={cidr}, ns_if={ns_if}, br_if={br_if}, gw={gw}, ns_ip={ns_ip}")

def deploy_app(args):
    """
    Start a Python http.server inside the subnet netns on given port.
    """
    vpc, subnet, port = args.vpc, args.subnet, int(args.port)
    ns = ns_name(vpc, subnet)
    pidfile = http_pidfile(vpc, subnet)
    # background http server (idempotent-ish)
    sh(f"ip netns exec {ns} nohup python3 -m http.server {port} "
       f">/tmp/{ns}-http.log 2>&1 & echo $! > {pidfile}", check=False)
    print(f"{LOG_PREFIX} started http server in {ns} on port {port}")

def stop_app(args):
    vpc, subnet = args.vpc, args.subnet
    pidfile = http_pidfile(vpc, subnet)
    sh(f"kill $(cat {pidfile}) 2>/dev/null || true", check=False)
    print(f"{LOG_PREFIX} stopped app in ns-{vpc}-{subnet} (if running)")

def enable_nat(args):
    """
    Enable internet egress for a CIDR via given outbound interface.
    """
    cidr, out_if = args.cidr, args.internet_interface
    sh("iptables -N VPCNAT 2>/dev/null || true", check=False)
    # Avoid double-NAT noise: insert RETURN for peer CIDRs if you want (user can do separate)
    sh(f"iptables -t nat -C POSTROUTING -s {cidr} -o {out_if} -j MASQUERADE || "
       f"iptables -t nat -A POSTROUTING -s {cidr} -o {out_if} -j MASQUERADE", check=False)
    print(f"{LOG_PREFIX} NAT enabled for {cidr} via {out_if}")

def disable_nat(args):
    cidr, out_if = args.cidr, args.internet_interface
    # Try to delete matching rule; ignore errors
    sh(f"iptables -t nat -D POSTROUTING -s {cidr} -o {out_if} -j MASQUERADE 2>/dev/null || true", check=False)
    print(f"{LOG_PREFIX} NAT disabled for {cidr} via {out_if}")

def apply_policy(args):
    """
    Apply simple security-group policy JSON inside a subnet namespace.
    JSON example:
    {
      "allow_tcp_ports": [80,8080],
      "deny_ssh": true
    }
    """
    ns = ns_name(args.vpc, args.subnet)
    policy_path = args.policy
    with open(policy_path, "r") as f:
        policy = json.load(f)
    chain = f"SG_{ns.replace('-', '_')}"
    sh(f"ip netns exec {ns} iptables -N {chain} 2>/dev/null || true", check=False)
    sh(f"ip netns exec {ns} iptables -F {chain}", check=False)
    sh(f"ip netns exec {ns} iptables -A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", check=False)
    for p in policy.get("allow_tcp_ports", []):
        sh(f"ip netns exec {ns} iptables -A {chain} -p tcp --dport {p} -j ACCEPT", check=False)
    if policy.get("deny_ssh", False):
        sh(f"ip netns exec {ns} iptables -A {chain} -p tcp --dport 22 -j REJECT --reject-with icmp-port-unreachable", check=False)
    sh(f"ip netns exec {ns} iptables -A {chain} -j DROP", check=False)
    if sh(f"ip netns exec {ns} iptables -C INPUT -j {chain}", check=False).returncode != 0:
        sh(f"ip netns exec {ns} iptables -A INPUT -j {chain}", check=False)
    print(f"{LOG_PREFIX} applied policy to {ns}: {policy_path}")

def peer(args):
    """
    Create a veth peering between two VPC bridges with a /30 link.
    """
    a, b = args.vpc_a, args.vpc_b
    br_a, br_b = bridge_name(a), bridge_name(b)
    pa, pb     = f"veth-peer-{a}", f"veth-peer-{b}"

    # allocate a deterministic /30 (simple, fixed; change if you want multiple):
    base = "169.254.2.0/30"
    ip_a, ip_b = "169.254.2.1/30", "169.254.2.2/30"

    # create if missing
    if sh(f"ip link show {pa}", check=False).returncode != 0 and \
       sh(f"ip link show {pb}", check=False).returncode != 0:
        sh(f"ip link add {pa} type veth peer name {pb}", check=True)

    # enslave to bridges (as routed L3 ports)
    sh(f"ip link set {pa} master {br_a}", check=False)
    sh(f"ip link set {pb} master {br_b}", check=False)
    sh(f"ip link set dev {pa} up", check=False)
    sh(f"ip link set dev {pb} up", check=False)

    # give /30 IPs to the peer ends
    sh(f"ip addr add {ip_a} dev {pa} 2>/dev/null || true", check=False)
    sh(f"ip addr add {ip_b} dev {pb} 2>/dev/null || true", check=False)

    print(f"{LOG_PREFIX} peering established between {a} <-> {b} via {pa}<->{pb} ({base})")
    print(f"{LOG_PREFIX} add routes with:\n  vpc {a}: ./vpcctl.py route --cidr <{b}-cidrs> --dev {pa}\n"
          f"  vpc {b}: ./vpcctl.py route --cidr <{a}-cidrs> --dev {pb}")

def route(args):
    """
    Add/replace a route on the host: either via dev or via next-hop.
    """
    if args.dev and args.via:
        print("Specify either --dev or --via, not both.")
        sys.exit(2)
    if args.dev:
        sh(f"ip route replace {args.cidr} dev {args.dev}", check=False)
    elif args.via:
        sh(f"ip route replace {args.cidr} via {args.via} dev {args.dev or ''}".strip(), check=False)
    else:
        print("Need --dev or --via")
        sys.exit(2)

def list_all(args):
    sh("ip -o link show | egrep 'br-|veth-|-peer-' || true", check=False)

def inspect(args):
    vpc = args.vpc
    br  = bridge_name(vpc)
    print("--- bridge addrs ---")
    sh(f"ip -4 addr show {br} | sed -n 's/ *inet /inet /p'", check=False)
    print("--- routes ---")
    sh("ip route | egrep '10\\.10\\.|10\\.20\\.|169\\.254' || true", check=False)
    print("--- namespaces ---")
    for name in ("pub","pri","public","private"):
        ns = ns_name(vpc, name)
        print(f"### {ns}")
        sh(f"ip -n {ns} -4 addr || true", check=False)
        sh(f"ip -n {ns} route || true", check=False)
        sh(f"ip -n {ns} neigh || true", check=False)

def teardown(args):
    """
    Cleanly remove a VPC (apps, veths, namespaces, bridge).
    Safe to run multiple times.
    """
    preflight_host_routing()
    vpc = args.vpc
    br  = bridge_name(vpc)

    # stop any demo apps
    for name in ("pub","pri","public","private"):
        sh(f"kill $(cat {http_pidfile(vpc,name)}) 2>/dev/null || true", check=False)

    # drop veths we create
    for name in ("pub","pri","public","private"):
        _, br_if = if_names(vpc, name)
        sh(f"ip link del {br_if} 2>/dev/null || true", check=False)

    # namespaces
    for name in ("pub","pri","public","private"):
        sh(f"ip netns del {ns_name(vpc,name)} 2>/dev/null || true", check=False)

    # peer links (best-effort)
    sh(f"ip link del veth-peer-{vpc} 2>/dev/null || true", check=False)

    # remove common SVIs from bridge (no-op if absent)
    for oct in ("1.1/24","2.1/24"):  # typical /24 demos .1 gateways
        sh(f"ip addr del 10.10.{oct} dev {br} 2>/dev/null || true", check=False)
        sh(f"ip addr del 10.20.{oct} dev {br} 2>/dev/null || true", check=False)

    # finally drop bridge
    if sh(f"ip link show {br}", check=False).returncode == 0:
        sh(f"ip link set dev {br} down", check=False)
        sh(f"ip link del {br}", check=False)

    print(f"{LOG_PREFIX} VPC {vpc} deleted.")

# ---------- CLI ----------

def main():
    p = argparse.ArgumentParser(description="vpcctl: build-your-own Linux VPC")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("create-vpc", help="Create a VPC bridge")
    s.add_argument("--vpc", required=True)
    s.add_argument("--cidr", required=True)
    s.set_defaults(func=create_vpc)

    s = sub.add_parser("delete-vpc", help="Delete a VPC and all resources")
    s.add_argument("--vpc", required=True)
    s.set_defaults(func=delete_vpc)

    s = sub.add_parser("add-subnet", help="Add a subnet (namespace) to VPC")
    s.add_argument("--vpc", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--cidr", required=True)
    s.set_defaults(func=add_subnet)

    s = sub.add_parser("deploy-app", help="Run a simple HTTP server in a subnet namespace")
    s.add_argument("--vpc", required=True)
    s.add_argument("--subnet", required=True)
    s.add_argument("--port", required=True)
    s.set_defaults(func=deploy_app)

    s = sub.add_parser("stop-app", help="Stop HTTP server in a subnet")
    s.add_argument("--vpc", required=True)
    s.add_argument("--subnet", required=True)
    s.set_defaults(func=stop_app)

    s = sub.add_parser("enable-nat", help="Enable MASQUERADE for a CIDR via outbound interface")
    s.add_argument("--cidr", required=True)
    s.add_argument("--internet-interface", required=True)
    s.set_defaults(func=enable_nat)

    s = sub.add_parser("disable-nat", help="Disable MASQUERADE for a CIDR via outbound interface")
    s.add_argument("--cidr", required=True)
    s.add_argument("--internet-interface", required=True)
    s.set_defaults(func=disable_nat)

    s = sub.add_parser("apply-policy", help="Apply security group policy JSON in subnet namespace")
    s.add_argument("--vpc", required=True)
    s.add_argument("--subnet", required=True)
    s.add_argument("--policy", required=True)
    s.set_defaults(func=apply_policy)

    s = sub.add_parser("peer", help="Create peering link between two VPCs")
    s.add_argument("--vpc-a", required=True)
    s.add_argument("--vpc-b", required=True)
    s.set_defaults(func=peer)

    s = sub.add_parser("route", help="Add host route for CIDR via nexthop or dev")
    s.add_argument("--cidr", required=True)
    s.add_argument("--dev", required=False)
    s.add_argument("--via", required=False)
    s.set_defaults(func=route)

    s = sub.add_parser("list", help="List bridges, netns, and veths")
    s.set_defaults(func=list_all)

    s = sub.add_parser("inspect", help="Inspect a VPC bridge and links")
    s.add_argument("--vpc", required=True)
    s.set_defaults(func=inspect)

    s = sub.add_parser("teardown", help="Stop apps and delete a VPC")
    s.add_argument("--vpc", required=True)
    s.set_defaults(func=teardown)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
