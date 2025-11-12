#!/usr/bin/env bash
set -euxo pipefail
ts() { date +"[%F %T]"; }

echo "$(ts) create VPC demo"
sudo ./vpcctl.py create-vpc --vpc demo --cidr 10.10.0.0/16

echo "$(ts) add subnets"
sudo ./vpcctl.py add-subnet --vpc demo --name public  --cidr 10.10.1.0/24
sudo ./vpcctl.py add-subnet --vpc demo --name private --cidr 10.10.2.0/24

echo "$(ts) deploy apps"
sudo ./vpcctl.py deploy-app --vpc demo --subnet public  --port 8080
sudo ./vpcctl.py deploy-app --vpc demo --subnet private --port 8080

echo "$(ts) enable NAT for public"
OUT_IF=$(ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
sudo ./vpcctl.py enable-nat --cidr 10.10.1.0/24 --internet-interface "$OUT_IF"

echo "$(ts) test connectivity"
sudo ip netns exec ns-demo-public curl -I https://example.com || true
sudo ip netns exec ns-demo-private curl -I https://example.com || true

echo "$(ts) apply policy to public"
sudo ./vpcctl.py apply-policy --vpc demo --subnet public --policy policies/sample-policy.json

echo "$(ts) list"
sudo ./vpcctl.py list

echo "$(ts) done"
