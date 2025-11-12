# vpc-mini (vpcctl)

Build-your-own Virtual Private Cloud (VPC) on a single Linux host using **only native tools**:
- `ip`, `ip netns`, `bridge`, `iptables`
- No third-party libs. Single-file Python CLI.

## Quickstart

```bash
sudo ./vpcctl.py create-vpc --vpc demo --cidr 10.10.0.0/16
sudo ./vpcctl.py add-subnet --vpc demo --name public  --cidr 10.10.1.0/24
sudo ./vpcctl.py add-subnet --vpc demo --name private --cidr 10.10.2.0/24
sudo ./vpcctl.py deploy-app --vpc demo --subnet public  --port 8080
sudo ./vpcctl.py deploy-app --vpc demo --subnet private --port 8080

OUT_IF=$(ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
sudo ./vpcctl.py enable-nat --cidr 10.10.1.0/24 --internet-interface "$OUT_IF"
```

## Peering Example

```bash
sudo ./vpcctl.py create-vpc --vpc prod --cidr 10.20.0.0/16
sudo ./vpcctl.py add-subnet --vpc prod --name public --cidr 10.20.1.0/24
sudo ./vpcctl.py peer --vpc-a demo --vpc-b prod
sudo ./vpcctl.py route --cidr 10.20.1.0/24 --dev veth-peer-demo
sudo ./vpcctl.py route --cidr 10.10.1.0/24 --dev veth-peer-prod
```

## Security Groups

```bash
sudo ./vpcctl.py apply-policy --vpc demo --subnet public --policy policies/sample-policy.json
```

## Teardown

```bash
sudo ./vpcctl.py teardown --vpc demo
sudo ./vpcctl.py teardown --vpc prod
```

## By
phycrypp olaoluwa
