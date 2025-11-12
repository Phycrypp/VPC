SHELL := /bin/bash

.PHONY: help
help:
	@echo "Targets:"
	@echo "  sudo make demo     # create demo VPC and run apps"
	@echo "  sudo make clean    # teardown demo/prod"

.PHONY: demo
demo:
	./vpcctl.py create-vpc --vpc demo --cidr 10.10.0.0/16
	./vpcctl.py add-subnet --vpc demo --name public  --cidr 10.10.1.0/24
	./vpcctl.py add-subnet --vpc demo --name private --cidr 10.10.2.0/24
	./vpcctl.py deploy-app --vpc demo --subnet public  --port 8080
	./vpcctl.py deploy-app --vpc demo --subnet private --port 8080
	@OUT_IF=$$(ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++)if($$i=="dev"){print $$(i+1);exit}}'); \
	echo "Using outbound $$OUT_IF"; \
	./vpcctl.py enable-nat --cidr 10.10.1.0/24 --internet-interface $$OUT_IF

.PHONY: clean
clean:
	-./vpcctl.py teardown --vpc demo || true
	-./vpcctl.py teardown --vpc prod || true
	@OUT_IF=$$(ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++)if($$i=="dev"){print $$(i+1);exit}}'); \
	./vpcctl.py disable-nat --cidr 10.10.1.0/24 --internet-interface $$OUT_IF || true
