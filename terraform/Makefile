PHASE ?= phase1-foundation
ORG ?= org-sbx

.PHONY: init plan apply destroy bootstrap package fmt validate

init:
	cd $(PHASE) && terraform init -reconfigure \
	  -backend-config=../environments/$(ORG)/backend.hcl \
	  -backend-config="key=$(PHASE)/terraform.tfstate"

plan: init
	cd $(PHASE) && terraform plan -input=false \
	  -var-file=../environments/$(ORG)/terraform.tfvars

apply: init
	cd $(PHASE) && terraform apply -input=false \
	  -var-file=../environments/$(ORG)/terraform.tfvars

destroy: init
	cd $(PHASE) && terraform destroy -input=false \
	  -var-file=../environments/$(ORG)/terraform.tfvars

bootstrap:
	cd phase0-bootstrap && terraform init && \
	terraform apply -input=false \
	  -var="org_name=$(ORG)" -var="aws_region=us-gov-west-1"

package:
	../scripts/build-lambda.sh $(PHASE)

fmt:
	terraform fmt -recursive

validate:
	@for phase in phase0-bootstrap phase1-foundation phase2-query-layer phase5-notification-test phase6-automation; do \
	  echo "Validating $$phase..."; \
	  (cd $$phase && terraform validate); \
	done
