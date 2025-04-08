region ?= us-west-2
tf_var_commandline_arguments=-var-file=${region}.tfvars
validate:
	@terraform validate

plan:
	@terraform plan ${tf_var_commandline_arguments}

apply:
	@terraform apply ${tf_var_commandline_arguments}

destroy:
		@terraform destroy ${tf_var_commandline_arguments}
