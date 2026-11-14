package main

import rego.v1

# Any job that applies Terraform must run in a protected environment, and the
# workflow must never be triggered by a pull request.

applies(job) if {
	some step in job.steps
	contains(step.run, "terraform apply")
}

deny contains msg if {
	some name, job in input.jobs
	applies(job)
	not job.environment
	msg := sprintf("job %s applies Terraform without an environment", [name])
}

# YAML 1.1 parsers read the key "on" as the boolean true.
triggers contains input["true"]

triggers contains input.on

deny contains msg if {
	some name, job in input.jobs
	applies(job)
	triggers[_].pull_request
	msg := sprintf("job %s applies Terraform on a pull_request trigger", [name])
}
