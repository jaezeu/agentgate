mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

run "static_apply" {
  command = apply

  variables {
    github_repository = "example/agentgate"
  }

  assert {
    condition     = output.deployer_role_arn != ""
    error_message = "The deployer role ARN must be exposed for the deploy workflow."
  }

  assert {
    condition     = output.github_oidc_provider_arn != ""
    error_message = "The GitHub OIDC provider must be created by default."
  }
}

run "existing_oidc_provider" {
  command = apply

  variables {
    github_repository                 = "example/agentgate"
    create_github_oidc_provider       = false
    existing_github_oidc_provider_arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
  }

  assert {
    condition     = output.github_oidc_provider_arn == "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
    error_message = "An existing OIDC provider must be reused, not recreated."
  }
}
