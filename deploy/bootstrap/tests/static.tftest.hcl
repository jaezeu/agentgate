mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
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
    condition     = output.backend_config.bucket == output.state_bucket
    error_message = "The backend config output must reference the state bucket."
  }

  assert {
    condition     = output.backend_config.region == var.aws_region
    error_message = "The backend config output must reference the state bucket region."
  }

  assert {
    condition     = output.state_kms_key_arn != ""
    error_message = "The dedicated state KMS key must be exposed for operators."
  }

  assert {
    condition     = aws_iam_role.deployer.max_session_duration == 3600
    error_message = "Deployer role sessions must stay bounded to one hour."
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 1
    error_message = "The GitHub OIDC provider must be created by default."
  }
}

run "existing_oidc_provider" {
  command = plan

  variables {
    github_repository                 = "example/agentgate"
    create_github_oidc_provider       = false
    existing_github_oidc_provider_arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 0
    error_message = "An existing OIDC provider must not be recreated."
  }
}
