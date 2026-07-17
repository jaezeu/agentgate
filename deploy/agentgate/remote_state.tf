data "terraform_remote_state" "infra" {
  backend = "remote"

  config = {
    hostname     = "app.terraform.io"
    organization = var.hcp_terraform_organization
    workspaces = {
      name = var.infra_workspace_name
    }
  }
}

data "terraform_remote_state" "platform" {
  backend = "remote"

  config = {
    hostname     = "app.terraform.io"
    organization = var.hcp_terraform_organization
    workspaces = {
      name = var.platform_workspace_name
    }
  }
}
