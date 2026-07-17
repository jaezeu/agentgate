data "terraform_remote_state" "infra" {
  backend = "s3"

  config = {
    bucket = var.state_bucket
    key    = "infra.tfstate"
    region = var.state_bucket_region
  }
}

data "terraform_remote_state" "platform" {
  backend = "s3"

  config = {
    bucket = var.state_bucket
    key    = "platform.tfstate"
    region = var.state_bucket_region
  }
}
