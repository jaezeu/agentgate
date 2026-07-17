resource "aws_s3_bucket" "demo" {
  bucket        = local.demo_bucket_name
  force_destroy = true

  tags = {
    Name                 = local.demo_bucket_name
    AgentGateGoverned    = "true"
    AgentGateResourceSet = "demo"
  }
}

resource "aws_s3_bucket_ownership_controls" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "demo" {
  bucket = aws_s3_bucket.demo.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {
      prefix = local.demo_s3_prefix
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "vault_broker_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["sts.amazonaws.com"]
      variable = "${local.eks_oidc_provider_host}:aud"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:vault:vault"]
      variable = "${local.eks_oidc_provider_host}:sub"
    }
  }
}

resource "aws_iam_role" "vault_broker" {
  name                 = "${var.name_prefix}-vault-broker"
  assume_role_policy   = data.aws_iam_policy_document.vault_broker_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "target_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      identifiers = [aws_iam_role.vault_broker.arn]
      type        = "AWS"
    }
  }
}

resource "aws_iam_role" "demo_target" {
  name                 = "${var.name_prefix}-terraform-target"
  assume_role_policy   = data.aws_iam_policy_document.target_assume.json
  max_session_duration = 3600

  tags = {
    AgentGateGoverned    = "true"
    AgentGateResourceSet = "demo"
  }
}

data "aws_iam_policy_document" "vault_broker" {
  statement {
    actions   = ["sts:AssumeRole"]
    effect    = "Allow"
    resources = [aws_iam_role.demo_target.arn]
  }
}

resource "aws_iam_role_policy" "vault_broker" {
  name   = "assume-agentgate-demo-target"
  policy = data.aws_iam_policy_document.vault_broker.json
  role   = aws_iam_role.vault_broker.id
}

data "aws_iam_policy_document" "demo_target" {
  statement {
    sid       = "ListGovernedPrefix"
    actions   = ["s3:ListBucket"]
    effect    = "Allow"
    resources = [aws_s3_bucket.demo.arn]

    condition {
      test = "StringLike"
      values = [
        trimsuffix(local.demo_s3_prefix, "/"),
        "${local.demo_s3_prefix}*",
      ]
      variable = "s3:prefix"
    }
  }

  statement {
    sid = "ReadBucketMetadata"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
    ]
    effect    = "Allow"
    resources = [aws_s3_bucket.demo.arn]
  }

  statement {
    sid = "ManageGovernedObjects"
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
    effect    = "Allow"
    resources = ["${aws_s3_bucket.demo.arn}/${local.demo_s3_prefix}*"]
  }

  # EC2 Describe APIs do not support resource-level permissions.
  statement {
    sid = "ReadEC2PlanMetadata"
    actions = [
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVpcs",
    ]
    effect    = "Allow"
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "demo_target" {
  name   = "agentgate-governed-demo"
  policy = data.aws_iam_policy_document.demo_target.json
  role   = aws_iam_role.demo_target.id
}
