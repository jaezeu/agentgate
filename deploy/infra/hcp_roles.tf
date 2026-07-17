data "aws_iam_policy_document" "hcp_workspace_assume" {
  for_each = local.hcp_workspace_subjects

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = [var.hcp_aws_oidc_provider_arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = [var.hcp_aws_workload_identity_audience]
      variable = "app.terraform.io:aud"
    }

    condition {
      test     = "StringLike"
      values   = [each.value]
      variable = "app.terraform.io:sub"
    }
  }
}

resource "aws_iam_role" "hcp_workspace" {
  for_each = local.hcp_workspace_subjects

  name                 = "${var.name_prefix}-tfc-${each.key}"
  assume_role_policy   = data.aws_iam_policy_document.hcp_workspace_assume[each.key].json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "hcp_eks_access" {
  statement {
    actions   = ["eks:DescribeCluster"]
    effect    = "Allow"
    resources = [aws_eks_cluster.sandbox.arn]
  }
}

resource "aws_iam_role_policy" "hcp_eks_access" {
  for_each = aws_iam_role.hcp_workspace

  name   = "eks-cluster-authentication"
  policy = data.aws_iam_policy_document.hcp_eks_access.json
  role   = each.value.id
}

resource "aws_eks_access_entry" "hcp_workspace" {
  for_each = aws_iam_role.hcp_workspace

  cluster_name  = aws_eks_cluster.sandbox.name
  principal_arn = each.value.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "hcp_workspace" {
  for_each = aws_iam_role.hcp_workspace

  cluster_name  = aws_eks_cluster.sandbox.name
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = each.value.arn

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.hcp_workspace]
}

resource "aws_eks_access_entry" "operator" {
  for_each = var.operator_access_principal_arns

  cluster_name  = aws_eks_cluster.sandbox.name
  principal_arn = each.value
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "operator" {
  for_each = var.operator_access_principal_arns

  cluster_name  = aws_eks_cluster.sandbox.name
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = each.value

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.operator]
}
