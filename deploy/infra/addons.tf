locals {
  eks_oidc_provider_host = replace(aws_iam_openid_connect_provider.eks.url, "https://", "")
}

data "aws_iam_policy_document" "vpc_cni_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["sts.amazonaws.com"]
      variable = "${local.eks_oidc_provider_host}:aud"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:kube-system:aws-node"]
      variable = "${local.eks_oidc_provider_host}:sub"
    }
  }
}

resource "aws_iam_role" "vpc_cni" {
  name               = "${var.name_prefix}-vpc-cni"
  assume_role_policy = data.aws_iam_policy_document.vpc_cni_assume.json
}

resource "aws_iam_role_policy_attachment" "vpc_cni" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.vpc_cni.name
}

resource "aws_eks_addon" "vpc_cni" {
  addon_name    = "vpc-cni"
  addon_version = "v1.22.3-eksbuild.1"
  cluster_name  = aws_eks_cluster.sandbox.name
  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
  })
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  service_account_role_arn    = aws_iam_role.vpc_cni.arn

  depends_on = [aws_iam_role_policy_attachment.vpc_cni]
}

data "aws_iam_policy_document" "ebs_csi_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["sts.amazonaws.com"]
      variable = "${local.eks_oidc_provider_host}:aud"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
      variable = "${local.eks_oidc_provider_host}:sub"
    }
  }
}

resource "aws_iam_role" "ebs_csi" {
  name               = "${var.name_prefix}-ebs-csi"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_assume.json
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicyV2"
  role       = aws_iam_role.ebs_csi.name
}

resource "aws_eks_addon" "ebs_csi" {
  addon_name = "aws-ebs-csi-driver"
  # TODO(verify): confirm v1.62.0-eksbuild.1 is offered for EKS 1.36 in the operator's region; AWS does not publish a static compatibility table for this add-on.
  addon_version               = "v1.62.0-eksbuild.1"
  cluster_name                = aws_eks_cluster.sandbox.name
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  service_account_role_arn    = aws_iam_role.ebs_csi.arn

  depends_on = [
    aws_eks_node_group.sandbox,
    aws_iam_role_policy_attachment.ebs_csi,
  ]
}

resource "aws_eks_addon" "coredns" {
  addon_name                  = "coredns"
  addon_version               = "v1.14.3-eksbuild.3"
  cluster_name                = aws_eks_cluster.sandbox.name
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"

  depends_on = [aws_eks_node_group.sandbox]
}

resource "aws_eks_addon" "kube_proxy" {
  addon_name                  = "kube-proxy"
  addon_version               = "v1.36.0-eksbuild.9"
  cluster_name                = aws_eks_cluster.sandbox.name
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"

  depends_on = [aws_eks_node_group.sandbox]
}
