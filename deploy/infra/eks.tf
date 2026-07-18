locals {
  eks_admin_policy_arn = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  # The deployer role needs cluster-admin so the platform and agentgate
  # roots can manage in-cluster resources.
  cluster_admin_access_entries = merge(
    {
      deployer = {
        principal_arn = var.deployer_role_arn
      }
    },
    {
      for arn in var.operator_access_principal_arns :
      "operator-${substr(sha1(arn), 0, 8)}" => {
        principal_arn = arn
      }
    },
  )
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.24"

  name               = local.cluster_name
  kubernetes_version = var.kubernetes_version

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = concat(module.vpc.private_subnets, module.vpc.public_subnets)

  endpoint_private_access      = true
  endpoint_public_access       = true
  endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs

  authentication_mode                      = "API"
  enable_cluster_creator_admin_permissions = false

  access_entries = {
    for key, entry in local.cluster_admin_access_entries :
    key => {
      principal_arn = entry.principal_arn
      policy_associations = {
        cluster_admin = {
          policy_arn   = local.eks_admin_policy_arn
          access_scope = { type = "cluster" }
        }
      }
    }
  }

  enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]
  cloudwatch_log_group_retention_in_days = 14

  create_kms_key                  = true
  kms_key_deletion_window_in_days = 7
  encryption_config               = { resources = ["secrets"] }

  service_ipv4_cidr = "172.20.0.0/16"
  upgrade_policy    = { support_type = "STANDARD" }

  enable_irsa = true

  addons = {
    vpc-cni = {
      addon_version               = "v1.22.3-eksbuild.1"
      most_recent                 = false
      before_compute              = true
      configuration_values        = jsonencode({ enableNetworkPolicy = "true" })
      service_account_role_arn    = aws_iam_role.vpc_cni.arn
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "PRESERVE"
    }
    coredns = {
      addon_version               = "v1.14.3-eksbuild.3"
      most_recent                 = false
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "PRESERVE"
    }
    kube-proxy = {
      addon_version               = "v1.36.0-eksbuild.9"
      most_recent                 = false
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "PRESERVE"
    }
    aws-ebs-csi-driver = {
      # TODO(verify): confirm v1.62.0-eksbuild.1 exists for EKS 1.36 in ap-southeast-1.
      addon_version               = "v1.62.0-eksbuild.1"
      most_recent                 = false
      service_account_role_arn    = aws_iam_role.ebs_csi.arn
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "PRESERVE"
    }
  }

  eks_managed_node_groups = {
    workers = {
      name            = "${var.name_prefix}-workers"
      use_name_prefix = false

      instance_types = var.node_instance_types
      ami_type       = "AL2023_x86_64_STANDARD"
      capacity_type  = "ON_DEMAND"

      min_size     = 2
      max_size     = 2
      desired_size = var.node_desired_size

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            delete_on_termination = true
            encrypted             = true
            volume_size           = var.node_disk_size_gib
            volume_type           = "gp3"
          }
        }
      }

      metadata_options = {
        http_endpoint               = "enabled"
        http_protocol_ipv6          = "disabled"
        http_put_response_hop_limit = 1
        http_tokens                 = "required"
        instance_metadata_tags      = "disabled"
      }

      update_config = {
        max_unavailable = 1
      }
    }
  }
}
