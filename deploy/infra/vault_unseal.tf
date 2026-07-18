# The unseal permissions attach to the existing vault-broker role because
# IRSA allows one role per service account.

# The account-root statement retains key administration and prevents
# lockout; only the vault-broker role may use the key.
data "aws_iam_policy_document" "vault_unseal_key" {
  statement {
    sid       = "KeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "VaultAutoUnseal"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.vault_broker.arn]
    }
  }
}

resource "aws_kms_key" "vault_unseal" {
  description             = "Auto-unseal key for the AgentGate sandbox Vault."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.vault_unseal_key.json
}

resource "aws_kms_alias" "vault_unseal" {
  name          = "alias/${var.name_prefix}-vault-unseal"
  target_key_id = aws_kms_key.vault_unseal.key_id
}

data "aws_iam_policy_document" "vault_broker_unseal" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.vault_unseal.arn]
  }
}

resource "aws_iam_role_policy" "vault_broker_unseal" {
  name   = "vault-auto-unseal"
  policy = data.aws_iam_policy_document.vault_broker_unseal.json
  role   = aws_iam_role.vault_broker.id
}
