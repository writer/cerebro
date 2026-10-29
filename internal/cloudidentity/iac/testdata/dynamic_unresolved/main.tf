variable "extra_statements" {
  type = list(object({
    sid     = string
    actions = list(string)
  }))
  default = [
    { sid = "ExtraRead", actions = ["s3:GetObject"] },
  ]
}

data "aws_iam_policy_document" "dynamic_doc" {
  statement {
    sid    = "Base"
    effect = "Allow"

    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::dynamic-bucket"]
  }

  dynamic "statement" {
    for_each = var.extra_statements
    content {
      sid       = statement.value.sid
      effect    = "Allow"
      actions   = statement.value.actions
      resources = ["arn:aws:s3:::dynamic-bucket/*"]

      dynamic "condition" {
        for_each = statement.value.sid == "ExtraRead" ? [1] : []
        content {
          test     = "StringEquals"
          variable = "aws:PrincipalTag/team"
          values   = ["platform"]
        }
      }
    }
  }
}

resource "aws_iam_policy" "dynamic_policy" {
  name   = "dynamic-policy"
  policy = data.aws_iam_policy_document.dynamic_doc.json
}

data "aws_eks_cluster" "main" {
  name = "cluster"
}

locals {
  # Not statically resolvable: the OIDC issuer is only known once the EKS
  # cluster exists live. This must surface as a gap, never a fabricated value.
  oidc_issuer = replace(data.aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")
}

resource "aws_iam_role" "eks_app" {
  name = "eks-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::444444444444:oidc-provider/${local.oidc_issuer}" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dynamic_attach" {
  role       = aws_iam_role.eks_app.name
  policy_arn = aws_iam_policy.dynamic_policy.arn
}
