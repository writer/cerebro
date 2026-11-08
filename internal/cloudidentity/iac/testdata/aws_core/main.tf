variable "account_id" {
  type    = string
  default = "111111111111"
}

locals {
  inline_policies = {
    s3-read = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid      = "S3Read"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
      }]
    })
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    sid     = "EKSAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${var.account_id}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"]
    }

    condition {
      test     = "StringEquals"
      variable = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub"
      values   = ["system:serviceaccount:default:app"]
    }
  }
}

resource "aws_iam_policy" "boundary" {
  name = "app-boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "BoundaryAllow"
      Effect   = "Allow"
      Action   = ["s3:*", "sts:AssumeRole"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_role" "app" {
  name                 = "app-role"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

resource "aws_iam_role_policy" "inline" {
  for_each = local.inline_policies

  name   = each.key
  role   = aws_iam_role.app.name
  policy = each.value
}

resource "aws_iam_role_policy_attachment" "managed" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_group" "readers" {
  name = "readers"
}

resource "aws_iam_group_policy" "readers_policy" {
  name  = "readers-policy"
  group = aws_iam_group.readers.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadLogs"
      Effect   = "Allow"
      Action   = ["logs:GetLogEvents"]
      Resource = ["*"]
    }]
  })
}

resource "aws_iam_user" "alice" {
  name = "alice"
}

resource "aws_iam_user_group_membership" "alice_membership" {
  user   = aws_iam_user.alice.name
  groups = [aws_iam_group.readers.name]
}
