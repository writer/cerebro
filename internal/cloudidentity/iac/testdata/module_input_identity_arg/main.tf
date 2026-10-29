resource "aws_iam_policy" "authorized_hydration" {
  name = "hydration-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["*"]
    }]
  })
}

module "observability_irsa" {
  source   = "./modules/role"
  policies = [aws_iam_policy.authorized_hydration.arn]
}
