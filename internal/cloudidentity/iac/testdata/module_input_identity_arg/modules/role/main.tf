variable "policies" {
  type = list(string)
}

resource "aws_iam_role" "this" {
  name = "observability-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "this" {
  count      = length(var.policies)
  role       = aws_iam_role.this.name
  policy_arn = var.policies[count.index]
}
