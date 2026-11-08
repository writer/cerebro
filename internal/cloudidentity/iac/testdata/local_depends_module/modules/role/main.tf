resource "aws_iam_role" "this" {
  name = "module-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

output "role_name" {
  value = aws_iam_role.this.name
}
