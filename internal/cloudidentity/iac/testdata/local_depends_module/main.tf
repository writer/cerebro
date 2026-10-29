module "role" {
  source = "./modules/role"
}

locals {
  attach_role_name = module.role.role_name
}

resource "aws_iam_role_policy_attachment" "extra" {
  role       = local.attach_role_name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
