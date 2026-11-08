variable "account_id" {
  type    = string
  default = "222222222222"
}

module "app_role" {
  source = "./modules/app_role"

  role_name  = "contained-role"
  account_id = var.account_id
}

resource "aws_iam_role_policy_attachment" "extra" {
  role       = module.app_role.role_name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
