data "aws_iam_policy_document" "broken" {
  statement {
    sid     = "BrokenCondition"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    # for_each here is a number, not an iterable collection: this must fail
    # to expand rather than silently producing zero conditions on a grant
    # that still gets reported as "complete".
    dynamic "condition" {
      for_each = 42
      content {
        test     = "StringEquals"
        variable = "aws:PrincipalTag/team"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_iam_role" "broken" {
  name               = "broken-role"
  assume_role_policy = data.aws_iam_policy_document.broken.json
}
