resource "aws_security_group" "public" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}