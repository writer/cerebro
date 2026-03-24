resource "aws_security_group" "public" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
}