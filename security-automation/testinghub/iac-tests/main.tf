# Only problem here: SSH open to the whole internet. Should FAIL on IaC.
resource "aws_security_group" "ssh" {
  name        = "ssh-port22-open"
  description = "sg-port22-open"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
