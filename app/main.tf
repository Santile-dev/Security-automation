resource "aws_s3_bucket" "s3_data_bucket" {
  bucket = "santile-insecure-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "santile_sg" {
  name = "allow-ssh-anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "santile-db" {
  identifier          = "santile-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "SantileS3cret!"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}