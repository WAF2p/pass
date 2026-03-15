resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # No tags at all
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.xlarge"
  tags = {
    Name = "web-server"
    # Missing: cost-center, owner, environment, workload
  }
}

provider "aws" {
  # No region set
}
