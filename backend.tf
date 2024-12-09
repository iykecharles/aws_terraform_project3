terraform {
  backend "s3" {
    bucket = "aws-terraform-project3-backend"
    key    = "terraform.tfstate"
    region = "us-east-1"
    encrypt = true
  }
}
