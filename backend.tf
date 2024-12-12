terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.76"
    }
  }

  backend "s3" {
    bucket  = "aws-terraform-project3-backend"
    key     = "terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}
