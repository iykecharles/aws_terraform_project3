#bucket for backend storage
resource "aws_s3_bucket" "backend-bucket" {
  bucket = "aws-terraform-project3-backend"
  force_destroy = true
}
/*
resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.backend-bucket.id
  acl    = "private"
}
*/
resource "aws_s3_bucket_versioning" "versioning_example" {
  bucket = aws_s3_bucket.backend-bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bucket-config" {
  bucket = aws_s3_bucket.backend-bucket.id

  rule {
    id = "log"

    expiration {
      days = 90
    }

    filter {
      and {
        prefix = "log/"

        tags = {
          rule      = "log"
          autoclean = "true"
        }
      }
    }

    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }
  }

  rule {
    id = "tmp"

    filter {
      prefix = "tmp/"
    }

    expiration {
      date = "2023-01-13T00:00:00Z"
    }

    status = "Enabled"
  }
}

