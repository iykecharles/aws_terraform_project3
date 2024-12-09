#! /bin/bash
sudo yum update -y
sudo yum install -y httpd
sudo yum install -y httpd aws-cli
sudo systemctl start httpd
sudo systemctl enable httpd

#get docker and install
curl -fsSL https://get.docker.com -o get-docker.sh
sudo yum install docker -y
sudo docker --version
sudo systemctl start docker
sudo systemctl status docker

sudo mkdir -p /var/www/html/project
aws s3 cp "C:\aws_terraform\aws_terraform_project2\project_files\index.html" s3://${aws_s3_bucket.aws-terraform-project1-bucket.bucket}/index.html --dryrun

#copy the Dockerfiles
aws s3 cp "C:\aws_terraform\aws_terraform_project2\project_files\Dockerfile" s3://${aws_s3_bucket.aws-terraform-project1-bucket.bucket}/Dockerfile --dryrun
aws s3 cp s3://charles-s3-bucket-aws-proj/Dockerfile ~/Dockerfile



sudo systemctl restart httpd





