#! /bin/bash
sudo yum update -y
sudo yum install -y httpd
sudo yum install -y aws-cli

# Start and enable Apache
sudo systemctl start httpd
sudo systemctl enable httpd

#get docker and install
curl -fsSL https://get.docker.com -o get-docker.sh
sudo yum install docker -y
sudo docker --version
sudo systemctl start docker
sudo systemctl status docker

#set the s3 bucket name
S3_BUCKET="charles-s3-bucket-aws-proj"
#sudo mkdir ~/project

# Fetch index.html from S3 and place it in the web root
aws s3 cp s3://$S3_BUCKET/index.html /var/www/html/index.html
#set the permissions
sudo chmod 644 /var/www/html/index.html

# Fetch Dockerfile from S3 and place it in the home
aws s3 cp s3://$S3_BUCKET/Dockerfile ~/Dockerfile

#restart apache
sudo systemctl restart httpd
#sudo systemctl stop httpd


#cd ~/project
docker build -t project-image .
docker run -d -p 8080:80 --name project-container project-image



