terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.76"
    }
  }
}

#bucket for backend storage
resource "aws_s3_bucket" "backend-bucket" {
  bucket = "aws-terraform-project3-backend"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.backend-bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "versioning_example" {
  bucket = aws_s3_bucket.backend-bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}


# Configure the AWS VPC
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main-vpc"
  }
}

# Configure the AWS SUBNETS
resource "aws_subnet" "subnet1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "public-subnet"
  }
}

resource "aws_subnet" "subnet2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
  tags = {
    Name = "private-subnet"
  }
}

# Configure the AWS INTERNET GATEWAY
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "internet-gateway"
  }
}


# Configure the AWS elastic-ip
resource "aws_eip" "lb" {
  #instance = aws_instance.web.id
  domain = "vpc"
}

# Configure the AWS route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "public-route-table"
  }
}


# Configure the AWS route table association
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.public.id
}


# Configure the AWS EC2 instance

data "aws_ami" "aws_terraform_project" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_launch_template" "project_instances" {
  name = "aws_terraform_project_instances"

  instance_type = "t2.micro"
  image_id      = data.aws_ami.aws_terraform_project.id
  #security_group_names = [aws_security_group.allow_tls.id]
  key_name = "aws_terraform1"


  monitoring {
    enabled = true
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.test_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.allow_tls.id]
  }

  #placement {
  #  availability_zone = "us-west-2a"
  #}


  #vpc_security_group_ids = [aws_security_group.allow_tls.id]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "test"
    }
  }
  user_data = base64encode(file("install_apache.sh"))
  #user_data = file("install_apache.sh")

  depends_on = [aws_s3_bucket.aws-terraform-project1-bucket]
}

resource "aws_placement_group" "test" {
  name     = "test"
  strategy = "cluster"
}

resource "aws_autoscaling_group" "aws_terraform_project" {
  name                      = "aws_terraform_autoscaling"
  max_size                  = 2
  min_size                  = 2
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2
  force_delete              = true
  #availability_zones        = ["us-east-1a", "us-east-1b"]   this is used if the subnet the Auto Scaling Group is used to span default subnets in specific zones.Use vpc_zone_identifier to specify subnet IDs for the Auto Scaling Group.

  launch_template {
    id      = aws_launch_template.project_instances.id
    version = "$Latest"
  }
  vpc_zone_identifier = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]

  target_group_arns = [
    aws_lb_target_group.alb-example.arn # Associate with the target group
  ]


  tag {
    key                 = "Name"
    value               = "app_instance_1"
    propagate_at_launch = true
  }
  tag {
    key                 = "Name"
    value               = "app_instance_2"
    propagate_at_launch = true
  }

  timeouts {
    delete = "15m"
  }

}

#Autoscaling attachment
# Create a new ALB Target Group attachment
resource "aws_autoscaling_attachment" "aws_terraform_project" {
  autoscaling_group_name = aws_autoscaling_group.aws_terraform_project.id
  lb_target_group_arn    = aws_lb_target_group.alb-example.arn
}

# Configure the AWS security group

resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "allow_tls"
  }

  #  from https port 443
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #  from http port 80
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  #  from ssh port 22
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


#1 configure load balancer
resource "aws_lb" "alb" {
  name               = "applicationloadbalcharles"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]

  enable_deletion_protection = false

  tags = {
    Environment = "development"
  }
}

#2. Create the target group
resource "aws_lb_target_group" "alb-example" {
  name     = "tf-example-lb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}





#4. target group
# Configure the AWS ALB listener
resource "aws_lb_listener" "alb_listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb-example.arn
  }
}

resource "aws_security_group" "load_balancer" {
  name        = "load_balancer"
  description = "security group for load_balancer"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "load_balancer-sg"
  }

  #  from http port 80
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  # egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


}

resource "aws_s3_object" "all_files" {
  for_each = fileset("/mnt/c/aws_terraform/aws_terraform_project2/project_files", "*")

  bucket     = "charles-s3-bucket-aws-proj"
  key        = each.value
  source     = "/mnt/c/aws_terraform/aws_terraform_project2/project_files/${each.value}"
  depends_on = [aws_s3_bucket.aws-terraform-project1-bucket]
}

/*
resource "aws_s3_object" "my_html_file" {
  bucket = "charles-s3-bucket-aws-proj"
  #bucket = "charles-s3-bucket-aws-proj"
  key    = "index.html"
  source = "/mnt/c/aws_terraform/aws_terraform_project1/index.html"

  depends_on = [ aws_s3_bucket.aws-terraform-project1-bucket ]

}
*/

output "dns_name" {
  value = aws_lb.alb.dns_name
}

#waf
resource "aws_wafv2_web_acl" "example" {
  name        = "managed-rule-example"
  description = "Example of a managed rule."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rule-1"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          action_to_use {
            count {}
          }

          name = "SizeRestrictions_QUERYSTRING"
        }

        rule_action_override {
          action_to_use {
            count {}
          }

          name = "NoUserAgent_HEADER"
        }

        scope_down_statement {
          geo_match_statement {
            country_codes = ["US", "NL"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "friendly-rule-metric-name"
      sampled_requests_enabled   = false
    }
  }

  tags = {
    Tag1 = "Value1"
    Tag2 = "Value2"
  }

  token_domains = ["mywebsite.com", "myotherwebsite.com"]

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "friendly-metric-name"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "example" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.example.arn
}

resource "aws_wafv2_ip_set" "example" {
  name               = "example"
  description        = "Example IP set"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["82.22.204.76/32"]
  #addresses          = ["92.40.191.69/32"]

  tags = {
    Tag1 = "phone"
    Tag2 = "charles_phone"
  }
}


resource "aws_iam_role" "aws_terraform_role" {
  name = "aws_terraform_role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" : "Allow",
        "Action" : "s3:GetObject",
        "Resource" : ["${aws_s3_bucket.aws-terraform-project1-bucket.arn}/*"]
      }
    ]
  })
}



resource "aws_iam_role_policy_attachment" "role_policy_aws_terraform" {
  role       = aws_iam_role.aws_terraform_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "test_profile" {
  name = "test_profile"
  role = aws_iam_role.aws_terraform_role.name
}

#Create s3
resource "aws_s3_bucket" "aws-terraform-project1-bucket" {
  bucket        = "charles-s3-bucket-aws-proj"
  force_destroy = "true"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

#Code PipeLine


#2 code build
resource "aws_codebuild_project" "example" {
  name          = "aws_terraform_project3_build"
  description   = "code build for aws_terraform_project3"
  build_timeout = 5
  service_role  = aws_iam_role.example.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }


  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"


  }

  logs_config {
    cloudwatch_logs {
      group_name  = "log-group"
      stream_name = "log-stream"
    }

    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.aws-terraform-project1-bucket.id}/build-log"
    }
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/iykecharles/aws_terraform_project3.git"
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = true
    }
  }

  source_version = "master"

  vpc_config {
    vpc_id = aws_vpc.main.id

    subnets = [
      aws_subnet.subnet1.id,
      aws_subnet.subnet2.id,
    ]

    security_group_ids = [
      aws_security_group.allow_tls.id
    ]
  }

  tags = {
    Environment = "github"
  }
}


resource "aws_codedeploy_app" "aws_terraform_project" {
  compute_platform = "Server"
  name             = "example"
}


#sns for codedeploy
resource "aws_sns_topic" "codedeploy" {
  name = "example-topic"
}

resource "aws_codedeploy_deployment_group" "aws_terraform_project" {
  app_name              = aws_codedeploy_app.aws_terraform_project.name
  deployment_group_name = "aws_terraform_project-group"
  service_role_arn      = aws_iam_role.example.arn


  trigger_configuration {
    trigger_events     = ["DeploymentFailure"]
    trigger_name       = "Deployment-trigger"
    trigger_target_arn = aws_sns_topic.codedeploy.arn
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  alarm_configuration {
    alarms  = ["aws_terraform_alarm"]
    enabled = true
  }

  outdated_instances_strategy = "UPDATE"

}

#Code Deploy IAM_ROLE, POLICY AND ATTACHMENT...
/*
data "aws_iam_policy_document" "codebuild_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }

    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeTags",
      "codedeploy:*",
      "s3:*",
      "cloudwatch:*",
      "iam:PassRole",
    ]
  }
}
*/
resource "aws_iam_role" "example" {
  name               = "example"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "example" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
    ]

    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.codebuild_bucket.arn,
      "${aws_s3_bucket.codebuild_bucket.arn}/*",
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["sns:Publish"]
    resources = ["arn:aws:sns:us-east-1:827950560876:example-topic"]
  }

  statement {
    effect = "Allow"

    actions = [
      "codecommit:ListBranches",
      "codecommit:GetRepository",
      "codecommit:GitPull",
      "codecommit:BatchGetRepositories",
    ]

    resources = ["arn:aws:codecommit:*:827950560876:*"]
  }
}

resource "aws_iam_role_policy" "example" {
  role   = aws_iam_role.example.name
  policy = data.aws_iam_policy_document.example.json
}

#s3 for the sotrage of codebuild artifacts
resource "aws_s3_bucket" "codebuild_bucket" {
  bucket = "charles316-aws-terraform-codebuild-bucket" #this name must be unique globally
}

resource "aws_s3_bucket_public_access_block" "codebuild_bucket_pab" {
  bucket = aws_s3_bucket.codebuild_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


#CodePipeline
resource "aws_codepipeline" "codepipeline" {
  name     = "tf-test-pipeline"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.codepipeline_bucket.bucket
    type     = "S3"

    encryption_key {
      #id   = aws_kms_alias.example.arn
      id   = "alias/aws/s3"
      type = "KMS"
    }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        Owner = "iykecharles"
        Repo = "https://github.com/iykecharles/aws_terraform_project3.git"
        Branch = "main"
        OAuthToken = var.github_token
        
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      version          = "1"

      configuration = {
        ProjectName = "test"
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeploy"
      input_artifacts = ["build_output"]
      version         = "1"

      configuration = {
      ApplicationName     = aws_codedeploy_app.aws_terraform_project.name
      DeploymentGroupName = aws_codedeploy_deployment_group.aws_terraform_project.deployment_group_name
    }
    }
  }
}


resource "aws_s3_bucket" "codepipeline_bucket" {
  bucket = "charles-aws-terraform-codepipeline-bucket"
}

resource "aws_s3_bucket_public_access_block" "codepipeline_bucket_pab" {
  bucket = aws_s3_bucket.codepipeline_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#codepipeline role, policy and attachment
data "aws_iam_policy_document" "codepipeline_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "codepipeline_role" {
  name               = "test-role"
  assume_role_policy = data.aws_iam_policy_document.codepipeline_assume_role.json
}

#codepipeline policy
data "aws_iam_policy_document" "codepipeline_policy" {
  statement {
    effect = "Allow"

    actions = [
      "github:GetBranch",
      "github:GetCommit",
      "github:GetRepository",
      "github:ListBranches",
      "github:ListRepositories",
    ]
    #arn:aws:iam::123456789012:role/codepipeline-example-role
    resources = [aws_codecommit_repository.test.arn]
  }
  
  statement {
    effect = "Allow"

    actions = [
      "codebuild:BatchGetBuilds",
      "codebuild:StartBuild",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "codepipeline_policy" {
  name   = "codepipeline_policy"
  role   = aws_iam_role.codepipeline_role.id
  policy = data.aws_iam_policy_document.codepipeline_policy.json
}

