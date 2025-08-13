terraform {
  required_version = ">= 1.5"
  required_providers { aws = { source = "hashicorp/aws" version = "~> 5.0" } }
}
provider "aws" { region = var.region }

locals {
  bucket_name = "${var.project}-${random_id.suffix.hex}"
}

resource "random_id" "suffix" { byte_length = 3 }

# --- VPC (minimal) ---
resource "aws_vpc" "main" { cidr_block = "10.60.0.0/16" tags = merge(var.tags, { Name = "${var.project}-vpc" }) }
resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }
resource "aws_subnet" "public_a" {
  vpc_id = aws_vpc.main.id cidr_block = "10.60.1.0/24" map_public_ip_on_launch = true
  availability_zone = "${var.region}a"
  tags = merge(var.tags, { Name = "${var.project}-public-a" })
}
resource "aws_route_table" "public" { vpc_id = aws_vpc.main.id }
resource "aws_route" "default" { route_table_id = aws_route_table.public.id destination_cidr_block = "0.0.0.0/0" gateway_id = aws_internet_gateway.igw.id }
resource "aws_route_table_association" "a" { route_table_id = aws_route_table.public.id subnet_id = aws_subnet.public_a.id }

# --- Security Groups ---
resource "aws_security_group" "alb_sg" {
  name = "${var.project}-alb-sg" vpc_id = aws_vpc.main.id
  ingress = [
    { from_port = 80, to_port = 80, protocol = "tcp", cidr_blocks = var.allowed_cidrs, ipv6_cidr_blocks = [], prefix_list_ids = [], security_groups = [], description = "HTTP" },
    { from_port = 443, to_port = 443, protocol = "tcp", cidr_blocks = var.allowed_cidrs, ipv6_cidr_blocks = [], prefix_list_ids = [], security_groups = [], description = "HTTPS" }
  ]
  egress = [{ from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"], ipv6_cidr_blocks = [] }]
}
resource "aws_security_group" "ec2_sg" {
  name = "${var.project}-ec2-sg" vpc_id = aws_vpc.main.id
  ingress = [
    { from_port = 80, to_port = 80, protocol = "tcp", security_groups = [aws_security_group.alb_sg.id], cidr_blocks = [], ipv6_cidr_blocks = [], description = "ALB -> EC2" },
    { from_port = 22, to_port = 22, protocol = "tcp", cidr_blocks = var.allowed_cidrs, ipv6_cidr_blocks = [], description = "SSH (tighten/remove in prod)" }
  ]
  egress = [{ from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"], ipv6_cidr_blocks = [] }]
}

# --- IAM for EC2 (read S3 only) ---
data "aws_iam_policy_document" "s3_read" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.assets.arn, "${aws_s3_bucket.assets.arn}/*"]
  }
}
resource "aws_iam_role" "ec2_role" {
  name = "${var.project}-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_policy" "s3_read" { name = "${var.project}-s3-read" policy = data.aws_iam_policy_document.s3_read.json }
resource "aws_iam_role_policy_attachment" "attach" { role = aws_iam_role.ec2_role.name policy_arn = aws_iam_policy.s3_read.arn }
resource "aws_iam_instance_profile" "ec2_profile" { name = "${var.project}-ec2-profile" role = aws_iam_role.ec2_role.name }

# --- S3 (private) + CloudFront OAC ---
resource "aws_s3_bucket" "assets" { bucket = local.bucket_name tags = var.tags }
resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.assets.id block_public_acls = true block_public_policy = true ignore_public_acls = true restrict_public_buckets = true
}
resource "aws_cloudfront_origin_access_control" "oac" {
  name = "${var.project}-oac" origin_access_control_origin_type = "s3" signing_behavior = "always" signing_protocol = "sigv4"
}
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origins {
    domain_name = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_id   = "s3assets"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }
  default_cache_behavior {
    allowed_methods  = ["GET","HEAD"]
    cached_methods   = ["GET","HEAD"]
    target_origin_id = "s3assets"
    viewer_protocol_policy = "redirect-to-https"
  }
  restrictions { geo_restriction { restriction_type = "none" } }
  viewer_certificate { cloudfront_default_certificate = true } # swap with ACM for custom domain on CDN if desired
  tags = var.tags
}

# Bucket policy to allow CloudFront OAC
data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid = "AllowCloudFrontOAC"
    principals { type = "Service" identifiers = ["cloudfront.amazonaws.com"] }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
    condition {
      test = "StringEquals"
      variable = "AWS:SourceArn"
      values = [aws_cloudfront_distribution.cdn.arn]
    }
  }
}
resource "aws_s3_bucket_policy" "assets" { bucket = aws_s3_bucket.assets.id policy = data.aws_iam_policy_document.bucket_policy.json }

# --- ALB + Target Group + Listener ---
resource "aws_lb" "alb" {
  name               = "${var.project}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_a.id]
  tags               = var.tags
}
resource "aws_lb_target_group" "tg" {
  name = "${var.project}-tg" port = 80 protocol = "HTTP" vpc_id = aws_vpc.main.id
  health_check { path = "/" matcher = "200-399" }
  tags = var.tags
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn port = 80 protocol = "HTTP"
  default_action { type = "redirect" redirect { port = "443" protocol = "HTTPS" status_code = "HTTP_301" } }
}
resource "aws_lb_listener" "https" {
  count = length(var.acm_cert_arn) > 0 ? 1 : 0
  load_balancer_arn = aws_lb.alb.arn port = 443 protocol = "HTTPS" ssl_policy = "ELBSecurityPolicy-2016-08" certificate_arn = var.acm_cert_arn
  default_action { type = "forward" target_group_arn = aws_lb_target_group.tg.arn }
}

# --- EC2 ---
data "aws_ami" "al2023" {
  most_recent = true owners = ["137112412989"] # Amazon
  filter { name = "name" values = ["al2023-ami-*-x86_64"] }
}
resource "aws_instance" "web" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  key_name               = var.key_pair_name
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  user_data              = file("${path.module}/../scripts/user-data.sh")
  tags = merge(var.tags, { Name = "${var.project}-web" })
}
resource "aws_lb_target_group_attachment" "attach" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.web.id
  port             = 80
}

output "alb_dns_name"      { value = aws_lb.alb.dns_name }
output "cloudfront_domain" { value = aws_cloudfront_distribution.cdn.domain_name }
output "s3_bucket"         { value = aws_s3_bucket.assets.bucket }
