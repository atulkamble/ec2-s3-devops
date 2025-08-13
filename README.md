# 🚀 EC2 + ALB + S3 (via CloudFront) — Production-ready DevOps Project

## 🧱 Architecture (recommended)

* **S3 (private)** stores images/assets
* **CloudFront** with **Origin Access Control (OAC)** fronts the S3 bucket (public access BLOCKED)
* **EC2 (Amazon Linux 2023) + Apache** serves HTML
* **ALB (HTTP → HTTPS)** terminates TLS (ACM cert) and routes to EC2
* **IAM Role on EC2** (read-only S3)
* **CloudWatch**: ALB/EC2 metrics & logs
* **CI/CD (GitHub Actions)**: pushes `/assets` to S3 and website HTML to EC2 via SSH (or SSM)

```
User → HTTPS → ALB → EC2:80
             └─(assets)→ CloudFront → S3 (private via OAC)
```

---

## 📁 Suggested Repo Layout

```
aws-ec2-s3-static-website/
├─ terraform/
│  ├─ main.tf
│  ├─ variables.tf
│  ├─ outputs.tf
├─ app/
│  ├─ index.html
│  └─ assets/               # png/jpg/css/js -> synced to S3 via CI
├─ scripts/
│  ├─ user-data.sh          # EC2 bootstrap
│  └─ deploy_ec2.sh         # rsync html to EC2 (optional)
├─ .github/workflows/
│  └─ deploy.yml            # CI/CD to S3 + EC2
└─ README.md
```

---

## ⚙️ Terraform (VPC, ALB, EC2, S3, CloudFront, IAM)

> Put these three files in `terraform/`. Adjust variables as needed.

### `variables.tf`

```hcl
variable "project"        { default = "ec2-s3-static-site" }
variable "region"         { default = "us-east-1" }
variable "domain_name"    { description = "FQDN for ALB (optional)" default = "" }
variable "acm_cert_arn"   { description = "ACM cert in same region as ALB" default = "" }
variable "key_pair_name"  { description = "Existing EC2 key pair" }
variable "allowed_cidrs"  { type = list(string) default = ["0.0.0.0/0"] } # tighten later
variable "tags"           { type = map(string) default = { "Owner" = "Atul" } }
```

### `main.tf` (concise, production-safe defaults)

```hcl
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
```

### `outputs.tf`

```hcl
output "ssh_example" { value = "ssh -i <key.pem> ec2-user@${aws_instance.web.public_dns}" }
```

---

## 🧰 EC2 Bootstrap (Apache + site deploy)

### `scripts/user-data.sh`

```bash
#!/usr/bin/env bash
set -euxo pipefail

# System
dnf -y update
dnf -y install httpd git

# Web root
install -d -m 0755 /var/www/html
cat >/var/www/html/index.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>My Static Website</title></head>
  <body>
    <h1 style="text-align:center">Welcome to My Static Website!</h1>
    <p style="text-align:center">Assets are served via CloudFront from S3.</p>
    <div style="text-align:center">
      <img src="__CLOUDFRONT_URL__/assets/coffee.png" alt="Coffee Image" width="420">
    </div>
  </body>
</html>
HTML

# Apache
systemctl enable --now httpd

# Insert CloudFront URL at first boot using instance metadata tag (optional)
CF_URL="$(/usr/bin/curl -s http://169.254.169.254/latest/meta-data/tags/instance/CLOUDFRONT_URL || true)"
if [[ -n "${CF_URL}" ]]; then
  sed -i "s|__CLOUDFRONT_URL__|${CF_URL}|g" /var/www/html/index.html
else
  sed -i "s|__CLOUDFRONT_URL__|#-set-cloudfront-url-|g" /var/www/html/index.html
fi
```

> Tip: You can set an **instance tag** `CLOUDFRONT_URL=https://xxxxxxxx.cloudfront.net` after `terraform apply` (or extend TF to set it automatically via `aws_instance` `tags` and replace in user-data with a `CF_URL` default).

---

## 🌩️ CI/CD — Sync assets to S3 + deploy HTML to EC2

### `.github/workflows/deploy.yml`

```yaml
name: Deploy Website
on:
  push:
    branches: [ main ]
    paths:
      - 'app/**'
      - '.github/workflows/deploy.yml'

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: us-east-1
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}   # (optional) OIDC role; else set AWS creds as secrets

      - name: Upload assets to S3
        run: |
          BUCKET="${{ secrets.S3_BUCKET }}"
          aws s3 sync app/assets "s3://${BUCKET}/assets" --delete --cache-control "public,max-age=31536000,immutable"

      # Option A: Upload HTML to EC2 via SSH
      - name: Deploy HTML to EC2
        if: ${{ success() }}
        env:
          EC2_HOST: ${{ secrets.EC2_HOST }}
        run: |
          echo "${{ secrets.EC2_SSH_KEY }}" > key.pem
          chmod 600 key.pem
          rsync -avz -e "ssh -i key.pem -o StrictHostKeyChecking=no" app/index.html ec2-user@${EC2_HOST}:/var/www/html/index.html

      # Option B (preferred): Store HTML in repo and let user-data pull from Git (not shown here)
```

**Secrets to set:**

* `S3_BUCKET` → the Terraform-created bucket output
* `EC2_HOST` → `aws ec2 describe-instances ...` public DNS or use SSM Session Manager instead of SSH
* `EC2_SSH_KEY` → private key (or use OIDC + SSM document for safer deploy)
* `AWS_ROLE_ARN` (optional) → if using GitHub OIDC for short-lived creds

---

## 💡 Using CloudFront URL in your HTML

Update `app/index.html` image links to the **CloudFront domain** output by Terraform:

```html
<img src="https://<cloudfront-domain>/assets/coffee.png" alt="Coffee">
```

Then commit & push:

```bash
git add app/index.html app/assets/*
git commit -m "Add CloudFront assets"
git push
```

The workflow will:

* Upload `/app/assets/*` → `s3://<bucket>/assets/`
* Rsync `/app/index.html` → `/var/www/html/index.html` on EC2

---

## 🛠️ Manual (quick) steps if you’re not using Terraform yet

1. **EC2** (Amazon Linux 2023), open port **80** from ALB (or world for test), **22** from your IP.
2. Install Apache + create index.html (your original steps are fine—keep `chmod 755 /var/www/html`).
3. **S3**: Create bucket, **block public access**, don’t use public bucket policies in prod.
4. **CloudFront**: Create distro with S3 origin + **OAC**; use the distro domain in your HTML `img src`.
5. Point browser to **ALB DNS** (or EC2 public DNS for a quick test).

---

## 🔒 Security & Ops Hardening

* **No public S3 bucket**; use **CloudFront OAC** (done).
* **HTTPS everywhere**: attach **ACM** cert to ALB (pass ARN to `var.acm_cert_arn`).
* Lock SSH to your IP (adjust `allowed_cidrs`). Consider SSM Session Manager instead of SSH.
* Add **AWS WAF** on ALB/CloudFront if needed.
* Enable **ALB access logs** to S3 and **CloudFront logs** (optional).
* Add **CloudWatch Agent** on EC2 for logs/metrics.
* Auto-healing: use **ASG** + **EC2 Launch Template** (easy to extend from current TF).

---

## 🧪 Smoke Test

* `terraform init && terraform apply -auto-approve -var key_pair_name=<your-keypair> -var acm_cert_arn=<optional>`
* Note outputs: `alb_dns_name`, `cloudfront_domain`, `s3_bucket`
* Push an image to `app/assets/coffee.png`, update HTML to reference CloudFront URL, push to `main`
* Visit `http://<alb_dns_name>` → should 301 to HTTPS (if cert provided) and load page + image.

---

## 🧯 Troubleshooting

* **Image 403**: Check CloudFront OAC policy attached to bucket; ensure object exists at `assets/<name>`.
* **Mixed content**: Ensure `https://` in HTML for CloudFront and site links.
* **Blank page**: Verify Apache is running and ALB Target Group health checks are **healthy**.
* **CI fails**: Validate `AWS creds`, `S3_BUCKET`, and network reachability to EC2.

---
