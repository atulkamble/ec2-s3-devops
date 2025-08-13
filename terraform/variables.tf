variable "project"        { default = "ec2-s3-static-site" }
variable "region"         { default = "us-east-1" }
variable "domain_name"    { description = "FQDN for ALB (optional)" default = "" }
variable "acm_cert_arn"   { description = "ACM cert in same region as ALB" default = "" }
variable "key_pair_name"  { description = "Existing EC2 key pair" }
variable "allowed_cidrs"  { type = list(string) default = ["0.0.0.0/0"] } # tighten later
variable "tags"           { type = map(string) default = { "Owner" = "Atul" } }
