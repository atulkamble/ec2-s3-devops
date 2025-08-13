output "ssh_example" { value = "ssh -i <key.pem> ec2-user@${aws_instance.web.public_dns}" }
