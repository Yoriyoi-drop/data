variable "name" { type = string }
variable "engine" { type = string  default = "postgres" }
variable "engine_version" { type = string  default = "15" }
variable "instance_class" { type = string }
variable "vpc_security_group_ids" { type = list(string) default = [] }
variable "subnet_ids" { type = list(string) }
variable "multi_az" { type = bool default = true }
