variable "compute_networks" {
  description = "Map of VPC networks to be created"
  type        = any
  default     = {}
}

variable "project_id" {
  description = "Project to be used to deploy"
  type        = string
}