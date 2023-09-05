output "compute_networks_all_input_attributes" {
  description = "all input attributes of created VPC Networks"
  value       = { for k, v in var.compute_networks : k => v }
}

output "compute_networks_all_attributes" {
  description = "all attributes of created VPC Networks"
  value       = { for k, v in google_compute_network.compute_network : k => v }
}
