resource "google_compute_network" "compute_network" {
  for_each                                  = var.compute_networks
  name                                      = lookup(each.value, "name", each.key)
  description                               = lookup(each.value, "description", null)
  auto_create_subnetworks                   = lookup(each.value, "auto_create_subnetworks", "true")
  routing_mode                              = lookup(each.value, "routing_mode", "REGIONAL") # REGIONAL or GLOBAL
  mtu                                       = lookup(each.value, "mtu", null)                # Min: 1300, Max: 8896
  enable_ula_internal_ipv6                  = lookup(each.value, "enable_ula_internal_ipv6", null)
  internal_ipv6_range                       = lookup(each.value, "internal_ipv6_range", null)
  network_firewall_policy_enforcement_order = lookup(each.value, "network_firewall_policy_enforcement_order", null) # BEFORE_CLASSIC_FIREWALL, AFTER_CLASSIC_FIREWALL (Default    )
  project                                   = lookup(each.value, "project", var.project_id)                                   # if not provided the provider project is used
  delete_default_routes_on_create           = lookup(each.value, "delete_default_routes_on_create", false)          # true or false (Default)
}

resource "google_compute_subnetwork" "compute_subnetwork" {
  for_each = { for k in flatten([
    for key, network in var.compute_networks : [
      for key_sn, subnet in lookup(network, "subnets", {}) : {
        net_key    = key
        subnet_key = key_sn
        subnet     = subnet
      }
    ]
    ]) : "${k.net_key}_${k.subnet_key}" => k
  }

  name                       = lookup(each.value.subnet, "name", each.value.subnet_key)
  ip_cidr_range              = each.value.subnet.ip_cidr_range
  network                    = google_compute_network.compute_network[each.value.net_key].id
  description                = lookup(each.value.subnet, "description", null)
  purpose                    = lookup(each.value.subnet, "purpose", null) # PRIVATE_RFC_1918 (D), INTERNAL_HTTPS_LOAD_BALANCER or REGIONAL_MANAGED_PROXY
  role                       = lookup(each.value.subnet, "role", null)    # ACTIVE or BACKUP
  secondary_ip_range         = lookup(each.value.subnet, "secondary_ip_range", null)
  private_ip_google_access   = lookup(each.value.subnet, "private_ip_google_access", "false")
  private_ipv6_google_access = lookup(each.value.subnet, "private_ipv6_google_access", "false")
  region                     = lookup(each.value.subnet, "region", null)
  dynamic "log_config" {
    for_each = { for key, value in each.value.subnet : key => value if key == "log_config" }
    content {
      aggregation_interval = lookup(log_config, "aggregation_interval", "INTERVAL_5_SEC") # INTERVAL_5_SEC (D), INTERVAL_30_SEC, INTERVAL_1_MIN, INTERVAL_5_MIN, INTERVAL_10_MIN, INTERVAL_15_MIN
      flow_sampling        = lookup(log_config, "flow_sampling", "0.5")                   # The value of the field must be in [0, 1]. Set the sampling rate of VPC flow logs within the subnetwork where 1.0 means all collected logs are reported and 0.0 means no logs are reported. Default is 0.5 which means half of all collected logs are reported.
      metadata             = lookup(log_config, "metadata", "INCLUDE_ALL_METADATA")       # EXCLUDE_ALL_METADATA, INCLUDE_ALL_METADATA (D), CUSTOM_METADATA
      metadata_fields      = lookup(log_config, "metadata_fields", null)
      filter_expr          = lookup(log_config, "filter_expr", null) # default true
    }
  }

  stack_type       = lookup(each.value.subnet, "stack_type", "IPV4_ONLY") #IPV4_ONLY (D), IPV4_IPV6
  ipv6_access_type = lookup(each.value.subnet, "ipv6_access_type", null)  # EXTERNAL, INTERNAL
  project          = lookup(each.value.subnet, "project", var.project_id)           # If it is not provided, the provider project is used.
}



resource "google_compute_firewall" "compute_firewall" {
  for_each = { for k in flatten([
    for key, network in var.compute_networks : [
      for key_fw, firewall in lookup(network, "firewalls", {}) : {
        net_key      = key
        firewall_key = key_fw
        firewall     = firewall
      }
    ]
    ]) : "${k.net_key}_${k.firewall_key}" => k
  }

  name    = lookup(each.value.firewall, "name", each.value.firewall_key)
  network = google_compute_network.compute_network[each.value.net_key].name

  dynamic "allow" {
    for_each = lookup(each.value.firewall, "allow", {})
    content {
      protocol = allow.value.protocol
      ports    = lookup(allow.value, "ports", null)
    }

  }

  dynamic "deny" {
    for_each = lookup(each.value.firewall, "deny", {})
    content {
      protocol = deny.protocol
      ports    = lookup(deny, "ports", null)
    }
  }

  description        = lookup(each.value.firewall, "description", null)
  destination_ranges = lookup(each.value.firewall, "destination_ranges", null)
  direction          = lookup(each.value.firewall, "direction", "INGRESS") #INGRESS (D), EGRESS
  disabled           = lookup(each.value.firewall, "disabled", "false")    #true or false
  dynamic "log_config" {
    for_each = { for key, value in each.value.firewall : key => value if key == "log_config" }
    content {
      metadata = lookup(log_config, "metadata", "INCLUDE_ALL_METADATA") # EXCLUDE_ALL_METADATA, INCLUDE_ALL_METADATA (D), CUSTOM_METADATA
    }
  }
  priority                = lookup(each.value.firewall, "priority", "1000") #integer between 0 and 65535, both inclusive. Default 1000
  source_ranges           = lookup(each.value.firewall, "source_ranges", null)
  source_service_accounts = lookup(each.value.firewall, "source_service_accounts", null)
  source_tags             = lookup(each.value.firewall, "source_tags", null)
  target_service_accounts = lookup(each.value.firewall, "target_service_accounts", null)
  target_tags             = lookup(each.value.firewall, "target_tags", null)
  project                 = lookup(each.value.firewall, "project", var.project_id) # If it is not provided, the provider project is used.


}

resource "google_compute_router" "compute_router" {
  for_each = { for k in flatten([
    for key, network in var.compute_networks : [
      for key_router, router in lookup(network, "routers", {}) : {
        net_key    = key
        router_key = key_router
        router     = router
      }
    ]
    ]) : "${k.net_key}_${k.router_key}" => k
  }
  name    = lookup(each.value.router, "name", each.value.router_key)
  network = google_compute_network.compute_network[each.value.net_key].name

  dynamic "bgp" {
    for_each = { for key, value in each.value.router : key => value if key == "bgp" }
    content {
      asn               = bgp.asn
      advertise_mode    = lookup(bgp, "advertise_mode", null)    # DEFAULT, CUSTOM
      advertised_groups = lookup(bgp, "advertised_groups", null) # ["ALL_SUBNETS"] (D)
      dynamic "advertised_ip_ranges" {
        for_each = { for key, value in bgp : key => value if key == "advertised_ip_ranges" }
        content {
          range = advertised_ip_ranges.range
        }
      }
    }
  }
}

resource "google_compute_router_peer" "compute_router_peer" {
  for_each = { for k in flatten([
    for key, network in var.compute_networks : [
      for key_router_peer, router_peer in lookup(network, "router_peers", {}) : {
        net_key         = key
        router_peer_key = key_router_peer
        router_peer     = router_peer
      }
    ]
    ]) : "${k.net_key}_${k.router_peer_key}" => k
  }
  name                      = lookup(each.value.router_peer, "name", each.value.router_peer_key)
  router                    = google_compute_router.compute_router["${each.value.net_key}_${each.value.router_peer.router}"].name
  region                    = lookup(each.value.router_peer, "region", null)
  project                   = lookup(each.value.router_peer, "project", var.project_id) # If it is not provided, the provider project is used.
  peer_ip_address           = each.value.router_peer.peer_ip_address
  peer_asn                  = each.value.router_peer.peer_asn
  advertised_route_priority = lookup(each.value.router_peer, "advertised_route_priority", null)
  interface                 = each.value.router_peer.interface
  advertise_mode            = lookup(each.value.router_peer, "advertise_mode", null)    # DEFAULT or CUSTOM
  advertised_groups         = lookup(each.value.router_peer, "advertised_groups", null) # ALL_SUBNETS or ALL_VPC_SUBNETS or ALL_PEER_VPC_SUBNETS
  dynamic "advertised_ip_ranges" {
    for_each = { for key, value in each.value.router_peer : key => value if key == "advertised_ip_ranges" }
    content {
      range       = advertised_ip_ranges.range
      description = lookup(advertised_ip_ranges, "description", null)
    }
  }
}

resource "google_compute_router_interface" "compute_router_interface" {
  for_each = { for k in flatten([
    for key, network in var.compute_networks : [
      for key_router_interface, router_interface in lookup(network, "router_interfaces", {}) : {
        net_key              = key
        router_interface_key = key_router_interface
        router_interface     = router_interface
      }
    ]
    ]) : "${k.net_key}_${k.router_interface_key}" => k
  }
  name                    = lookup(each.value.router_interface, "name", each.value.router_interface_key)
  router                  = google_compute_router.compute_router["${each.value.net_key}_${each.value.router_interface.router}"].name
  region                  = lookup(each.value.router_interface, "region", null)
  ip_range                = lookup(each.value.router_interface, "ip_range", null)
  vpn_tunnel              = lookup(each.value.router_interface, "vpn_tunnel", null)
  interconnect_attachment = lookup(each.value.router_interface, "interconnect_attachment", null)
  project                 = lookup(each.value.router_interface, "project", var.project_id) # If it is not provided, the provider project is used.
}


resource "google_compute_router_nat" "compute_router_nat" {
  for_each = { for k in flatten([
    for key, network in var.compute_networks : [
      for key_router_nat, router_nat in lookup(network, "routers_nat", {}) : {
        net_key                = key
        router_nat_key = key_router_nat
        router_nat     = router_nat
      }
    ]
    ]) : "${k.net_key}_${k.router_nat_key}" => k
  }
  name                               = lookup(each.value.router_nat, "name", each.value.router_nat_key)
  router                             = google_compute_router.compute_router["${each.value.net_key}_${each.value.router_nat.router}"].name
  region                             = lookup(each.value.router_nat, "region", null)
  nat_ip_allocate_option             = lookup(each.value.router_nat, "nat_ip_allocate_option", "AUTO_ONLY")                                 #AUTO_ONLY or MANUAL_ONLY
  source_subnetwork_ip_ranges_to_nat = lookup(each.value.router_nat, "source_subnetwork_ip_ranges_to_nat", "ALL_SUBNETWORKS_ALL_IP_RANGES") #ALL_SUBNETWORKS_ALL_IP_RANGES or ALL_SUBNETWORKS_ALL_PRIMARY_IP_RANGES or LIST_OF_SUBNETWORKS
  nat_ips                            = lookup(each.value.router_nat, "nat_ips", null)
  dynamic subnetwork {
    for_each = { for key, value in each.value.router_nat : key => value if key == "subnetwork" }
    content {
      name = google_compute_network.compute_subnetwork[each.value.subnetwork].name
      source_ip_ranges_to_nat = lookup(subnetwork.router_nat, "source_ip_ranges_to_nat", "ALL_IP_RANGES") #ALL_IP_RANGES, LIST_OF_SECONDARY_IP_RANGES, PRIMARY_IP_RANGE.
      secondary_ip_range_names = lookup(subnetwork.router_nat, "secondary_ip_range_names", null) #ALL_IP_RANGES, LIST_OF_SECONDARY_IP_RANGES, PRIMARY_IP_RANGE
    }    
  }                        
  min_ports_per_vm                   = lookup(each.value.router_nat, "min_ports_per_vm", null)
  udp_idle_timeout_sec               = lookup(each.value.router_nat, "udp_idle_timeout_sec", null)
  icmp_idle_timeout_sec              = lookup(each.value.router_nat, "icmp_idle_timeout_sec", null)
  tcp_established_idle_timeout_sec   = lookup(each.value.router_nat, "tcp_established_idle_timeout_sec", null)
  tcp_transitory_idle_timeout_sec    = lookup(each.value.router_nat, "tcp_transitory_idle_timeout_sec", null)

  dynamic "log_config" {
    for_each = { for key, value in each.value.router_nat : key => value if key == "log_config" }
    content {
      enable = lookup(log_config, "enable", "true")
      filter = lookup(log_config, "filter", "ERRORS_ONLY") #"ERRORS_ONLY", "TRANSLATIONS_ONLY", "ALL"
    }
  }
}