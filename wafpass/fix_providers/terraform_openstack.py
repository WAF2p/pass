"""Terraform OpenStack defaults for the WAF++ auto-fixer."""
from __future__ import annotations

from wafpass.fix_providers import FixProvider, fix_provider_registry

_TERRAFORM_OPENSTACK_BLOCK_DEFAULTS: dict[tuple[str, str], dict[str, object]] = {
    ("openstack_compute_instance_v2", "metadata"): {},
    ("openstack_compute_instance_v2", "security_groups"): ["default"],
    ("openstack_compute_instance_v2", "network"): {
        "uuid": "",
        "fixed_ip_v4": "",
        "access_network": False,
    },
    ("openstack_compute_instance_v2", "block_device"): {
        "uuid": "",
        "source_type": "image",
        "destination_type": "volume",
        "volume_size": 20,
        "delete_on_termination": True,
    },
    ("openstack_compute_instance_v2", "scheduler_hints"): {},
    ("openstack_compute_instance_v2", "user_data"): "",
    ("openstack_compute_instance_v2", "admin_pass"): "TODO-fill-in",
    ("openstack_compute_keypair_v2", "public_key"): "",
    ("openstack_compute_secgroup_v2", "rule"): {
        "ip_protocol": "tcp",
        "from_port": 443,
        "to_port": 443,
        "cidr": "0.0.0.0/0",
    },
    ("openstack_networking_network_v2", "admin_state_up"): True,
    ("openstack_networking_network_v2", "shared"): False,
    ("openstack_networking_network_v2", "port_security_enabled"): True,
    ("openstack_networking_network_v2", "tags"): [],
    ("openstack_networking_subnet_v2", "cidr"): "192.168.0.0/24",
    ("openstack_networking_subnet_v2", "gateway_ip"): "192.168.0.1",
    ("openstack_networking_subnet_v2", "enable_dhcp"): True,
    ("openstack_networking_subnet_v2", "allocation_pool"): {
        "start": "192.168.0.100",
        "end": "192.168.0.254",
    },
    ("openstack_networking_subnet_v2", "dns_nameservers"): [],
    ("openstack_networking_router_v2", "external_network_id"): "",
    ("openstack_networking_router_v2", "admin_state_up"): True,
    ("openstack_networking_router_interface_v2", "router_id"): "",
    ("openstack_networking_router_interface_v2", "subnet_id"): "",
    ("openstack_networking_floatingip_v2", "pool"): "public",
    ("openstack_networking_floatingip_v2", "address"): "",
    ("openstack_blockstorage_volume_v3", "size"): 20,
    ("openstack_blockstorage_volume_v3", "volume_type"): "__DEFAULT__",
    ("openstack_blockstorage_volume_v3", "metadata"): {},
    ("openstack_blockstorage_volume_v3", "multiattach"): False,
    ("openstack_blockstorage_volume_attach_v3", "host_name"): "",
    ("openstack_blockstorage_volume_attach_v3", "device"): "",
    ("openstack_images_image_v2", "container_format"): "bare",
    ("openstack_images_image_v2", "disk_format"): "qcow2",
    ("openstack_images_image_v2", "visibility"): "private",
    ("openstack_lb_loadbalancer_v2", "vip_subnet_id"): "",
    ("openstack_lb_loadbalancer_v2", "admin_state_up"): True,
    ("openstack_lb_listener_v2", "protocol"): "HTTPS",
    ("openstack_lb_listener_v2", "protocol_port"): 443,
    ("openstack_lb_pool_v2", "lb_algorithm"): "ROUND_ROBIN",
    ("openstack_lb_pool_v2", "protocol"): "HTTPS",
    ("openstack_identity_project_v3", "enabled"): True,
    ("openstack_identity_project_v3", "description"): "Managed by Terraform",
    ("openstack_identity_user_v3", "enabled"): True,
    ("openstack_identity_user_v3", "default_project_id"): "",
    ("openstack_identity_application_credential_v3", "roles"): [],
    ("openstack_dns_recordset_v2", "ttl"): 3600,
    ("openstack_dns_recordset_v2", "records"): [],
    ("openstack_dns_zone_v2", "email"): "hostmaster@example.com",
    ("openstack_dns_zone_v2", "ttl"): 3600,
    ("openstack_dns_zone_v2", "type"): "PRIMARY",
    ("openstack_objectstorage_container_v1", "container_read"): "",
    ("openstack_objectstorage_container_v1", "container_write"): "",
    ("openstack_objectstorage_container_v1", "versioning"): True,
    ("openstack_objectstorage_container_v1", "metadata"): {},
    # Provider-level defaults for provider "openstack" {} blocks.
    ("openstack", "auth_url"): "",
    ("openstack", "region"): "RegionOne",
    # Generic tag/metadata controls can apply to any OpenStack resource.
    ("*", "tags"): [],
    ("*", "metadata"): {},
}


fix_provider_registry.register(
    FixProvider(
        name="terraform_openstack",
        frameworks=["terraform"],
        providers=["openstack"],
        block_defaults=_TERRAFORM_OPENSTACK_BLOCK_DEFAULTS,
        resource_type_prefixes=["openstack_"],
        provider_block_types=["openstack"],
    )
)
