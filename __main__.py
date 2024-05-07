import pulumi as pulumi
import pulumi_azure_native as azure_native
from pulumi_azure_native import resources, network, compute, storage
from azure_client import _azure_client_id, _azure_client_secret, _azure_tenant_id, _azure_subscription_id
from pulumi import automation as auto

# Import the program's configuration settings
config = pulumi.Config()
vm_name = config.get("vmName", "my-server")
vm_size = config.get("vmSize", "Standard_DS2_v2")
admin_username = config.get("adminUsername", "devops")

def create_instance():
    
    # Create a resource group
    resource_group = resources.ResourceGroup("my-Resource-Group", location="westeurope")

    # Create a virtual network
    virtual_network = network.VirtualNetwork(
        "network",
        resource_group_name=resource_group.name,
        address_space=network.AddressSpaceArgs(
            address_prefixes=[
                "10.0.0.0/16",
            ],
        ),
        subnets=[
            network.SubnetArgs(
                name=f"{vm_name}-subnet",
                address_prefix="10.0.1.0/24",
            ),
        ],
    )
    # Use a random string to give the VM a unique DNS name
    domain_name_label = random_string.RandomString(
        "domain-label",
        length=8,
        upper=False,
        special=False,
    ).result.apply(lambda result: f"{vm_name}-{result}")

    # Create a public IP address for the VM
    public_ip = network.PublicIPAddress(
        "public-ip",
        resource_group_name=resource_group.name,
        public_ip_allocation_method=network.IpAllocationMethod.DYNAMIC,
        dns_settings=network.PublicIPAddressDnsSettingsArgs(
            domain_name_label=domain_name_label,
        ),
    )

    # Create a security group allowing inbound access over ports 80 (for HTTP) and 22 (for SSH)
    security_group = network.NetworkSecurityGroup(
        "security-group",
        resource_group_name=resource_group.name,
        security_rules=[
            network.SecurityRuleArgs(
                name=f"{vm_name}-securityrule",
                priority=1000,
                direction=network.AccessRuleDirection.INBOUND,
                access="Allow",
                protocol="Tcp",
                source_port_range="*",
                source_address_prefix="*",
                destination_address_prefix="*",
                destination_port_ranges=[
                    "22",
                ],
            ),
        ],
    )

    # Create a network interface with the virtual network, IP address, and security group
    network_interface = network.NetworkInterface(
        "network-interface",
        resource_group_name=resource_group.name,
        network_security_group=network.NetworkSecurityGroupArgs(
            id=security_group.id,
        ),
        ip_configurations=[
            network.NetworkInterfaceIPConfigurationArgs(
                name=f"{vm_name}-ipconfiguration",
                private_ip_allocation_method=network.IpAllocationMethod.DYNAMIC,
                subnet=network.SubnetArgs(
                    id=virtual_network.subnets.apply(lambda subnets: subnets[0].id),
                ),
                public_ip_address=network.PublicIPAddressArgs(
                    id=public_ip.id,
                ),
            ),
        ],
    )


    # Create the virtual machine
    vm = compute.VirtualMachine(
        "vm",
        resource_group_name=resource_group.name,
        # location="westeurope",
        network_profile=compute.NetworkProfileArgs(
            network_interfaces=[
                compute.NetworkInterfaceReferenceArgs(
                    id=network_interface.id,
                    primary=True,
                )
            ]
        ),
        hardware_profile=compute.HardwareProfileArgs(
            vm_size=vm_size,
        ),
        os_profile=compute.OSProfileArgs(
            computer_name=vm_name,
            admin_username=admin_username,
            linux_configuration=compute.LinuxConfigurationArgs(
                disable_password_authentication=True,
                ssh=compute.SshConfigurationArgs(
                    public_keys=[
                        compute.SshPublicKeyArgs(
                            key_data="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCqq8tgJwEtqGPw8DZaGWuWPuYx9PdjV5Wk5Ecmvytj6h+FyBfchYkzW60gNJwcolUbbDjJV36IrR/HROOcdlI3UkYjQJ4yGoO3i+xj3WN7SJ2JShskJsWTYoeVG1hC4n+dw4CVDjK/ueDxxj4yW298HwNRHEhaRwPWBzLC0kxqZpUo1r66nUV50hYo39pivpMHAGedJZtvCKru1zOy5EqoZP6/ApDfXRzhLi7e5a/UGbrxVQ+NxxIa61F5cmLK9/Uxcbi4up4kEkwnUbkv3VyhchSjCu5Tq9lUfUu81mdWsLiwnqmMlWRrT52bAQ43KaYFztlQ9E8aO3hvX9cq+9H22NmxyJ+oqA75eXWC5b07oNtDsKGIAb3zQaYMaA9OR4xkEyMAc/7x9piXcglWmPC1wlnsg/ghOZGzL3NxaeSUewVv6lWmt3Otogxz7CjbZ+tn03nG8lsJVJprHCb/bwO1qIKcxxKsFY43g4/PeF7finKO4ToI7s5PJxqdtQQltLc= nidhal@nidhal-virtual-machine",
                            # key_data=config.get("sshPublicKey"),
                            path=f"/home/{admin_username}/.ssh/authorized_keys",
                        ),
                    ],
                ),
            ),
        ),
        storage_profile=compute.StorageProfileArgs(
            image_reference=compute.ImageReferenceArgs(
                id="/subscriptions/5c799ce8-a3c7-4f8e-befe-3f59c567caa6/resourceGroups/my-Resource-Group/providers/Microsoft.Compute/images/myPackerImageDEMO",
            ),
            os_disk={
                "caching": compute.CachingTypes.READ_WRITE,
                "createOption": "FromImage",
                "managedDisk": compute.ManagedDiskParametersArgs(
                    storage_account_type="Standard_LRS",
                ),
                "name": "myVMosdisk",
            },
        ),
    )

    # Once the machine is created, fetch its IP address and DNS hostname
    vm_address = vm.id.apply(
        lambda id: network.get_public_ip_address_output(
            resource_group_name=resource_group.name,
            public_ip_address_name=public_ip.name,
        )
    )

    # Export the VM's hostname, public IP address, HTTP URL, and SSH private key
    pulumi.export(
        "ip",
        vm_address.ip_address
    )
    pulumi.export(
        "hostname",
        vm_address.dns_settings.apply(
            lambda settings: settings.fqdn
        )
    )

    # pulumi.export(
    #     "privatekey",
    #     ssh_key.private_key_openssh,
    # )

def create_bucket(user_email, bucket_id, hashed_bucket_name, region, bucket_type):
    def create_pulumi_program():
        resource_group_name = f"rg-{hashed_bucket_name}"
        resource_group = resources.ResourceGroup("my-Resource-Group", location=region, resource_group_name=resource_group_name)
        
        # Create an Azure storage account
        storage_account = storage.StorageAccount("storage", 
                                                resource_group_name=resource_group.name,
                                                sku=storage.SkuArgs(
                                                    name=storage.SkuName.STANDARD_LRS
                                                    ),
                                                allow_blob_public_access=True,
                                                location=region,
                                                # allow_shared_key_access=True,
                                                # account_tier="Standard",
                                                kind=storage.Kind.STORAGE_V2
                                                )
        # Create a storage container
        storage_container = storage.BlobContainer(hashed_bucket_name, 
                                                resource_group_name=resource_group.name,
                                                account_name=storage_account.name)
        
        # # Create a storage blob using the storage account and container
        # storage_blob = storage.Blob(hashed_bucket_name, 
        #                             account_name=storage_account.name,
        #                             container_name=storage_container.name,
        #                             type=storage.BlobType.BLOCK,
        #                             resource_group_name=resource_group.name)


        # Retrieve the primary storage account key
        async def get_primary_storage_key(args):
            keys = await storage.list_storage_account_keys(resource_group_name=args[0], account_name=args[1])
            return keys.keys[0].value

        primary_storage_key = pulumi.Output.all(resource_group.name, storage_account.name).apply(get_primary_storage_key)
        # Construct the Blob Container URL
        blob_container_url = pulumi.Output.concat(
            "https://",
            storage_account.name,
            ".blob.core.windows.net/",
            storage_container.name
        )
        
        # pulumi.export("endpoint", storage_container.url)
        # pulumi.export("endpoint", storage_account.primary_endpoints['blob'])
        pulumi.export("endpoint", blob_container_url)
        pulumi.export("access_key", primary_storage_key)
        pulumi.export("secret_key", storage_account.private_endpoint_connections)

    print('Creating stack')
    stack = auto.create_or_select_stack(stack_name = hashed_bucket_name,
                                        project_name = user_email,
                                        program = create_pulumi_program)

    stack.set_config("azure-native:environment", auto.ConfigValue("public"))
    stack.set_config("azure-native:clientId", auto.ConfigValue(_azure_client_id))
    stack.set_config("azure-native:clientSecret", auto.ConfigValue(_azure_client_secret, secret=True))
    stack.set_config("azure-native:tenantId", auto.ConfigValue(_azure_tenant_id))
    stack.set_config("azure-native:subscriptionId", auto.ConfigValue(_azure_subscription_id))
    stack.set_config("azure-native:location", auto.ConfigValue(region))
    
    up_res = stack.up()
    
    print('Stack created successfully.')
    
    return {
            "endpoint": up_res.outputs.get("endpoint").value,
            "user_id": user_email,
            # "access_key": access_key,
            "access_key": up_res.outputs.get("access_key").value,
            "secret_key": up_res.outputs.get("secret_key").value,
            "status": "active"
    }

def delete_bucket(user_email, hashed_bucket_name):
    def delete_pulumi_program():
        # Delete the Pulumi program resources
        resource_group_name = f"rg-{hashed_bucket_name}"
        # resource_group = resources.ResourceGroup.get("my-Resource-Group", resource_group_name=resource_group_name)
        # resource_group.delete()
        
    print('Deleting stack')
    try:
        stack = auto.select_stack(stack_name=hashed_bucket_name, project_name=user_email, program=delete_pulumi_program)
        stack.destroy()
        
        qualified_name = f"{user_email}/{hashed_bucket_name}"
        stack.workspace.remove_stack(hashed_bucket_name)

        print('Stack deleted successfully.')

        return True
    except Exception as e:
        print("ERROR", "[AzureDriver][delete_bucket] unexpected exception : e = {}".format(e))
        return False

result = create_bucket('nidhal123', 'bucket_id', 'blob123', 'westeurope','STORAGE_V2')
# result = delete_bucket('nidhal123', 'blob123')
print(result)
