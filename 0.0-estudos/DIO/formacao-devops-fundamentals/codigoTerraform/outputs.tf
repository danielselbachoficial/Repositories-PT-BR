output "resource_group_name" {
  description = "Nome do Resource Group criado."
  value       = azurerm_resource_group.rg.name
}

output "resource_group_tags" {
  description = "Tags aplicadas ao Resource Group."
  value       = azurerm_resource_group.rg.tags
}

output "site_url" {
  description = "Endereço do site estático."
  value       = azurerm_storage_account.site.primary_web_endpoint
}
