# Terraform Settings Block
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0" # trava na major 4: a 5 pode quebrar o código sem aviso
    }
  }

  # Estado remoto no container tfstate (rg-terraform-base).
  # Os valores são passados pela task Terraform init do pipeline.
  backend "azurerm" {}
}

# Configure the Microsoft Azure Provider
provider "azurerm" {
  features {}

  # Evita que o provider v4 tente registrar dezenas de resource providers na assinatura
  resource_provider_registrations = "none"
}

locals {
  tags = merge(var.tags, {
    "Workspace"     = terraform.workspace
    "GerenciadoPor" = "Terraform"
  })
}

# Create Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.tags
}

# Storage Account que hospeda o site estático
resource "azurerm_storage_account" "site" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  tags = local.tags
}

# No provider v4 o site estático virou um recurso próprio
resource "azurerm_storage_account_static_website" "site" {
  storage_account_id = azurerm_storage_account.site.id
  index_document     = "index.html"
  error_404_document = "404.html"
}
