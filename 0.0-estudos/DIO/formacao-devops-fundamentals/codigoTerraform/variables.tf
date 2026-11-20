variable "location" {
  description = "Região da Azure onde os recursos serão criados."
  type        = string
  default     = "brazilsouth"
}

variable "resource_group_name" {
  description = "Nome do Resource Group criado pelo pipeline."
  type        = string
  default     = "rg-devopsdio-lab-brs"
}

variable "storage_account_name" {
  description = "Nome da Storage Account do site (3-24 caracteres, minúsculos e números, único na Azure)."
  type        = string
  default     = "stsitedevopsdsf2611"

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Use de 3 a 24 caracteres, apenas letras minúsculas e números."
  }
}

variable "tags" {
  description = "Tags aplicadas a todos os recursos."
  type        = map(string)
  default = {
    "Ambiente"    = "Laboratorio"
    "Integracao"  = "Azure DevOps CI-CD"
    "Projeto"     = "DIO Fundamentos de DevOps"
    "Responsavel" = "Daniel Selbach Figueiro"
    "CentroCusto" = "Estudos"
  }
}
