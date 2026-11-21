# Provisionamento de Resource Group na Azure com Terraform e Azure DevOps

Projeto prático do curso **Fundamentos de DevOps** da DIO. O pipeline cria na Azure um Resource Group com tags, uma Storage Account e um site estático, usando Terraform e CI/CD no Azure DevOps.

## Estrutura

```
formacao-devops-fundamentals/
├── azure-pipelines.yml        # CI: fmt, init, validate e publicação do artefato
├── codigoTerraform/
│   ├── site.tf                # provider, backend remoto, RG, Storage e site estático
│   ├── variables.tf           # região, nomes e tags
│   ├── outputs.tf             # nome do RG, tags e URL do site
│   └── .gitignore             # impede tfstate e .terraform no Git
└── relatorio-validacao.pdf    # relatório com as evidências
```

## Fluxo

```
GitHub (main) ──► CI-Terraform (Build) ──► artefato "terraform"
                                                │
                                                ▼
                               CD-Terraform (Release): init ► plan ► apply
                                                │   Service Principal app-devops-dio
                                                ▼
                    Azure: rg-devopsdio-lab-brs  +  tfstate em rg-terraform-base
```

## Personalização em relação ao código base

| Item | Código base | Este projeto |
|---|---|---|
| Região | westeurope fixa | brazilsouth via variável |
| Resource Group | rg-auladevops-002 | rg-devopsdio-lab-brs |
| Storage do site | staccdevopsrg21605 | stsitedevopsdsf2611 |
| Tags | 4 tags da aula | 5 tags próprias + Workspace + GerenciadoPor |
| Provider azurerm | >= 2.0 | ~> 4.0 |
| HTTPS | enable_https_traffic_only | https_traffic_only_enabled |
| Site estático | bloco na storage | recurso azurerm_storage_account_static_website |
| Estado | tfstate local no repositório | backend remoto em blob, tfstate removido do Git |
| Segurança | sem ajustes | TLS 1.2 e sem acesso público a blobs |
| Saídas | nenhuma | outputs.tf com nome do RG, tags e URL do site |

## Problema encontrado

O `terraform init` do Release falhou com erro 403 (AuthorizationPermissionMismatch) ao acessar o container `tfstate`. A tarefa Terraform usa autenticação Entra ID no backend, e a role Contributor não dá acesso aos dados do blob. A correção foi atribuir ao Service Principal a role **Storage Blob Data Contributor** somente na Storage Account do backend.

## Segurança

- Nenhuma credencial no repositório. O segredo do Service Principal fica apenas na Service Connection.
- O valor do segredo foi ocultado nos prints.
- O Resource Group de laboratório foi excluído após a coleta das evidências.

## Autor

Daniel Selbach Figueiró
