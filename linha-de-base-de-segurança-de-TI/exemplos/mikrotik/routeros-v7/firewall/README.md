# 🔥 MikroTik RouterOS v7 — Baseline Firewall (IPv4 + IPv6)

Este diretório contém uma linha de base de firewall para RouterOS v7, organizada para:

- rastreabilidade (comentários padronizados)
- mínimo privilégio
- clareza operacional
- revisão e auditoria

## Padrão de comentários (obrigatório)
As regras seguem o padrão:

`ORIGEM_DESTINO_SERVICO_ACAO`

Exemplos:
- `WAN_FW_WINBOX_ALW`
- `LAN_WAN_DNS_ALW`
- `WAN_FW_ANY_BLK`

## Siglas utilizadas
- `LAN`, `WAN`, `DMZ`, `VPN`, `MGMT`
- `FW` (Firewall/Router)
- `ALW` (Allow), `BLK` (Block), `LOG` (Log), `REJ` (Reject)

## Antes de aplicar (checklist)
- [ ] Ajustar as interfaces nas Interface Lists (WAN/LAN/MGMT)
- [ ] Ajustar portas de gestão (Winbox/SSH) e listas de origem permitida
- [ ] Confirmar se o router atuará como DNS (senão, feche DNS no INPUT)
- [ ] Aplicar em janela de mudança e manter acesso físico/console

## Arquivos
- `firewall-ipv4.rsc`
- `firewall-ipv6.rsc`
