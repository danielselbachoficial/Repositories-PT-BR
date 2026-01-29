# 🔥 MikroTik RouterOS v6 — Firewall (IPv4 + IPv6)

Este diretório contém uma linha de base de firewall para RouterOS v6, separada em arquivos IPv4 e IPv6.

O objetivo é manter um padrão seguro, rastreável e fácil de auditar.

---

## 🎯 Objetivo

- Proteger o roteador (INPUT)
- Controlar tráfego roteado (FORWARD)
- Reduzir superfície de ataque
- Padronizar nomenclatura de regras
- Facilitar manutenção e revisão

---

## 📌 Padrão de Comentários (Obrigatório)

As regras seguem o padrão:

`ORIGEM_DESTINO_SERVICO_ACAO`

Exemplos:

- `WAN_FW_WINBOX_ALW`
- `LAN_FW_DNS_UDP_ALW`
- `WAN_LAN_ANY_BLK`

Siglas usadas:
- Origem/Destino: `LAN`, `WAN`, `DMZ`, `VPN`, `MGMT`, `SOC`
- Equipamento: `FW`
- Ações: `ALW`, `BLK`, `LOG`, `REJ`

---

## 📂 Arquivos

- `firewall-ipv4.rsc`  
  Baseline IPv4 (filter + raw quando aplicável)

- `firewall-ipv6.rsc`  
  Baseline IPv6 (filter + raw quando aplicável)

---

## ✅ Checklist antes de aplicar

- [ ] Interface Lists configuradas (`WAN`, `LAN`, `MGMT`)
- [ ] IPs/redes de gestão definidos (`MGMT-ALLOWED`)
- [ ] Portas de gestão revisadas (Winbox/SSH)
- [ ] Confirmado se o roteador será DNS (se não, manter fechado)
- [ ] Testado em janela de mudança com acesso alternativo (console)

---

## 🧪 Aplicação (RouterOS v6)

Importe manualmente (Winbox → Files) ou via terminal:

```rsc
/import file-name=firewall-ipv4.rsc
/import file-name=firewall-ipv6.rsc
