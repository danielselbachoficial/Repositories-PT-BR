# RouterOS v7 — Firewall Baseline IPv4
# Padrão de comentários: ORIGEM_DESTINO_SERVICO_ACAO
# Ajuste os placeholders: <WINBOX_PORT>, <SSH_PORT>, listas e interfaces

########################################
# 1) INTERFACE LISTS (padronizadas)
########################################
/interface list
add name=WAN comment="WAN interfaces"
add name=LAN comment="LAN interfaces"
add name=MGMT comment="Management interfaces (opcional)"

########################################
# 2) ADDRESS LISTS (exemplos)
########################################
/ip firewall address-list
add list=MGMT-ALLOWED address=<SEU_IP_OU_REDE> comment="IPs/redes autorizadas a gerenciar"
add list=MONITORING address=<SEU_ZABBIX_OU_REDE> comment="Monitoramento autorizado"
# add list=LAN-NETS address=<SUA_REDE_LAN> comment="Redes internas"

########################################
# 3) FILTER — INPUT (protege o roteador)
########################################
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="ANY_FW_STATEFUL_ALW"
add chain=input action=drop connection-state=invalid comment="ANY_FW_INVALID_BLK"

# Portscan detection (WAN -> FW)
/ip firewall filter
add chain=input action=add-src-to-address-list in-interface-list=WAN protocol=tcp psd=21,3s,3,1 \
  address-list=PORTSCAN address-list-timeout=4w2d comment="WAN_FW_PORTSCAN_TCP_LOG"
add chain=input action=add-src-to-address-list in-interface-list=WAN protocol=udp psd=21,3s,3,1 \
  address-list=PORTSCAN address-list-timeout=4w2d comment="WAN_FW_PORTSCAN_UDP_LOG"
add chain=input action=drop src-address-list=PORTSCAN in-interface-list=WAN comment="WAN_FW_PORTSCAN_BLK"

# Gestão (somente de fontes permitidas)
add chain=input action=accept in-interface-list=WAN protocol=tcp dst-port=<WINBOX_PORT> src-address-list=MGMT-ALLOWED \
  comment="WAN_FW_WINBOX_ALW" log=yes log-prefix="WAN_FW_WINBOX_ALW"
add chain=input action=accept in-interface-list=WAN protocol=tcp dst-port=<SSH_PORT> src-address-list=MGMT-ALLOWED \
  comment="WAN_FW_SSH_ALW" log=yes log-prefix="WAN_FW_SSH_ALW"

# DHCP (LAN -> FW)
/ip firewall filter
add chain=input action=accept in-interface-list=LAN protocol=udp dst-port=67,68 comment="LAN_FW_DHCP_ALW"

# DNS no roteador (SÓ se você realmente usa o MikroTik como DNS)
# Se NÃO usa DNS no router, REMOVA estas duas regras.
/ip firewall filter add chain=input action=accept in-interface-list=LAN protocol=udp dst-port=53 comment="LAN_FW_DNS_UDP_ALW"
/ip firewall filter add chain=input action=accept in-interface-list=LAN protocol=tcp dst-port=53 comment="LAN_FW_DNS_TCP_ALW"

# WireGuard (WAN -> FW) — se usar
# /ip firewall filter add chain=input action=accept in-interface-list=WAN protocol=udp dst-port=<WG_PORT> comment="WAN_FW_WG_ALW"

# SNMP (monitoramento -> FW) — se usar
# /ip firewall filter add chain=input action=accept protocol=udp dst-port=<SNMP_PORT> src-address-list=MONITORING comment="MON_FW_SNMP_ALW"

# ICMP control
/ip firewall filter add chain=input action=jump protocol=icmp jump-target=ICMP-CONTROL comment="ANY_FW_ICMP_JMP"

/ip firewall filter
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=8:0 limit=2,5:packet comment="ANY_FW_ICMP_ECHO_REQ_ALW"
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=0:0-255 limit=30/1m,5:packet comment="ANY_FW_ICMP_ECHO_REP_ALW"
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=11:0-255 limit=30/1m,5:packet comment="ANY_FW_ICMP_TIME_EXC_ALW"
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=3:0-255 limit=40/1m,5:packet comment="ANY_FW_ICMP_UNREACH_ALW"
add chain=ICMP-CONTROL action=drop protocol=icmp comment="ANY_FW_ICMP_OTHER_BLK"

# Default deny (WAN -> FW)
/ip firewall filter
add chain=input action=drop in-interface-list=WAN comment="WAN_FW_ANY_BLK" log=yes log-prefix="WAN_FW_ANY_BLK"

########################################
# 4) FILTER — FORWARD (tráfego passando pelo roteador)
########################################
/ip firewall filter
add chain=forward action=accept connection-state=established,related,untracked comment="ANY_ANY_STATEFUL_ALW"
add chain=forward action=drop connection-state=invalid comment="ANY_ANY_INVALID_BLK"

# Permitir LAN -> WAN (novo tráfego)
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment="LAN_WAN_ANY_ALW"

# (Opcional) bloquear LAN -> LAN se você segmenta por VLANs e quer controle explícito
# add chain=forward action=drop in-interface-list=LAN out-interface-list=LAN comment="LAN_LAN_ANY_BLK"

# Default deny (WAN -> LAN) novo tráfego
add chain=forward action=drop in-interface-list=WAN out-interface-list=LAN comment="WAN_LAN_ANY_BLK" log=yes log-prefix="WAN_LAN_ANY_BLK"

########################################
# 5) RAW (mantendo a ideia do seu script, mas padronizado)
########################################
/ip firewall raw
add chain=prerouting action=accept protocol=icmp limit=50,5:packet comment="ANY_ANY_ICMP_RATE_ALW"
add chain=prerouting action=drop in-interface-list=WAN src-address-list=PORTSCAN comment="WAN_ANY_PORTSCAN_BLK" log=yes log-prefix="WAN_ANY_PORTSCAN_BLK"

# DNS vindo da WAN para o roteador (não expor)
add chain=prerouting action=drop in-interface-list=WAN protocol=udp dst-port=53 comment="WAN_FW_DNS_UDP_BLK"
add chain=prerouting action=drop in-interface-list=WAN protocol=tcp dst-port=53 comment="WAN_FW_DNS_TCP_BLK"
