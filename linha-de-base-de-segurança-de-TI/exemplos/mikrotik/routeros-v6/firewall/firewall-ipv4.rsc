# MikroTik RouterOS v6 — Baseline Firewall IPv4
# Padrão de comentários: ORIGEM_DESTINO_SERVICO_ACAO
# Ajuste estes placeholders:
# - <WINBOX_PORT> (default 8291)
# - <SSH_PORT> (default 22)
# - <MGMT_IP_OU_REDE> (ex: 192.168.88.0/24 ou seu IP fixo)

########################################
# 1) Interface Lists (WAN/LAN/MGMT)
########################################
/interface list
add name=WAN comment="WAN interfaces"
add name=LAN comment="LAN interfaces"
add name=MGMT comment="Management interfaces (opcional)"

/interface list member
# EXEMPLOS (AJUSTE):
# add list=WAN interface=ether1
# add list=LAN interface=bridge
# add list=MGMT interface=bridge

########################################
# 2) Address Lists (Gestão / Monitoramento)
########################################
/ip firewall address-list
add list=MGMT-ALLOWED address=<MGMT_IP_OU_REDE> comment="MGMT_FW_MGMT_ALLOWED_ALW"

########################################
# 3) FILTER — INPUT (Protege o roteador)
########################################
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="ANY_FW_STATEFUL_ALW"
add chain=input action=drop connection-state=invalid comment="ANY_FW_INVALID_BLK"

# Anti Portscan (WAN -> FW) — adiciona IP em lista e bloqueia
/ip firewall filter
add chain=input action=add-src-to-address-list in-interface-list=WAN protocol=tcp psd=21,3s,3,1 \
  address-list=PORTSCAN address-list-timeout=4w2d comment="WAN_FW_PORTSCAN_TCP_LOG"
add chain=input action=add-src-to-address-list in-interface-list=WAN protocol=udp psd=21,3s,3,1 \
  address-list=PORTSCAN address-list-timeout=4w2d comment="WAN_FW_PORTSCAN_UDP_LOG"
add chain=input action=drop src-address-list=PORTSCAN in-interface-list=WAN comment="WAN_FW_PORTSCAN_BLK"

# Gestão (apenas IPs permitidos)
/ip firewall filter
add chain=input action=accept in-interface-list=WAN protocol=tcp dst-port=<WINBOX_PORT> src-address-list=MGMT-ALLOWED \
  comment="WAN_FW_WINBOX_ALW" log=yes log-prefix="WAN_FW_WINBOX_ALW"
add chain=input action=accept in-interface-list=WAN protocol=tcp dst-port=<SSH_PORT> src-address-list=MGMT-ALLOWED \
  comment="WAN_FW_SSH_ALW" log=yes log-prefix="WAN_FW_SSH_ALW"

# DHCP (LAN -> FW)
ip firewall filter add chain=input action=accept in-interface-list=LAN protocol=udp dst-port=67,68 comment="LAN_FW_DHCP_ALW"

# DNS no roteador (SÓ se você usa o MikroTik como DNS)
# Se NÃO usa, REMOVA estas regras.
/ip firewall filter
add chain=input action=accept in-interface-list=LAN protocol=udp dst-port=53 comment="LAN_FW_DNS_UDP_ALW"
add chain=input action=accept in-interface-list=LAN protocol=tcp dst-port=53 comment="LAN_FW_DNS_TCP_ALW"

# ICMP (controle via chain dedicada)
/ip firewall filter
add chain=input action=jump protocol=icmp jump-target=ICMP-CONTROL comment="ANY_FW_ICMP_JMP"

add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=8:0 limit=2,5:packet comment="ANY_FW_ICMP_ECHO_REQ_ALW"
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=0:0-255 limit=30/1m,5:packet comment="ANY_FW_ICMP_ECHO_REP_ALW"
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=11:0-255 limit=30/1m,5:packet comment="ANY_FW_ICMP_TIME_EXC_ALW"
add chain=ICMP-CONTROL action=accept protocol=icmp icmp-options=3:0-255 limit=40/1m,5:packet comment="ANY_FW_ICMP_UNREACH_ALW"
add chain=ICMP-CONTROL action=drop protocol=icmp comment="ANY_FW_ICMP_OTHER_BLK"

# Default deny — tudo que vier da WAN para o roteador
/ip firewall filter
add chain=input action=drop in-interface-list=WAN comment="WAN_FW_ANY_BLK" log=yes log-prefix="WAN_FW_ANY_BLK"

########################################
# 4) FILTER — FORWARD (Tráfego roteado)
########################################
/ip firewall filter
add chain=forward action=accept connection-state=established,related,untracked comment="ANY_ANY_STATEFUL_ALW"
add chain=forward action=drop connection-state=invalid comment="ANY_ANY_INVALID_BLK"

# (Opcional) FastTrack — use somente se você não depende de mangle/queues/contabilidade avançada
# add chain=forward action=fasttrack-connection connection-state=established,related comment="ANY_ANY_FASTTRACK_ALW"

# LAN -> WAN permitido (novo tráfego)
/ip firewall filter
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment="LAN_WAN_ANY_ALW"

# WAN -> LAN bloqueado (novo tráfego)
/ip firewall filter
add chain=forward action=drop in-interface-list=WAN out-interface-list=LAN comment="WAN_LAN_ANY_BLK" log=yes log-prefix="WAN_LAN_ANY_BLK"

########################################
# 5) RAW (pré-conntrack) — redução de ruído/abuso
########################################
/ip firewall raw
# Bloqueia portscan cedo
add chain=prerouting action=drop in-interface-list=WAN src-address-list=PORTSCAN comment="WAN_ANY_PORTSCAN_BLK" log=yes log-prefix="WAN_ANY_PORTSCAN_BLK"

# Não expor DNS do roteador para a Internet
add chain=prerouting action=drop in-interface-list=WAN protocol=udp dst-port=53 comment="WAN_FW_DNS_UDP_BLK"
add chain=prerouting action=drop in-interface-list=WAN protocol=tcp dst-port=53 comment="WAN_FW_DNS_TCP_BLK"
