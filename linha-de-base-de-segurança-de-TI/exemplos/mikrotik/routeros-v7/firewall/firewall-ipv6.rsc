# RouterOS v7 — Firewall Baseline IPv6
# Padrão de comentários: ORIGEM_DESTINO_SERVICO_ACAO
# Ajuste: <WINBOX_PORT>, <SSH_PORT> e listas

########################################
# 1) ADDRESS LISTS — IPv6 (mantendo base do seu script)
########################################
/ipv6 firewall address-list
add list=bad_ipv6 address=::/128 comment="ANY_ANY_BOGON_BLK (unspecified)"
add list=bad_ipv6 address=::1/128 comment="ANY_ANY_BOGON_BLK (loopback)"
add list=bad_ipv6 address=fec0::/10 comment="ANY_ANY_BOGON_BLK (site-local)"
add list=bad_ipv6 address=::ffff:0.0.0.0/96 comment="ANY_ANY_BOGON_BLK (v4-mapped)"
add list=bad_ipv6 address=::/96 comment="ANY_ANY_BOGON_BLK (v4-compat)"
add list=bad_ipv6 address=100::/64 comment="ANY_ANY_BOGON_BLK (discard-only)"
add list=bad_ipv6 address=2001:db8::/32 comment="ANY_ANY_BOGON_BLK (documentation)"
add list=bad_ipv6 address=3ffe::/16 comment="ANY_ANY_BOGON_BLK (6bone)"

########################################
# 2) FILTER — INPUT (roteador)
########################################
/ipv6 firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="ANY_FW_STATEFUL_ALW"
add chain=input action=accept protocol=icmpv6 comment="ANY_FW_ICMPV6_ALW"

# DHCPv6 client (se usa PD)
add chain=input action=accept protocol=udp dst-port=546 src-address=fe80::/16 comment="LAN_FW_DHCPV6_PD_ALW"

# IPsec (se usa)
add chain=input action=accept protocol=udp dst-port=500,4500 comment="ANY_FW_IKE_NATT_ALW"
add chain=input action=accept protocol=ipsec-ah comment="ANY_FW_IPSEC_AH_ALW"
add chain=input action=accept protocol=ipsec-esp comment="ANY_FW_IPSEC_ESP_ALW"  ;;; CORRIGIDO

# Gestão IPv6 (somente se você realmente expõe gestão em IPv6 — senão, remova)
# Ideal: criar /ipv6 firewall address-list list=MGMT6-ALLOWED ...
# add chain=input action=accept protocol=tcp dst-port=<WINBOX_PORT> src-address-list=MGMT6-ALLOWED comment="WAN_FW_WINBOX_ALW"
# add chain=input action=accept protocol=tcp dst-port=<SSH_PORT> src-address-list=MGMT6-ALLOWED comment="WAN_FW_SSH_ALW"

# Default deny: tudo que NÃO vem de LAN
add chain=input action=drop in-interface-list=!LAN comment="WAN_FW_ANY_BLK"

########################################
# 3) FILTER — FORWARD (tráfego roteado)
########################################
/ipv6 firewall filter
add chain=forward action=accept connection-state=established,related,untracked comment="ANY_ANY_STATEFUL_ALW"
add chain=forward action=drop connection-state=invalid comment="ANY_ANY_INVALID_BLK"
add chain=forward action=accept protocol=icmpv6 comment="ANY_ANY_ICMPV6_ALW"

# Default deny: tráfego novo vindo de fora para LAN
add chain=forward action=drop in-interface-list=!LAN comment="WAN_LAN_ANY_BLK"

########################################
# 4) RAW — IPv6 (bogons e multicast)
########################################
/ipv6 firewall raw
add chain=prerouting action=drop src-address-list=bad_ipv6 comment="ANY_ANY_BOGON_SRC_BLK"
add chain=prerouting action=drop dst-address-list=bad_ipv6 comment="ANY_ANY_BOGON_DST_BLK"
add chain=prerouting action=accept protocol=icmpv6 comment="ANY_ANY_ICMPV6_ALW"
add chain=prerouting action=accept dst-address=ff02::/16 comment="ANY_ANY_MCAST_LINKLOCAL_ALW"
add chain=prerouting action=drop dst-address=ff00::/8 comment="ANY_ANY_MCAST_OTHER_BLK"
