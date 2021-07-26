# Online Python compiler (interpreter) to run Python online.
# Write Python 3 code in this online editor and run it.
new_dic = {}

#T1
new_dic["ingress_port_mapping"] = {}
new_dic["ingress_port_mapping"]["M"] = ["standard_metadata.ingress_port"]
new_dic["ingress_port_mapping"]["A"] = ["ingress_metadata.ifindex","ingress_metadata.port_type"]

#T2
new_dic["validate_outer_ethernet"] = {}
new_dic["validate_outer_ethernet"]["M"] = ["ethernet.srcAddr“,”ethernet.dstAddr","vlan_tag_[0]","vlan_tag_[1]"]
new_dic["validate_outer_ethernet"]["A"] = ["ingress_metadata.drop_flag","ingress_metadata.drop_reason","l2_metadata.lkp_pkt_type","l2_metadata.lkp_mac_type","l2_metadata.lkp_pcp"]

#T3
new_dic["validate_outer_ipv4_packet"] = {}
new_dic["validate_outer_ipv4_packet"]["M"] = ["ipv4.version","ipv4.ttl","ipv4.srcAddr"]
new_dic["validate_outer_ipv4_packet"]["A"] = ["l3_metadata.lkp_ip_type","l3_metadata.lkp_dscp","l3_metadata.lkp_ip_version","ingress_metadata.drop_flag","ingress_metadata.drop_reason"]

#T4
new_dic["validate_outer_ipv6_packet"] = {}
new_dic["validate_outer_ipv6_packet"]["M"] = ["ipv6.version","ipv6.hopLimit","ipv6.srcAddr"]
new_dic["validate_outer_ipv6_packet"]["A"] = ["l3_metadata.lkp_ip_type","l3_metadata.lkp_dscp","l3_metadata.lkp_ip_version","ingress_metadata.drop_flag","ingress_metadata.drop_reason"]

#T5
new_dic["validate_mpls_packet"] = {}
new_dic["validate_mpls_packet"]["M"] = ["mpls[0].bos","mpls[0].label","mpls[1].label","mpls[1].bos","mpls[2].label","mpls[2].bos"]
new_dic["validate_mpls_packet"]["A"] = ["tunnel_metadata.mpls_label","tunnel_metadata.mpls_exp"]

#T6
new_dic["switch_config_params"] = {}
new_dic["switch_config_params"]["M"] = [""]
new_dic["switch_config_params"]["A"] = ["i2e_metadata.ingress_tstamp","ingress_metadata.ingress_port","l2_metadata.same_if_check","standard_metadata.egress_spec","ingress_metadata.sflow_take_sample"]

#T7
new_dic["port_vlan_mapping"] = {}
new_dic["port_vlan_mapping"]["M"] = ["ingress_metadata.ifindex","vlan_tag_[0]","vlan_tag_[0].vid","vlan_tag_[1]","vlan_tag_[1].vid"]
new_dic["port_vlan_mapping"]["A"] = ["ingress_metadata.bd","ingress_metadata.outer_bd","acl_metadata.bd_label","l2_metadata.stp_group","l2_metadata.bd_stats_idx","l2_metadata.learning_enabled","l3_metadata.vrf","ipv4_metadata.ipv4_unicast_enabled","ipv6_metadata.ipv6_unicast_enabled","ipv4_metadata.ipv4_urpf_mode","ipv6_metadata.ipv6_urpf_mode","l3_metadata.rmac_group","multicast_metadata.igmp_snooping_enabled","multicast_metadata.mld_snooping_enabled","multicast_metadata.ipv4_multicast_enabled","multicast_metadata.ipv6_multicast_enabled","multicast_metadata.bd_mrpf_group","multicast_metadata.ipv4_mcast_key_type","multicast_metadata.ipv4_mcast_key","multicast_metadata.ipv6_mcast_key_type","multicast_metadata.ipv6_mcast_key","l2_metadata.port_vlan_mapping_miss"]

#T8
new_dic["adjust_lkp_fields"] = {}
new_dic["adjust_lkp_fields"]["M"] = ["ipv4","ipv6"]
new_dic["adjust_lkp_fields"]["A"] = ["l2_metadata.lkp_mac_sa","l2_metadata.lkp_mac_da","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","l3_metadata.lkp_ip_ttl","l3_metadata.lkp_l4_sport","l3_metadata.lkp_l4_dport","ipv6_metadata.lkp_ipv6_sa","ipv6_metadata.lkp_ipv6_da"]

#T9
new_dic["spanning_tree"] = {}
new_dic["spanning_tree"]["M"] = ["ingress_metadata.ifindex","l2_metadata.stp_group"]
new_dic["spanning_tree"]["A"] = ["l2_metadata.stp_state"]

#T10
new_dic["ingress_qos_map_dscp"] = {}
new_dic["ingress_qos_map_dscp"]["M"] = ["qos_metadata.ingress_qos_group","l3_metadata.lkp_dscp"]
new_dic["ingress_qos_map_dscp"]["A"] = ["qos_metadata.lkp_tc","meter_metadata.packet_color"]

#T11
new_dic["ingress_qos_map_pcp"] = {}
new_dic["ingress_qos_map_pcp"]["M"] = ["qos_metadata.ingress_qos_group","l2_metadata.lkp_pcp"]
new_dic["ingress_qos_map_pcp"]["A"] = ["qos_metadata.lkp_tc","meter_metadata.packet_color"]

#T12
new_dic["ipsg"] = {}
new_dic["ipsg"]["M"] = ["ingress_metadata.ifindex","ingress_metadata.bd","l2_metadata.lkp_mac_sa","ipv4_metadata.lkp_ipv4_sa"]
new_dic["ipsg"]["A"] = [""]

#T13
new_dic["ipsg_permit_special"] = {}
new_dic["ipsg_permit_special"]["M"] = ["l3_metadata.lkp_ip_proto","l3_metadata.lkp_l4_dport","ipv4_metadata.lkp_ipv4_da"]
new_dic["ipsg_permit_special"]["A"] = ["security_metadata.ipsg_check_fail"]

#T14
new_dic["int_source"] = {}
new_dic["int_source"]["M"] = ["int_header","ipv4","ipv4_metadata.lkp_ipv4_da","ipv4_metadata.lkp_ipv4_sa","inner_ipv4","inner_ipv4.dstAddr","inner_ipv4.srcAddr"]
new_dic["int_source"]["A"] = ["int_metadata_i2e.source"]

#T15
new_dic["int_terminate"] = {}
new_dic["int_terminate"]["M"] = ["int_header","ipv4","ipv4_metadata.lkp_ipv4_da","inner_ipv4","inner_ipv4.dstAddr"]
new_dic["int_terminate"]["A"] = ["int_metadata.insert_byte_cnt","int_metadata.gpe_int_hdr_len","int_metadata_i2e.sink"]

#T16
new_dic["int_sink_update_outer"] = {}
new_dic["int_sink_update_outer"]["M"] = ["vxlan_gpe_int_header“,”ipv4","int_metadata_i2e.sink"]
new_dic["int_sink_update_outer"]["A"] = ["vxlan_gpe.next_proto","vxlan_gpe_int_header","ipv4.totalLen","udp.length_"]

#T17
new_dic["sflow_ingress"] = {}
new_dic["sflow_ingress"]["M"] = ["ingress_metadata.ifindex","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","sflow"]
new_dic["sflow_ingress"]["A"] = ["ingress_metadata.sflow_take_sample","sflow_metadata.sflow_session_id"]

#T18
new_dic["sflow_ing_take_sample"] = {}
new_dic["sflow_ing_take_sample"]["M"] = ["ingress_metadata.sflow_take_sample","sflow_metadata.sflow_session_id"]
new_dic["sflow_ing_take_sample"]["A"] = ["i2e_metadata.mirror_session_id"]

#T19
new_dic["fabric_ingress_dst_lkp"] = {}
new_dic["fabric_ingress_dst_lkp"]["M"] = ["fabric_header.dstDevice"]
new_dic["fabric_ingress_dst_lkp"]["A"] = ["standard_metadata.egress_spec","egress_metadata.bypass","intrinsic_metadata.mcast_grp","ethernet.etherType","fabric_metadata.fabric_header_present","fabric_metadata.dst_device","fabric_metadata.dst_port","tunnel_metadata.tunnel_terminate","tunnel_metadata.ingress_tunnel_type","l3_metadata.nexthop_index","l3_metadata.routed","l3_metadata.outer_routed"]

#T20
new_dic["fabric_ingress_src_lkp"] = {}
new_dic["fabric_ingress_src_lkp"]["M"] = ["fabric_header_multicast.ingressIfindex"]
new_dic["fabric_ingress_src_lkp"]["A"] = [""]

#T21
new_dic["native_packet_over_fabric"] = {}
new_dic["native_packet_over_fabric"]["M"] = ["ipv4","ipv6"]
new_dic["native_packet_over_fabric"]["A"] = ["l2_metadata.lkp_mac_sa","l2_metadata.lkp_mac_da","l2_metadata.lkp_mac_type","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","l3_metadata.lkp_l4_sport","l3_metadata.lkp_l4_dport","ipv6_metadata.lkp_ipv6_sa","ipv6_metadata.lkp_ipv6_da"]

#T22
new_dic["outer_rmac"] = {}
new_dic["outer_rmac"]["M"] = ["l3_metadata.rmac_group","ethernet.dstAddr"]
new_dic["outer_rmac"]["A"] = ["l3_metadata.rmac_hit"]

#T23
new_dic["outer_ipv4_multicast"] = {}
new_dic["outer_ipv4_multicast"]["M"] = ["multicast_metadata.ipv4_mcast_key_type","multicast_metadata.ipv4_mcast_key","ipv4.srcAddr","ipv4.dstAddr"]
new_dic["outer_ipv4_multicast"]["A"] = ["intrinsic_metadata.mcast_grp","multicast_metadata.outer_mcast_route_hit","multicast_metadata.mcast_rpf_group","fabric_metadata.dst_device","tunnel_metadata.tunnel_terminate"]

#T24
new_dic["outer_ipv4_multicast_star_g"] = {}
new_dic["outer_ipv4_multicast_star_g"]["M"] = ["multicast_metadata.ipv4_mcast_key_type","multicast_metadata.ipv4_mcast_key","ipv4.dstAddr"]
new_dic["outer_ipv4_multicast_star_g"]["A"] = ["multicast_metadata.outer_mcast_mode","intrinsic_metadata.mcast_grp","multicast_metadata.outer_mcast_route_hit","multicast_metadata.mcast_rpf_group","fabric_metadata.dst_device","tunnel_metadata.tunnel_terminate"]

#T25
new_dic["outer_ipv6_multicast"] = {}
new_dic["outer_ipv6_multicast"]["M"] = ["multicast_metadata.ipv6_mcast_key_type","multicast_metadata.ipv6_mcast_key","ipv6.srcAddr","ipv6.dstAddr"]
new_dic["outer_ipv6_multicast"]["A"] = ["intrinsic_metadata.mcast_grp","multicast_metadata.outer_mcast_route_hit","multicast_metadata.mcast_rpf_group","fabric_metadata.dst_device","tunnel_metadata.tunnel_terminate"]

#T26
new_dic["outer_ipv6_multicast_star_g"] = {}
new_dic["outer_ipv6_multicast_star_g"]["M"] = ["multicast_metadata.ipv6_mcast_key_type","multicast_metadata.ipv6_mcast_key","ipv6.dstAddr"]
new_dic["outer_ipv6_multicast_star_g"]["A"] = ["multicast_metadata.outer_mcast_mode","intrinsic_metadata.mcast_grp","multicast_metadata.outer_mcast_route_hit","multicast_metadata.mcast_rpf_group","fabric_metadata.dst_device","tunnel_metadata.tunnel_terminate"]

#T27
new_dic["outer_multicast_rpf"] = {}
new_dic["outer_multicast_rpf"]["M"] = ["multicast_metadata.mcast_rpf_group","multicast_metadata.bd_mrpf_group"]
new_dic["outer_multicast_rpf"]["A"] = ["tunnel_metadata.tunnel_terminate","l3_metadata.outer_routed"]

#T28
new_dic["ipv4_src_vtep"] = {}
new_dic["ipv4_src_vtep"]["M"] = ["l3_metadata.vrf","ipv4.srcAddr","tunnel_metadata.ingress_tunnel_type"]
new_dic["ipv4_src_vtep"]["A"] = ["ingress_metadata.ifindex"]

#T29
new_dic["ipv4_dest_vtep"] = {}
new_dic["ipv4_dest_vtep"]["M"] = ["l3_metadata.vrf","ipv4.srcAddr","tunnel_metadata.ingress_tunnel_type"]
new_dic["ipv4_dest_vtep"]["A"] = ["tunnel_metadata.tunnel_terminate","tunnel_metadata.tunnel_vni"]

#T30
new_dic["ipv6_src_vtep"] = {}
new_dic["ipv6_src_vtep"]["M"] = ["l3_metadata.vrf","ipv6.srcAddr","tunnel_metadata.ingress_tunnel_type"]
new_dic["ipv6_src_vtep"]["A"] = ["ingress_metadata.ifindex"]

#T31
new_dic["ipv6_dest_vtep"] = {}
new_dic["ipv6_dest_vtep"]["M"] = ["l3_metadata.vrf","ipv6.dstAddr","tunnel_metadata.ingress_tunnel_type"]
new_dic["ipv6_dest_vtep"]["A"] = ["tunnel_metadata.tunnel_terminate","tunnel_metadata.tunnel_vni"]

#T32
new_dic["mpls"] = {}
new_dic["mpls"]["M"] = ["tunnel_metadata.mpls_label","inner_ipv4","inner_ipv6"]
new_dic["mpls"]["A"] = ["tunnel_metadata.tunnel_terminate","tunnel_metadata.ingress_tunnel_type","ingress_metadata.bd","l2_metadata.lkp_mac_type","l3_metadata.vrf","l2_metadata.lkp_mac_sa","l2_metadata.lkp_mac_da","l3_metadata.lkp_ip_type","l3_metadata.lkp_ip_version","l3_metadata.lkp_dscp","ingress_metadata.egress_ifindex","l3_metadata.fib_nexthop","l3_metadata.fib_nexthop_type","l3_metadata.fib_hit"]

#T33
new_dic["storm_control"] = {}
new_dic["storm_control"]["M"] = ["standard_metadata.ingress_port“,”l2_metadata.lkp_pkt_type"]
new_dic["storm_control"]["A"] = ["meter_metadata.meter_index"]

#T34
new_dic["validate_packet"] = {}
new_dic["validate_packet"]["M"] = ["l2_metadata.lkp_mac_sa","l2_metadata.lkp_mac_da","l3_metadata.lkp_ip_type","l3_metadata.lkp_ip_ttl","l3_metadata.lkp_ip_version","ipv4_metadata.lkp_ipv4_sa","ipv6_metadata.lkp_ipv6_sa"]
new_dic["validate_packet"]["A"] = ["l2_metadata.lkp_pkt_type","ipv6_metadata.ipv6_src_is_link_local","l2_metadata.bd_stats_idx","ingress_metadata.drop_flag","ingress_metadata.drop_reason"]

#T35
new_dic["ingress_l4_src_port"] = {}
new_dic["ingress_l4_src_port"]["M"] = ["l3_metadata.lkp_l4_sport"]
new_dic["ingress_l4_src_port"]["A"] = ["acl_metadata.ingress_src_port_range_id"]

#T36
new_dic["ingress_l4_dst_port"] = {}
new_dic["ingress_l4_dst_port"]["M"] = ["l3_metadata.lkp_l4_dport"]
new_dic["ingress_l4_dst_port"]["A"] = ["acl_metadata.ingress_dst_port_range_id"]

#T37
new_dic["smac"] = {}
new_dic["smac"]["M"] = ["ingress_metadata.bd","l2_metadata.lkp_mac_sa"]
new_dic["smac"]["A"] = ["l2_metadata.l2_src_miss","l2_metadata.l2_src_move"]

#T38
new_dic["dmac"] = {}
new_dic["dmac"]["M"] = ["ingress_metadata.bd","l2_metadata.lkp_mac_da"]
new_dic["dmac"]["A"] = ["openflow_metadata.bmap","openflow_metadata.indexopenflow_metadata.group_id","openflow_metadata.ofvalid","fabric_metadata.etherType","fabric_metadata.ingressPort","fabric_metadata.reason_code","standard_metadata.egress_spec","ingress_metadata.egress_ifindex","l2_metadata.same_if_check","intrinsic_metadata.mcast_grp","fabric_metadata.dst_device","ingress_metadata.egress_ifindex","l2_metadata.l2_redirect","l2_metadata.l2_nexthop","l2_metadata.l2_nexthop_type"]

#T39
new_dic["mac_acl"] = {}
new_dic["mac_acl"]["M"] = ["acl_metadata.if_label","acl_metadata.bd_label","l2_metadata.lkp_mac_sa","l2_metadata.lkp_mac_da","l2_metadata.lkp_mac_type"]
new_dic["mac_acl"]["A"] = ["acl_metadata.acl_deny","acl_metadata.acl_stats_index","meter_metadata.meter_index","fabric_metadata.reason_code","nat_metadata.ingress_nat_mode","intrinsic_metadata.ingress_cos","qos_metadata.lkp_tc","meter_metadata.packet_color","acl_metadata.acl_redirect","acl_metadata.acl_nexthop","acl_metadata.acl_nexthop_type","i2e_metadata.mirror_session_id"]

#T40
new_dic["ip_acl"] = {}
new_dic["ip_acl"]["M"] = ["acl_metadata.if_label","acl_metadata.bd_label","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","acl_metadata.ingress_src_port_range_id","acl_metadata.ingress_dst_port_range_id","tcp.flags","l3_metadata.lkp_ip_ttl"]
new_dic["ip_acl"]["A"] = ["acl_metadata.acl_deny","acl_metadata.acl_stats_index","meter_metadata.meter_index","fabric_metadata.reason_code","nat_metadata.ingress_nat_mode","intrinsic_metadata.ingress_cos","qos_metadata.lkp_tc","meter_metadata.packet_color","acl_metadata.acl_redirect","acl_metadata.acl_nexthop","acl_metadata.acl_nexthop_type","i2e_metadata.mirror_session_id"]

#T41
new_dic["ipv6_acl"] = {}
new_dic["ipv6_acl"]["M"] = ["acl_metadata.if_label","acl_metadata.bd_label","ipv6_metadata.lkp_ipv6_sa","ipv6_metadata.lkp_ipv6_da","l3_metadata.lkp_ip_proto","acl_metadata.ingress_src_port_range_id","acl_metadata.ingress_dst_port_range_id","tcp.flags","l3_metadata.lkp_ip_ttl"]
new_dic["ipv6_acl"]["A"] = ["acl_metadata.acl_deny","acl_metadata.acl_stats_index","meter_metadata.meter_index","fabric_metadata.reason_code","nat_metadata.ingress_nat_mode","intrinsic_metadata.ingress_cos","qos_metadata.lkp_tc","meter_metadata.packet_color","acl_metadata.acl_redirect","acl_metadata.acl_nexthop","acl_metadata.acl_nexthop_type","i2e_metadata.mirror_session_id"]

#T42
new_dic["ipv4_multicast_bridge"] = {}
new_dic["ipv4_multicast_bridge"]["M"] = ["ingress_metadata.bd","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da"]
new_dic["ipv4_multicast_bridge"]["A"] = ["intrinsic_metadata.mcast_grp","tunnel_metadata.tunnel_terminate","fabric_metadata.dst_device"]

#T43
new_dic["ipv4_multicast_bridge_star_g"] = {}
new_dic["ipv4_multicast_bridge_star_g"]["M"] = ["ingress_metadata.bd","ipv4_metadata.lkp_ipv4_da"]
new_dic["ipv4_multicast_bridge_star_g"]["A"] = ["intrinsic_metadata.mcast_grp","tunnel_metadata.tunnel_terminate","fabric_metadata.dst_device"]

#T44
new_dic["ipv6_multicast_bridge"] = {}
new_dic["ipv6_multicast_bridge"]["M"] = ["ingress_metadata.bd","ipv6_metadata.lkp_ipv6_sa","ipv6_metadata.lkp_ipv6_da"]
new_dic["ipv6_multicast_bridge"]["A"] = ["intrinsic_metadata.mcast_grp","tunnel_metadata.tunnel_terminate","fabric_metadata.dst_device"]

#T45
new_dic["ipv6_multicast_bridge_star_g"] = {}
new_dic["ipv6_multicast_bridge_star_g"]["M"] = ["ingress_metadata.bd","ipv6_metadata.lkp_ipv6_da"]
new_dic["ipv6_multicast_bridge_star_g"]["A"] = ["intrinsic_metadata.mcast_grp","tunnel_metadata.tunnel_terminate","fabric_metadata.dst_device"]

#T46
new_dic["multicast_rpf"] = {}
new_dic["multicast_rpf"]["M"] = ["multicast_metadata.mcast_rpf_group","multicast_metadata.bd_mrpf_group"]
new_dic["multicast_rpf"]["A"] = ["l3_metadata.routed","multicast_metadata.multicast_route_mc_index","multicast_metadata.mcast_route_hit","fabric_metadata.dst_device"]

#T47
new_dic["ipv4_racl"] = {}
new_dic["ipv4_racl"]["M"] = ["acl_metadata.bd_label","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","acl_metadata.ingress_src_port_range_id","acl_metadata.ingress_dst_port_range_id"]
new_dic["ipv4_racl"]["A"] = ["acl_metadata.racl_deny","acl_metadata.acl_stats_index","fabric_metadata.reason_code","intrinsic_metadata.ingress_cos","qos_metadata.lkp_tc","meter_metadata.packet_color","acl_metadata.racl_redirect","acl_metadata.racl_nexthop","acl_metadata.racl_nexthop_type"]

#T48
new_dic["ipv4_urpf"] = {}
new_dic["ipv4_urpf"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_sa"]
new_dic["ipv4_urpf"]["A"] = ["l3_metadata.urpf_hit","l3_metadata.urpf_bd_group","l3_metadata.urpf_mode"]

#T49
new_dic["ipv4_urpf_lpm"] = {}
new_dic["ipv4_urpf_lpm"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_sa"]
new_dic["ipv4_urpf_lpm"]["A"] = ["l3_metadata.urpf_hit","l3_metadata.urpf_bd_group","l3_metadata.urpf_mode"]

#T50
new_dic["ipv4_fib"] = {}
new_dic["ipv4_fib"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_da"]
new_dic["ipv4_fib"]["A"] = ["l3_metadata.fib_hit","l3_metadata.fib_nexthop","l3_metadata.fib_nexthop_type"]

#T51
new_dic["ipv4_fib_lpm"] = {}
new_dic["ipv4_fib_lpm"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_da"]
new_dic["ipv4_fib_lpm"]["A"] = ["l3_metadata.fib_hit","l3_metadata.fib_nexthop","l3_metadata.fib_nexthop_type"]

#T52
new_dic["ipv6_racl"] = {}
new_dic["ipv6_racl"]["M"] = ["acl_metadata.bd_label","ipv6_metadata.lkp_ipv6_sa","ipv6_metadata.lkp_ipv6_da","l3_metadata.lkp_ip_proto","acl_metadata.ingress_src_port_range_id","acl_metadata.ingress_dst_port_range_id"]
new_dic["ipv6_racl"]["A"] = ["acl_metadata.racl_deny","acl_metadata.acl_stats_index","fabric_metadata.reason_code","intrinsic_metadata.ingress_cos","qos_metadata.lkp_tc","meter_metadata.packet_color","acl_metadata.racl_redirect","acl_metadata.racl_nexthop","acl_metadata.racl_nexthop_type"]

#T53
new_dic["ipv6_urpf"] = {}
new_dic["ipv6_urpf"]["M"] = ["l3_metadata.vrf","ipv6_metadata.lkp_ipv6_sa"]
new_dic["ipv6_urpf"]["A"] = ["l3_metadata.urpf_hit","l3_metadata.urpf_bd_group","l3_metadata.urpf_mode"]

#T54
new_dic["ipv6_urpf_lpm"] = {}
new_dic["ipv6_urpf_lpm"]["M"] = ["l3_metadata.vrf","ipv6_metadata.lkp_ipv6_sa"]
new_dic["ipv6_urpf_lpm"]["A"] = ["l3_metadata.urpf_hit","l3_metadata.urpf_bd_group","l3_metadata.urpf_mode"]

#T55
new_dic["ipv6_fib"] = {}
new_dic["ipv6_fib"]["M"] = ["l3_metadata.vrf","ipv6_metadata.lkp_ipv6_da"]
new_dic["ipv6_fib"]["A"] = ["l3_metadata.fib_hit","l3_metadata.fib_nexthop","l3_metadata.fib_nexthop_type"]

#T56
new_dic["ipv6_fib_lpm"] = {}
new_dic["ipv6_fib_lpm"]["M"] = ["l3_metadata.vrf","ipv6_metadata.lkp_ipv6_da"]
new_dic["ipv6_fib_lpm"]["A"] = ["l3_metadata.fib_hit","l3_metadata.fib_nexthop","l3_metadata.fib_nexthop_type"]

#T57
new_dic["urpf_bd"] = {}
new_dic["urpf_bd"]["M"] = ["l3_metadata.urpf_bd_group","ingress_metadata.bd"]
new_dic["urpf_bd"]["A"] = ["l3_metadata.urpf_check_fail"]

#T58
new_dic["nat_twice"] = {}
new_dic["nat_twice"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","l3_metadata.lkp_l4_sport","l3_metadata.lkp_l4_dport"]
new_dic["nat_twice"]["A"] = ["nat_metadata.nat_nexthop","nat_metadata.nat_nexthop_type","nat_metadata.nat_rewrite_index","nat_metadata.nat_hit"]

#T59
new_dic["nat_dst"] = {}
new_dic["nat_dst"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","l3_metadata.lkp_l4_dport"]
new_dic["nat_dst"]["A"] = ["nat_metadata.nat_nexthop","nat_metadata.nat_nexthop_type","nat_metadata.nat_rewrite_index","nat_metadata.nat_hit"]

#T60
new_dic["nat_src"] = {}
new_dic["nat_src"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_sa","l3_metadata.lkp_ip_proto","l3_metadata.lkp_l4_sport"]
new_dic["nat_src"]["A"] = ["nat_metadata.nat_rewrite_index"]

#T61
new_dic["nat_flow"] = {}
new_dic["nat_flow"]["M"] = ["l3_metadata.vrf","ipv4_metadata.lkp_ipv4_sa","ipv4_metadata.lkp_ipv4_da","l3_metadata.lkp_ip_proto","l3_metadata.lkp_l4_sport","l3_metadata.lkp_l4_dport"]
new_dic["nat_flow"]["A"] = ["nat_metadata.nat_rewrite_index","nat_metadata.nat_nexthop","nat_metadata.nat_nexthop_type","nat_metadata.nat_hit"]

#T62
new_dic["meter_index"] = {}
new_dic["meter_index"]["M"] = ["meter_metadata.meter_index"]
new_dic["meter_index"]["A"] = [""]

#T63
new_dic["compute_ipv4_hashes"] = {}
new_dic["compute_ipv4_hashes"]["M"] = ["ingress_metadata.drop_flag"]
new_dic["compute_ipv4_hashes"]["A"] = ["hash_metadata.hash1","hash_metadata.hash2"]

#T64
new_dic["compute_ipv6_hashes"] = {}
new_dic["compute_ipv6_hashes"]["M"] = ["ingress_metadata.drop_flag"]
new_dic["compute_ipv6_hashes"]["A"] = ["hash_metadata.hash1","hash_metadata.hash2"]

#T65
new_dic["compute_non_ip_hashes"] = {}
new_dic["compute_non_ip_hashes"]["M"] = ["ingress_metadata.drop_flag"]
new_dic["compute_non_ip_hashes"]["A"] = ["hash_metadata.hash2"]

#T66
new_dic["compute_other_hashes"] = {}
new_dic["compute_other_hashes"]["M"] = ["hash_metadata.hash1"]
new_dic["compute_other_hashes"]["A"] = ["intrinsic_metadata.mcast_hash","hash_metadata.entropy_hash","hash_metadata.hash1"]

#T67
new_dic["meter_action"] = {}
new_dic["meter_action"]["M"] = ["meter_metadata.packet_color","meter_metadata.meter_index"]
new_dic["meter_action"]["A"] = [""]

#T68
new_dic["ingress_bd_stats"] = {}
new_dic["ingress_bd_stats"]["M"] = [""]
new_dic["ingress_bd_stats"]["A"] = ["l2_metadata.bd_stats_idx"]

#T69
new_dic["acl_stats"] = {}
new_dic["acl_stats"]["M"] = [""]
new_dic["acl_stats"]["A"] = ["acl_metadata.acl_stats_index"]

#T70
new_dic["storm_control_stats"] = {}
new_dic["storm_control_stats"]["M"] = ["meter_metadata.packet_color","standard_metadata.ingress_port"]
new_dic["storm_control_stats"]["A"] = [""]

#T71
new_dic["fwd_result"] = {}
new_dic["fwd_result"]["M"] = ["l2_metadata.l2_redirect","acl_metadata.acl_redirect","acl_metadata.racl_redirect","l3_metadata.rmac_hit","l3_metadata.fib_hit","nat_metadata.nat_hit","l2_metadata.lkp_pkt_type","l3_metadata.lkp_ip_type","multicast_metadata.igmp_snooping_enabled","multicast_metadata.mld_snooping_enabled","multicast_metadata.mcast_route_hit","multicast_metadata.mcast_bridge_hit","multicast_metadata.mcast_rpf_group","multicast_metadata.mcast_mode"]
new_dic["fwd_result"]["A"] = ["l3_metadata.nexthop_index","nexthop_metadata.nexthop_type","ingress_metadata.egress_ifindex","intrinsic_metadata.mcast_grp","fabric_metadata.dst_device","l3_metadata.routed","fabric_metadata.reason_code","standard_metadata.egress_spec","l3_metadata.same_bd_check","ingress_metadata.drop_flag","ingress_metadata.drop_reason"]

#T72
new_dic["ecmp_group"] = {}
new_dic["ecmp_group"]["M"] = ["l3_metadata.nexthop_index"]
new_dic["ecmp_group"]["A"] = ["ingress_metadata.egress_ifindex","l3_metadata.nexthop_index","intrinsic_metadata.mcast_grp","fabric_metadata.dst_device"]

#T73
new_dic["nexthop"] = {}
new_dic["nexthop"]["M"] = ["l3_metadata.nexthop_index"]
new_dic["nexthop"]["A"] = ["intrinsic_metadata.mcast_grp","ingress_metadata.egress_ifindex","fabric_metadata.dst_device"]

#T74
new_dic["ofpat_group_ingress"] = {}
new_dic["ofpat_group_ingress"]["M"] = ["openflow_metadata.group_id"]
new_dic["ofpat_group_ingress"]["A"] = [""]

#T75
new_dic["ofpat_output"] = {}
new_dic["ofpat_output"]["M"] = ["openflow_metadata.index","openflow_metadata.group_id","standard_metadata.egress_spec"]
new_dic["ofpat_output"]["A"] = ["ingress_metadata.egress_ifindex","standard_metadata.egress_spec"]

#T76
new_dic["bd_flood"] = {}
new_dic["bd_flood"]["M"] = ["ingress_metadata.bd","l2_metadata.lkp_pkt_type"]
new_dic["bd_flood"]["A"] = ["intrinsic_metadata.mcast_grp"]

#T77
new_dic["lag_group"] = {}
new_dic["lag_group"]["M"] = ["ingress_metadata.egress_ifindex"]
new_dic["lag_group"]["A"] = ["standard_metadata.egress_spec","fabric_metadata.dst_device","fabric_metadata.dst_port"]

#T78
new_dic["learn_notify"] = {}
new_dic["learn_notify"]["M"] = ["l2_metadata.l2_src_miss","l2_metadata.l2_src_move","l2_metadata.stp_state"]
new_dic["learn_notify"]["A"] = [""]

#T79
new_dic["fabric_lag"] = {}
new_dic["fabric_lag"]["M"] = ["fabric_metadata.dst_device"]
new_dic["fabric_lag"]["A"] = ["standard_metadata.egress_spec","multicast_metadata.mcast_grp"]

#T80
new_dic["traffic_class"] = {}
new_dic["traffic_class"]["M"] = ["qos_metadata.tc_qos_group","qos_metadata.lkp_tc"]
new_dic["traffic_class"]["A"] = ["intrinsic_metadata.ingress_cos","intrinsic_metadata.qid"]

#T81
new_dic["system_acl"] = {}
new_dic["system_acl"]["M"] = ["acl_metadata.if_label","acl_metadata.bd_label","ingress_metadata.ifindex","l2_metadata.lkp_mac_type","l2_metadata.port_vlan_mapping_miss","security_metadata.ipsg_check_fail","acl_metadata.acl_deny","acl_metadata.racl_deny","l3_metadata.urpf_check_fail","ingress_metadata.drop_flag","l3_metadata.l3_copy","l3_metadata.rmac_hit","l3_metadata.routed","ipv6_metadata.ipv6_src_is_link_local","l2_metadata.same_if_check","tunnel_metadata.tunnel_if_check","l3_metadata.same_bd_check","l3_metadata.lkp_ip_ttl","l2_metadata.stp_state","ingress_metadata.control_frame","ipv4_metadata.ipv4_unicast_enabled","ipv6_metadata.ipv6_unicast_enabled","ingress_metadata.egress_ifindex","fabric_metadata.reason_code"]
new_dic["system_acl"]["A"] = ["fabric_metadata.dst_device","intrinsic_metadata.qid"]

#T82
new_dic["drop_stats"] = {}
new_dic["drop_stats"]["M"] = [""]
new_dic["drop_stats"]["A"] = [""]

def overlap(l1, l2):
    for e in l1:
        if e in l2:
            return True
    return False

key_list = list(new_dic.keys())
cnt = 0
# Forbidden pair:
forbidden_dic = {}
forbidden_dic["validate_outer_ipv4_packet"] = ["validate_outer_ipv6_packet","validate_mpls_packet"]
forbidden_dic["validate_outer_ipv6_packet"] = ["validate_mpls_packet"]

forbidden_dic["ingress_qos_map_dscp"] = ["ingress_qos_map_pcp"]
forbidden_dic["ipsg"] = ["ipsg_permit_special"]

forbidden_dic["int_source"] = ["int_terminate"]

forbidden_dic["fabric_ingress_src_lkp"] = ["native_packet_over_fabric"]

forbidden_dic["outer_ipv4_multicast"] = ["outer_ipv4_multicast_star_g", "outer_ipv6_multicast", "outer_ipv6_multicast_star_g",
                                         "ipv4_src_vtep", "ipv4_dest_vtep", "ipv6_src_vtep", "ipv6_dest_vtep", "mpls"]
forbidden_dic["outer_ipv4_multicast_star_g"] = ["outer_ipv6_multicast", "outer_ipv6_multicast_star_g",
                                                "ipv4_src_vtep", "ipv4_dest_vtep", "ipv6_src_vtep", "ipv6_dest_vtep", "mpls"]
forbidden_dic["outer_ipv6_multicast"] = ["outer_ipv6_multicast_star_g",
                                         "ipv4_src_vtep", "ipv4_dest_vtep", "ipv6_src_vtep", "ipv6_dest_vtep", "mpls"]
forbidden_dic["outer_multicast_rpf"] = ["ipv4_src_vtep", "ipv4_dest_vtep", "ipv6_src_vtep", "ipv6_dest_vtep", "mpls"]
forbidden_dic["ipv4_src_vtep"] = ["ipv6_src_vtep", "ipv6_dest_vtep", "mpls"]
forbidden_dic["ipv4_dest_vtep"] = ["ipv6_src_vtep", "ipv6_dest_vtep", "mpls"]
forbidden_dic["ipv6_src_vtep"] = ["mpls"]
forbidden_dic["ipv6_dest_vtep"] = ["mpls"]

forbidden_dic["mac_acl"] = ["ip_acl","ipv6_acl"]
forbidden_dic["ip_acl"] = ["ipv6_acl"]

forbidden_dic["ipv4_multicast_bridge"] = ["ipv4_multicast_bridge_star_g","ipv6_multicast_bridge","ipv6_multicast_bridge_star_g",
                                          "ipv4_racl", "ipv4_urpf", "ipv4_urpf_lpm", "ipv4_fib", "ipv4_fib_lpm", "ipv6_racl", "ipv6_urpf", 
                                          "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]
forbidden_dic["ipv4_multicast_bridge_star_g"] = ["ipv6_multicast_bridge","ipv6_multicast_bridge_star_g",
                                                "ipv4_racl", "ipv4_urpf", "ipv4_urpf_lpm", "ipv4_fib", "ipv4_fib_lpm", "ipv6_racl", 
                                                "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]
forbidden_dic["ipv6_multicast_bridge"] = ["ipv6_multicast_bridge_star_g",
                                          "ipv4_racl", "ipv4_urpf", "ipv4_urpf_lpm", "ipv4_fib", "ipv4_fib_lpm", "ipv6_racl",
                                          "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]
forbidden_dic["multicast_rpf"] = ["ipv4_racl", "ipv4_urpf", "ipv4_urpf_lpm", "ipv4_fib", "ipv4_fib_lpm", "ipv6_racl",
                                   "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]

forbidden_dic["ipv4_racl"] = ["ipv6_racl", "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]
forbidden_dic["ipv4_urpf"] = ["ipv4_urpf_lpm", "ipv6_racl", "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]
forbidden_dic["ipv4_fib"] = ["ipv4_fib_lpm", "ipv6_racl", "ipv6_urpf", "ipv6_urpf_lpm", "ipv6_fib", "ipv6_fib_lpm"]

forbidden_dic["ipv6_urpf"] = ["ipv4_urpf_lpm"]
forbidden_dic["ipv6_fib"] = ["ipv4_fib_lpm"]

forbidden_dic["nat_twice"] = ["nat_dst", "nat_src", "nat_flow"]
forbidden_dic["nat_dst"] = ["nat_src", "nat_flow"]
forbidden_dic["nat_src"] = ["nat_flow"]

forbidden_dic["compute_ipv4_hashes"] = ["compute_ipv6_hashes", "compute_non_ip_hashes"]
forbidden_dic["compute_ipv6_hashes"] = ["compute_non_ip_hashes"]

forbidden_dic["ecmp_group"] = ["nexthop"]



for i in range(len(key_list)):
    for j in range(i + 1, len(key_list)):
        key1 = key_list[i]
        key2 = key_list[j]
        if key1 in forbidden_dic and key2 in forbidden_dic[key1]:
            continue
        M1 = new_dic[key1]['M']
        M2 = new_dic[key2]['M']
        A1 = new_dic[key1]['A']
        A2 = new_dic[key2]['A']
        # match dep
        if overlap(A1, M2):
            cnt += 1
            print(key1, "has MATCH dep with", key2)
        elif overlap(A1, A2):
            cnt += 1
            print(key1, "has ACTION dep with", key2)
        elif overlap(M1, A2):
            cnt += 1
            print(key1, "has REVERSE dep with", key2)

print("cnt =", cnt)
