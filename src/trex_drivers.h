#ifndef TREX_DRIVERS_H
#define TREX_DRIVERS_H

/*
  Hanoh Haim
  Cisco Systems, Inc.
*/

/*
  Copyright (c) 2015-2017 Cisco Systems, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "main_dpdk.h"
#include "dpdk_drv_filter.h"


struct port_cfg_t {
public:
    port_cfg_t();

    void update_var(void);
    void update_global_config_fdir(void);

    struct rte_eth_conf     m_port_conf;
    struct rte_eth_rxconf   m_rx_conf;
    struct rte_eth_rxconf   m_rx_drop_conf;
    struct rte_eth_txconf   m_tx_conf;
};


class CTRexExtendedDriverBase {
protected:
    enum {
        // Is there HW support for dropping packets arriving to certain queue?
        TREX_DRV_CAP_DROP_Q = 0x1,
        /* Does this NIC type support automatic packet dropping in case of a link down?
           in case it is supported the packets will be dropped, else there would be a back pressure to tx queues
           this interface is used as a workaround to let TRex work without link in stateless mode, driver that
           does not support that will be failed at init time because it will cause watchdog due to watchdog hang */
        TREX_DRV_CAP_DROP_PKTS_IF_LNK_DOWN = 0x2,
        // Does the driver support changing MAC address?
        TREX_DRV_CAP_MAC_ADDR_CHG = 0x4,

        // when there is more than one RX queue, does RSS is configured by by default to split to all the queues.
        // some driver configure RSS by default (MLX5/ENIC) and some (Intel) does not. in case of TCP stack need to remove the latency thread from RSS
        TREX_DRV_DEFAULT_RSS_ON_RX_QUEUES = 0x08,

        /* ASTF multi-core is supported */
        TREX_DRV_DEFAULT_ASTF_MULTI_CORE = 0x10


    } trex_drv_cap;

public:
    virtual int get_min_sample_rate(void)=0;
    virtual void update_configuration(port_cfg_t * cfg)=0;
    virtual void update_global_config_fdir(port_cfg_t * cfg)=0;
    virtual int configure_rx_filter_rules(CPhyEthIF * _if)=0;
    virtual int add_del_rx_flow_stat_rule(CPhyEthIF * _if, enum rte_filter_op op, uint16_t l3, uint8_t l4
                                          , uint8_t ipv6_next_h, uint16_t id) {return 0;}
    bool is_hardware_default_rss(){
        return ((m_cap & TREX_DRV_DEFAULT_RSS_ON_RX_QUEUES) != 0);
    }

    bool is_capable_astf_multi_core(){
        return ((m_cap & TREX_DRV_DEFAULT_ASTF_MULTI_CORE) != 0);
    }

    bool is_hardware_support_drop_queue() {
        return ((m_cap & TREX_DRV_CAP_DROP_Q) != 0);
    }
    bool hardware_support_mac_change() {
        return ((m_cap & TREX_DRV_CAP_MAC_ADDR_CHG) != 0);
    }
    bool drop_packets_incase_of_linkdown() {
        return ((m_cap & TREX_DRV_CAP_DROP_PKTS_IF_LNK_DOWN) != 0);
    }

    virtual int stop_queue(CPhyEthIF * _if, uint16_t q_num);
    virtual bool get_extended_stats_fixed(CPhyEthIF * _if, CPhyEthIFStats *stats, int fix_i, int fix_o);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats)=0;
    virtual void clear_extended_stats(CPhyEthIF * _if)=0;
    virtual int  wait_for_stable_link();
    virtual bool sleep_after_arp_needed(){
        return(false);
    }
    virtual void wait_after_link_up();
    virtual bool hw_rx_stat_supported(){return false;}
    virtual int get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts, uint32_t *bytes, uint32_t *prev_bytes
                             , int min, int max) {return -1;}
    virtual void reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len) {}
    virtual int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd) { return -1;}
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) = 0;

    /* can't get CPhyEthIF as it won't be valid at that time */
    virtual int verify_fw_ver(tvpid_t   tvpid) {return 0;}
    virtual CFlowStatParser *get_flow_stat_parser();
    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on)=0;
    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) = 0;

    virtual rte_mempool_t * get_rx_mem_pool(int socket_id);

    virtual void get_dpdk_drv_params(CTrexDpdkParams &p);

    uint32_t get_capabilities(void) {
        return m_cap;
    }

    static void set_global_dev_info(rte_eth_dev_info &dev_info);

protected:
    // flags describing interface capabilities
    uint32_t m_cap;
    static rte_eth_dev_info g_dev_info; // assumption: all drivers have same 
};


// stubs in case of dummy port, call to normal function otherwise
class CTRexExtendedDriverDummySelector : public CTRexExtendedDriverBase {
public:
    CTRexExtendedDriverDummySelector(CTRexExtendedDriverBase *original_driver) {
        m_real_drv = original_driver;
        m_cap = m_real_drv->get_capabilities();
    }

    int get_min_sample_rate(void) {
        return m_real_drv->get_min_sample_rate();
    }
    void update_configuration(port_cfg_t *cfg) {
        m_real_drv->update_configuration(cfg);
    }
    void update_global_config_fdir(port_cfg_t *cfg) {
        m_real_drv->update_global_config_fdir(cfg);
    }
    int configure_rx_filter_rules(CPhyEthIF *_if) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->configure_rx_filter_rules(_if);
        }
    }
    int add_del_rx_flow_stat_rule(CPhyEthIF *_if, enum rte_filter_op op, uint16_t l3, uint8_t l4, uint8_t ipv6_next_h, uint16_t id) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->add_del_rx_flow_stat_rule(_if, op, l3, l4, ipv6_next_h, id);
        }
    }
    int stop_queue(CPhyEthIF * _if, uint16_t q_num) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->stop_queue(_if, q_num);
        }
    }
    bool get_extended_stats_fixed(CPhyEthIF * _if, CPhyEthIFStats *stats, int fix_i, int fix_o) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->get_extended_stats_fixed(_if, stats, fix_i, fix_o);
        }
    }
    bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->get_extended_stats(_if, stats);
        }
    }
    void clear_extended_stats(CPhyEthIF * _if) {
        if ( ! _if->is_dummy() ) {
            m_real_drv->clear_extended_stats(_if);
        }
    }
    int  wait_for_stable_link() {
        return m_real_drv->wait_for_stable_link();
    }
    bool sleep_after_arp_needed() {
        return m_real_drv->sleep_after_arp_needed();
    }
    void wait_after_link_up() {
        m_real_drv->wait_after_link_up();
    }
    bool hw_rx_stat_supported() {
        return m_real_drv->hw_rx_stat_supported();
    }
    int get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts, uint32_t *bytes, uint32_t *prev_bytes, int min, int max) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->get_rx_stats(_if, pkts, prev_pkts, bytes, prev_bytes, min, max);
        }
    }
    void reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len) {
        if ( ! _if->is_dummy() ) {
            m_real_drv->reset_rx_stats(_if, stats, min, len);
        }
    }
    int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->dump_fdir_global_stats(_if, fd);
        }
    }
    void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
         m_real_drv->get_rx_stat_capabilities(flags, num_counters, base_ip_id);
    }
    int verify_fw_ver(tvpid_t tvpid) {
        if ( CTVPort(tvpid).is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->verify_fw_ver(tvpid);
        }
    }
    CFlowStatParser *get_flow_stat_parser() {
        return m_real_drv->get_flow_stat_parser();
    }
    int set_rcv_all(CPhyEthIF * _if, bool set_on) {
        if ( _if->is_dummy() ) {
            return 0;
        } else {
            return m_real_drv->set_rcv_all(_if, set_on);
        }
    }
    TRexPortAttr * create_port_attr(tvpid_t tvpid, repid_t repid) {
        if ( CTVPort(tvpid).is_dummy() ) {
            return new SimTRexPortAttr();
        } else {
            return m_real_drv->create_port_attr(tvpid, repid);
        }
    }
    rte_mempool_t * get_rx_mem_pool(int socket_id) {
        return m_real_drv->get_rx_mem_pool(socket_id);
    }
    void get_dpdk_drv_params(CTrexDpdkParams &p) {
        return m_real_drv->get_dpdk_drv_params(p);
    }
private:
    CTRexExtendedDriverBase *m_real_drv;
};

class CTRexExtendedDriverBase1G : public CTRexExtendedDriverBase {

public:
    CTRexExtendedDriverBase1G(){
        m_cap = TREX_DRV_CAP_DROP_Q | TREX_DRV_CAP_MAC_ADDR_CHG;
    }

    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, false, true, true, true);
    }

    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverBase1G() );
    }

    virtual void update_global_config_fdir(port_cfg_t * cfg);

    virtual int get_min_sample_rate(void);
    virtual void update_configuration(port_cfg_t * cfg);
    virtual int stop_queue(CPhyEthIF * _if, uint16_t q_num);
    virtual int configure_rx_filter_rules(CPhyEthIF * _if);
    virtual int configure_rx_filter_rules_statefull(CPhyEthIF * _if);
    virtual int configure_rx_filter_rules_stateless(CPhyEthIF * _if);
    virtual void clear_rx_filter_rules(CPhyEthIF * _if);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    virtual void clear_extended_stats(CPhyEthIF * _if);
    virtual int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd) {return 0;}
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_RX_BYTES_COUNT
            | TrexPlatformApi::IF_STAT_PAYLOAD;

        if (CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_ONE_QUEUE
            || CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_RSS) {
            num_counters = MAX_FLOW_STATS;
            base_ip_id = IP_ID_RESERVE_BASE;
        } else {
            num_counters = UINT8_MAX;
            // Must be 0xff00, since we configure HW filter for the 0xff byte
            // The filter must catch all flow stat packets, and latency packets (having 0xffff in IP ID)
            base_ip_id = 0xff00;
        }
    }
    virtual int wait_for_stable_link();
    virtual void wait_after_link_up();
    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on);
};

typedef uint8_t tvpid_t; /* port ID of trex 0,1,2,3 up to MAX_PORTS*/
typedef uint8_t repid_t; /* DPDK port id  */


// Base for all virtual drivers. No constructor. Should not create object from this type.
class CTRexExtendedDriverVirtBase : public CTRexExtendedDriverBase {
public:
    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, true, true, true, true);
    }
    virtual void update_global_config_fdir(port_cfg_t * cfg) {}

    virtual int get_min_sample_rate(void);
    virtual void get_dpdk_drv_params(CTrexDpdkParams &p);
    virtual void update_configuration(port_cfg_t * cfg);
    virtual int configure_rx_filter_rules(CPhyEthIF * _if);
    virtual int stop_queue(CPhyEthIF * _if, uint16_t q_num);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats)=0;
    virtual void clear_extended_stats(CPhyEthIF * _if);
    virtual int wait_for_stable_link();
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_RX_BYTES_COUNT
            | TrexPlatformApi::IF_STAT_PAYLOAD;
        num_counters = MAX_FLOW_STATS;
        base_ip_id = IP_ID_RESERVE_BASE;
    }

    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on) {return 0;}
    CFlowStatParser *get_flow_stat_parser();
};

class CTRexExtendedDriverVirtio : public CTRexExtendedDriverVirtBase {
public:
    CTRexExtendedDriverVirtio() {
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = /*TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG */ 0;
    }
    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverVirtio() );
    }
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);

    virtual void update_configuration(port_cfg_t * cfg);

};

class CTRexExtendedDriverVmxnet3 : public CTRexExtendedDriverVirtBase {
public:
    CTRexExtendedDriverVmxnet3(){
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = /*TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG*/0;
    }

    static CTRexExtendedDriverBase * create() {
        return ( new CTRexExtendedDriverVmxnet3() );
    }
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    virtual void update_configuration(port_cfg_t * cfg);


};

class CTRexExtendedDriverI40evf : public CTRexExtendedDriverVirtBase {
public:
    CTRexExtendedDriverI40evf(){
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = /*TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG */0;
    }
    virtual bool get_extended_stats(CPhyEthIF * _if, CPhyEthIFStats *stats) {
        return get_extended_stats_fixed(_if, stats, 4, 4);
    }
    virtual void update_configuration(port_cfg_t * cfg);
    static CTRexExtendedDriverBase * create() {
        return ( new CTRexExtendedDriverI40evf() );
    }
    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, true, true, false, true);
    }
};

class CTRexExtendedDriverIxgbevf : public CTRexExtendedDriverI40evf {

public:
    CTRexExtendedDriverIxgbevf(){
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = /*TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG */0;
    }
    virtual bool get_extended_stats(CPhyEthIF * _if, CPhyEthIFStats *stats) {
        return get_extended_stats_fixed(_if, stats, 4, 4);
    }

    static CTRexExtendedDriverBase * create() {
        return ( new CTRexExtendedDriverIxgbevf() );
    }
    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, true, true, false, true);
    }
};

class CTRexExtendedDriverBaseE1000 : public CTRexExtendedDriverVirtBase {
    CTRexExtendedDriverBaseE1000() {
        // E1000 driver is only relevant in VM in our case
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = /*TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG */0;
    }
public:
    static CTRexExtendedDriverBase * create() {
        return ( new CTRexExtendedDriverBaseE1000() );
    }
    // e1000 driver handing us packets with ethernet CRC, so we need to chop them
    virtual void update_configuration(port_cfg_t * cfg);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);

};

class CTRexExtendedDriverAfPacket : public CTRexExtendedDriverVirtBase {
public:
    CTRexExtendedDriverAfPacket(){
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = 0;
    }
    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverAfPacket() );
    }
    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, true, true, true, false);
    }
    virtual void get_dpdk_drv_params(CTrexDpdkParams &p);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    virtual void update_configuration(port_cfg_t * cfg);
};

class CTRexExtendedDriverBase10G : public CTRexExtendedDriverBase {
public:
    CTRexExtendedDriverBase10G(){
        m_cap = TREX_DRV_CAP_DROP_Q | TREX_DRV_CAP_MAC_ADDR_CHG | TREX_DRV_DEFAULT_ASTF_MULTI_CORE;
    }

    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, false, true, true, true);
    }

    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverBase10G() );
    }

    virtual void update_global_config_fdir(port_cfg_t * cfg);

    virtual int get_min_sample_rate(void);
    virtual void update_configuration(port_cfg_t * cfg);
    virtual int configure_rx_filter_rules(CPhyEthIF * _if);
    virtual int configure_rx_filter_rules_stateless(CPhyEthIF * _if);
    virtual int configure_rx_filter_rules_statefull(CPhyEthIF * _if);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    virtual void clear_extended_stats(CPhyEthIF * _if);
    virtual int wait_for_stable_link();
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_RX_BYTES_COUNT
            | TrexPlatformApi::IF_STAT_PAYLOAD;
        if ((CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_RSS)
            || (CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_ONE_QUEUE)) {
            num_counters = MAX_FLOW_STATS;
        } else {
            num_counters = 127;
        }
        base_ip_id = IP_ID_RESERVE_BASE;
    }
    virtual CFlowStatParser *get_flow_stat_parser();
    int add_del_eth_filter(CPhyEthIF * _if, bool is_add, uint16_t ethertype);
    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on);
};

class CTRexExtendedDriverBase40G : public CTRexExtendedDriverBase {
public:
    CTRexExtendedDriverBase40G(){
        m_cap = TREX_DRV_CAP_DROP_Q | TREX_DRV_CAP_MAC_ADDR_CHG | TREX_DRV_CAP_DROP_PKTS_IF_LNK_DOWN | TREX_DRV_DEFAULT_ASTF_MULTI_CORE;
    }

    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        // disabling flow control on 40G using DPDK API causes the interface to malfunction
        return new DpdkTRexPortAttr(tvpid, repid, false, false, true, true);
    }

    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverBase40G() );
    }

    virtual void update_global_config_fdir(port_cfg_t * cfg){
    }
    virtual int get_min_sample_rate(void);
    virtual void update_configuration(port_cfg_t * cfg);
    virtual int configure_rx_filter_rules(CPhyEthIF * _if);
    virtual int add_del_rx_flow_stat_rule(CPhyEthIF * _if, enum rte_filter_op op, uint16_t l3_proto
                                          , uint8_t l4_proto, uint8_t ipv6_next_h, uint16_t id);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    virtual void clear_extended_stats(CPhyEthIF * _if);
    virtual void reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len);
    virtual int get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts, uint32_t *bytes, uint32_t *prev_bytes, int min, int max);
    virtual int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd);
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_PAYLOAD;
        // HW counters on x710 do not support counting bytes.
        if ( CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_ONE_QUEUE
             || CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_RSS) {
            flags |= TrexPlatformApi::IF_STAT_RX_BYTES_COUNT;
            num_counters = MAX_FLOW_STATS;
        } else {
            // TODO: check if we could get amount of interfaces per NIC to enlarge this
            num_counters = MAX_FLOW_STATS_X710;
        }
        base_ip_id = IP_ID_RESERVE_BASE;
        m_max_flow_stats = num_counters;
    }
    virtual int wait_for_stable_link();
    virtual bool hw_rx_stat_supported(){
        if (CGlobalInfo::m_options.preview.get_disable_hw_flow_stat()
            || CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_ONE_QUEUE
            || CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_RSS) {
            return false;
        } else {
            return true;
        }
    }
    virtual int verify_fw_ver(tvpid_t   tvpid);
    virtual CFlowStatParser *get_flow_stat_parser();
    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on);

private:
    virtual void add_del_rules(enum rte_filter_op op, repid_t  repid, uint16_t type, uint8_t ttl
                               , uint16_t ip_id, uint8_t l4_proto, int queue, uint16_t stat_idx);
    virtual int add_del_eth_type_rule(repid_t  repid, enum rte_filter_op op, uint16_t eth_type);
    virtual int configure_rx_filter_rules_statefull(CPhyEthIF * _if);
    uint32_t get_flow_stats_offset(repid_t repid);

private:
    uint16_t m_max_flow_stats;
};

class CTRexExtendedDriverBaseVIC : public CTRexExtendedDriverBase {
public:
    CTRexExtendedDriverBaseVIC(){
        if (get_is_tcp_mode()) {
            CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
            m_cap = /*TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG */0;
        }else{
            m_cap = TREX_DRV_CAP_DROP_Q  | TREX_DRV_CAP_MAC_ADDR_CHG ;
        }
    }

    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, false, false, true, true);
    }

    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverBaseVIC() );
    }
    virtual void update_global_config_fdir(port_cfg_t * cfg){
    }
    void clear_extended_stats(CPhyEthIF * _if);
    bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);

    virtual int get_min_sample_rate(void);

    virtual int verify_fw_ver(tvpid_t   tvpid);

    virtual void update_configuration(port_cfg_t * cfg);

    virtual int configure_rx_filter_rules(CPhyEthIF * _if);
    virtual void reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len);
    virtual int get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts, uint32_t *bytes, uint32_t *prev_bytes, int min, int max);
    virtual int get_stat_counters_num() {return MAX_FLOW_STATS;}
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_RX_BYTES_COUNT
            | TrexPlatformApi::IF_STAT_PAYLOAD;
        num_counters = MAX_FLOW_STATS;
        base_ip_id = IP_ID_RESERVE_BASE;
    }

    virtual CFlowStatParser *get_flow_stat_parser();
    virtual int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd);
    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on);

private:

    virtual void add_del_rules(enum rte_filter_op op, repid_t  repid, uint16_t type, uint16_t id
                               , uint8_t l4_proto, uint8_t tos, int queue);
    virtual int add_del_eth_type_rule(repid_t  repid, enum rte_filter_op op, uint16_t eth_type);
    virtual int configure_rx_filter_rules_statefull(CPhyEthIF * _if);

};


class CTRexExtendedDriverBaseMlnx5G : public CTRexExtendedDriverBase {
public:
    CTRexExtendedDriverBaseMlnx5G(){
         m_cap = TREX_DRV_CAP_DROP_Q | TREX_DRV_CAP_MAC_ADDR_CHG |  TREX_DRV_DEFAULT_ASTF_MULTI_CORE;
    }

    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        // disabling flow control on 40G using DPDK API causes the interface to malfunction
        return new DpdkTRexPortAttr(tvpid, repid, false, false, true, true);
    }

    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverBaseMlnx5G() );
    }

    virtual void get_dpdk_drv_params(CTrexDpdkParams &p);

    virtual void update_global_config_fdir(port_cfg_t * cfg){
    }

    virtual int get_min_sample_rate(void);

    virtual void update_configuration(port_cfg_t * cfg);
    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    virtual void clear_extended_stats(CPhyEthIF * _if);
    virtual void reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len);
    virtual int get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts, uint32_t *bytes, uint32_t *prev_bytes, int min, int max);
    virtual int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd);
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_RX_BYTES_COUNT
            | TrexPlatformApi::IF_STAT_PAYLOAD;
        num_counters = 127; //With MAX_FLOW_STATS we saw packet failures in rx_test. Need to check.
        base_ip_id = IP_ID_RESERVE_BASE;
    }

    virtual int wait_for_stable_link();
    // disabling flow control on 40G using DPDK API causes the interface to malfunction
    virtual bool flow_control_disable_supported(){return false;}
    virtual CFlowStatParser *get_flow_stat_parser();

    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on){
        return(m_filter_manager.set_rcv_all(_if->get_repid(),set_on));
    }

    virtual int configure_rx_filter_rules(CPhyEthIF * _if){
        return(m_filter_manager.configure_rx_filter_rules(_if->get_repid()));
    }

private:
    CDpdkFilterManager  m_filter_manager;
};



/* wan't verified by us, software mode  */
class CTRexExtendedDriverMlnx4 : public CTRexExtendedDriverVirtBase {
public:
    CTRexExtendedDriverMlnx4() {
        CGlobalInfo::set_queues_mode(CGlobalInfo::Q_MODE_ONE_QUEUE);
        m_cap = TREX_DRV_CAP_MAC_ADDR_CHG ;
    }
    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverMlnx4() );
    }

    virtual bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
        return get_extended_stats_fixed(_if, stats, 4, 4);
    };

    virtual void update_configuration(port_cfg_t * cfg);
};

#include <dlfcn.h>

class CTRexExtendedDriverBaseNtAcc : public CTRexExtendedDriverBase {
public:
    CTRexExtendedDriverBaseNtAcc(){
        m_cap = TREX_DRV_CAP_DROP_Q | TREX_DRV_CAP_DROP_PKTS_IF_LNK_DOWN ;
        TAILQ_INIT(&lh_fid);
        // The current rte_flow.h is not C++ includable so rte_flow wrappers
        // have been made in libntacc
        void *libntacc = dlopen(this->g_ntacc_so_id_str, RTLD_NOW);
        if (libntacc == NULL) {
          /* Library does not exist. */
          fprintf(stderr, "Failed to find needed library : %s\n", this->g_ntacc_so_id_str);
          exit(-1);
        }
        ntacc_add_rules = (void* (*)(uint8_t, uint16_t,
            uint8_t, int, char *))dlsym(libntacc, "ntacc_add_rules");
        if (ntacc_add_rules == NULL) {
          fprintf(stderr, "Failed to find \"ntacc_add_rules\" in %s\n", this->g_ntacc_so_id_str);
          exit(-1);
        }
        ntacc_del_rules = (void * (*)(uint8_t, void*))dlsym(libntacc, "ntacc_del_rules");
        if (ntacc_add_rules == NULL) {
          fprintf(stderr, "Failed to find \"ntacc_del_rules\" in %s\n", this->g_ntacc_so_id_str);
          exit(-1);
        }
    }

    ~CTRexExtendedDriverBaseNtAcc();

    virtual TRexPortAttr * create_port_attr(tvpid_t tvpid,repid_t repid) {
        return new DpdkTRexPortAttr(tvpid, repid, false, false, true, true);
    }

    virtual bool sleep_after_arp_needed(){
        return(true);
    }

    static CTRexExtendedDriverBase * create(){
        return ( new CTRexExtendedDriverBaseNtAcc() );
    }

    virtual void update_global_config_fdir(port_cfg_t * cfg){
    }

    virtual int get_min_sample_rate(void);

    virtual void get_dpdk_drv_params(CTrexDpdkParams &p);

    virtual void update_configuration(port_cfg_t * cfg);
    virtual int configure_rx_filter_rules(CPhyEthIF * _if);
    bool get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats);
    void clear_extended_stats(CPhyEthIF * _if);
    virtual void reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len);
    virtual int get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts, uint32_t *bytes, uint32_t *prev_bytes, int min, int max);
    virtual int get_stat_counters_num() {return MAX_FLOW_STATS;}
    virtual void get_rx_stat_capabilities(uint16_t &flags, uint16_t &num_counters, uint16_t &base_ip_id) {
        // Even though the NIC support per flow statistics it is not yet available in the DPDK so SW must be used
        flags = TrexPlatformApi::IF_STAT_IPV4_ID | TrexPlatformApi::IF_STAT_RX_BYTES_COUNT
        | TrexPlatformApi::IF_STAT_PAYLOAD;
        num_counters = MAX_FLOW_STATS;
        base_ip_id = IP_ID_RESERVE_BASE;
    }
    virtual CFlowStatParser *get_flow_stat_parser();
    virtual int dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd);
    virtual int set_rcv_all(CPhyEthIF * _if, bool set_on);
    virtual int verify_fw_ver(int i);
    static char g_ntacc_so_id_str[50];

private:
    void* (*ntacc_add_rules)(uint8_t port_id, uint16_t type,
            uint8_t l4_proto, int queue, char *ntpl_str);
    void* (*ntacc_del_rules)(uint8_t port_id, void *rte_flow);

    virtual void add_del_rules(enum rte_filter_op op, uint8_t port_id, uint16_t type,
                               uint8_t l4_proto, int queue, uint32_t f_id, char *ntpl_str);
    virtual int add_del_eth_type_rule(uint8_t port_id, enum rte_filter_op op, uint16_t eth_type);
    virtual int configure_rx_filter_rules_stateless(CPhyEthIF * _if);
    virtual int configure_rx_filter_rules_statefull(CPhyEthIF * _if);
    struct fid_s {
        uint8_t port_id;
        uint32_t id;
        void *rte_flow;
        TAILQ_ENTRY(fid_s) leTQ; //!< TailQ element.
    };
    TAILQ_HEAD(, fid_s) lh_fid;
};

typedef CTRexExtendedDriverBase * (*create_object_t) (void);

class CTRexExtendedDriverRec {
public:
    std::string         m_driver_name;
    create_object_t     m_constructor;
};

class CTRexExtendedDriverDb {
public:

    const std::string & get_driver_name() {
        return m_driver_name;
    }

    bool is_driver_exists(std::string name);



    void set_driver_name(std::string name){
        m_driver_was_set=true;
        m_driver_name=name;
        printf(" set driver name %s \n",name.c_str());
        m_drv=create_driver(m_driver_name);
        assert(m_drv);
    }

    void create_dummy() {
        if ( ! m_dummy_selector_created ) {
            m_dummy_selector_created = true;
            m_drv = new CTRexExtendedDriverDummySelector(get_drv());
        }
    }

    CTRexExtendedDriverBase * get_drv(){
        if (!m_driver_was_set) {
            printf(" ERROR too early to use this object !\n");
            printf(" need to set the right driver \n");
            assert(0);
        }
        assert(m_drv);
        return (m_drv);
    }

public:

    static CTRexExtendedDriverDb * Ins();

private:
    CTRexExtendedDriverBase * create_driver(std::string name);

    CTRexExtendedDriverDb(){
        register_driver(std::string("net_ixgbe"),CTRexExtendedDriverBase10G::create);
        register_driver(std::string("net_e1000_igb"),CTRexExtendedDriverBase1G::create);
        register_driver(std::string("net_i40e"),CTRexExtendedDriverBase40G::create);
        register_driver(std::string("net_enic"),CTRexExtendedDriverBaseVIC::create);
        register_driver(std::string("net_mlx5"),CTRexExtendedDriverBaseMlnx5G::create);
        register_driver(std::string("net_mlx4"),CTRexExtendedDriverMlnx4::create);
        register_driver(std::string("net_ntacc"), CTRexExtendedDriverBaseNtAcc::create);


        /* virtual devices */
        register_driver(std::string("net_e1000_em"), CTRexExtendedDriverBaseE1000::create);
        register_driver(std::string("net_vmxnet3"), CTRexExtendedDriverVmxnet3::create);
        register_driver(std::string("net_virtio"), CTRexExtendedDriverVirtio::create);
        register_driver(std::string("net_ena"),CTRexExtendedDriverVirtio::create);
        register_driver(std::string("net_i40e_vf"), CTRexExtendedDriverI40evf::create);
        register_driver(std::string("net_ixgbe_vf"), CTRexExtendedDriverIxgbevf::create);

        /* raw socket */
        register_driver(std::string("net_af_packet"), CTRexExtendedDriverAfPacket::create);

        m_driver_was_set=false;
        m_dummy_selector_created=false;
        m_drv=NULL;
        m_driver_name="";
    }
    void register_driver(std::string name, create_object_t func);
    static CTRexExtendedDriverDb * m_ins;
    bool        m_driver_was_set;
    bool        m_dummy_selector_created;
    std::string m_driver_name;
    CTRexExtendedDriverBase * m_drv;
    std::vector <CTRexExtendedDriverRec*>     m_list;

};


static CTRexExtendedDriverBase * get_ex_drv(){
    return ( CTRexExtendedDriverDb::Ins()->get_drv());
}


#endif /* TREX_DRIVERS_H */
