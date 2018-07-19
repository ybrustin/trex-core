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

#include "trex_drivers.h"
#include "dpdk_funcs.h"

#include <rte_tailq.h>

#include "dpdk/drivers/net/e1000/base/e1000_regs.h"

extern "C" {
#include "dpdk/drivers/net/ixgbe/base/ixgbe_type.h"
}

#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define TX_WTHRESH_1G 1  /**< Default values of TX write-back threshold reg. */
#define TX_PTHRESH_1G 1 /**< Default values of TX prefetch threshold reg. */


#define RX_DESC_NUM_DROP_Q 64
#define RX_DESC_NUM_DATA_Q 4096
#define RX_DESC_NUM_DROP_Q_MLX 8
#define RX_DESC_NUM_DATA_Q_VM 512
#define TX_DESC_NUM 1024

#define RX_CHECK_MIX_SAMPLE_RATE 8
#define RX_CHECK_MIX_SAMPLE_RATE_1G 2

static uint16_t all_eth_types[]  = {
    0x0800, 0x0806, 0x0842, 0x22F3, 0x22EA, 0x6003, 0x8035, 0x809B, 0x80F3, 0x8100,
    0x8137, 0x8204, 0x86DD, 0x8808, 0x8809, 0x8819, 0x8847, 0x8848, 0x8863, 0x8864,
    0x886D, 0x8870, 0x887B, 0x888E, 0x8892, 0x889A, 0x88A2, 0x88A4, 0x88A8, 0x88AB,
    0x88B8, 0x88B9, 0x88BA, 0x88CC, 0x88CD, 0x88DC, 0x88E1, 0x88E3, 0x88E5, 0x88E7,
    0x88F7, 0x88FB, 0x8902, 0x8906, 0x8914, 0x8915, 0x891D, 0x892F, 0x9000, 0x9100,
};


char CTRexExtendedDriverBaseNtAcc::g_ntacc_so_id_str[];
rte_eth_dev_info CTRexExtendedDriverBase::g_dev_info;

port_cfg_t::port_cfg_t() {
    memset(&m_port_conf,0,sizeof(m_port_conf));
    memset(&m_rx_conf,0,sizeof(m_rx_conf));
    memset(&m_tx_conf,0,sizeof(m_tx_conf));
    memset(&m_rx_drop_conf,0,sizeof(m_rx_drop_conf));

    m_rx_conf.rx_thresh.pthresh = RX_PTHRESH;
    m_rx_conf.rx_thresh.hthresh = RX_HTHRESH;
    m_rx_conf.rx_thresh.wthresh = RX_WTHRESH;
    m_rx_conf.rx_free_thresh =32;

    m_rx_drop_conf.rx_thresh.pthresh = 0;
    m_rx_drop_conf.rx_thresh.hthresh = 0;
    m_rx_drop_conf.rx_thresh.wthresh = 0;
    m_rx_drop_conf.rx_free_thresh =32;
    m_rx_drop_conf.rx_drop_en=1;

    m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;

    m_port_conf.rxmode.max_rx_pkt_len = 9*1024+22;
    m_port_conf.rxmode.offloads |= ( DEV_RX_OFFLOAD_JUMBO_FRAME
                                   | DEV_RX_OFFLOAD_CRC_STRIP
                                   | DEV_RX_OFFLOAD_SCATTER );
    // start optimistic
    m_port_conf.txmode.offloads = UINT64_MAX;
}

void port_cfg_t::update_var(void) {
    get_ex_drv()->update_configuration(this);
    if ( (m_port_conf.rxmode.offloads & DEV_RX_OFFLOAD_TCP_LRO) && 
        CGlobalInfo::m_options.preview.getLroOffloadDisable() ) {
        m_port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_TCP_LRO;
        printf("Warning LRO is supported and asked to be disabled by user \n");
    }
}

void port_cfg_t::update_global_config_fdir(void) {
    get_ex_drv()->update_global_config_fdir(this);
}


rte_mempool_t* CTRexExtendedDriverBase::get_rx_mem_pool(int socket_id) {
    CTrexDpdkParams dpdk_p;
    get_dpdk_drv_params(dpdk_p);

    switch(dpdk_p.rx_mbuf_type) {
    case MBUF_9k:
        return CGlobalInfo::m_mem_pool[socket_id].m_mbuf_pool_9k;
    case MBUF_2048:
        return CGlobalInfo::m_mem_pool[socket_id].m_mbuf_pool_2048;
    default:
        fprintf(stderr, "Internal error: Wrong rx_mem_pool");
        assert(0);
        return nullptr;
    }
}

void CTRexExtendedDriverDb::register_driver(std::string name,
                                            create_object_t func){
    CTRexExtendedDriverRec * rec;
    rec = new CTRexExtendedDriverRec();
    rec->m_driver_name=name;
    rec->m_constructor=func;
    m_list.push_back(rec);
}


bool CTRexExtendedDriverDb::is_driver_exists(std::string name){
    int i;
    for (i=0; i<(int)m_list.size(); i++) {
        if (m_list[i]->m_driver_name == name) {
            return (true);
        }
    }
    return (false);
}

CTRexExtendedDriverBase * CTRexExtendedDriverDb::create_driver(std::string name){
    int i;
    for (i=0; i<(int)m_list.size(); i++) {
        if (m_list[i]->m_driver_name == name) {
            return ( m_list[i]->m_constructor() );
        }
    }
    return( (CTRexExtendedDriverBase *)0);
}


void CTRexExtendedDriverBase::set_global_dev_info(rte_eth_dev_info &dev_info) {
    g_dev_info = dev_info;
}


CTRexExtendedDriverDb * CTRexExtendedDriverDb::Ins(){
    if (!m_ins) {
        m_ins = new CTRexExtendedDriverDb();
    }
    return (m_ins);
}

/* ----------------------
   get_min_sample_rate
-----------------------*/

int CTRexExtendedDriverBase1G::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE_1G);
}

int CTRexExtendedDriverVirtBase::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE_1G);
}

int CTRexExtendedDriverBase10G::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE);
}

int CTRexExtendedDriverBase40G::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE);
}

int CTRexExtendedDriverBaseVIC::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE);
}

int CTRexExtendedDriverBaseMlnx5G::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE);
}

int CTRexExtendedDriverBaseNtAcc::get_min_sample_rate(void){
    return (RX_CHECK_MIX_SAMPLE_RATE);
}


/* ----------------------
   get_dpdk_drv_params
-----------------------*/

void CTRexExtendedDriverBase::get_dpdk_drv_params(CTrexDpdkParams &p) {
    p.rx_data_q_num = 1;

    if (CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_ONE_QUEUE) {
        p.rx_drop_q_num = 0;
    } else {
        p.rx_drop_q_num = 1;
        if (get_is_tcp_mode()) {
            /* data queues is the number of cores , drop is the first queue in this mode */
            p.rx_drop_q_num = CGlobalInfo::m_options.preview.getCores();
        }

    }
    p.rx_desc_num_data_q = RX_DESC_NUM_DATA_Q;
    p.rx_desc_num_drop_q = RX_DESC_NUM_DROP_Q;
    if (get_is_tcp_mode()) {
        /* data queues is the number of cores , drop is the first queue in this mode */
        p.rx_desc_num_drop_q = RX_DESC_NUM_DATA_Q;
    }
    p.tx_desc_num = TX_DESC_NUM;
    p.rx_mbuf_type = MBUF_2048;
}

void CTRexExtendedDriverVirtBase::get_dpdk_drv_params(CTrexDpdkParams &p) {
    p.rx_data_q_num = 1;
    p.rx_drop_q_num = 0;
    p.rx_desc_num_data_q = RX_DESC_NUM_DATA_Q_VM;
    p.rx_desc_num_drop_q = RX_DESC_NUM_DROP_Q;
    p.tx_desc_num = TX_DESC_NUM;
    p.rx_mbuf_type = MBUF_2048;
}

void CTRexExtendedDriverAfPacket::get_dpdk_drv_params(CTrexDpdkParams &p) {
    CTRexExtendedDriverVirtBase::get_dpdk_drv_params(p);
    p.rx_mbuf_type = MBUF_9k;
}

void CTRexExtendedDriverBaseMlnx5G::get_dpdk_drv_params(CTrexDpdkParams &p) {
    CTRexExtendedDriverBase::get_dpdk_drv_params(p);
    if (get_is_tcp_mode()){
        p.rx_mbuf_type = MBUF_9k; /* due to trex-481*/
    }
}

void CTRexExtendedDriverBaseNtAcc::get_dpdk_drv_params(CTrexDpdkParams &p) {
    p.rx_data_q_num = 1;
    p.rx_drop_q_num = 1;
    p.rx_desc_num_data_q = RX_DESC_NUM_DATA_Q;
    p.rx_desc_num_drop_q = RX_DESC_NUM_DROP_Q;
    p.tx_desc_num = TX_DESC_NUM;
    p.rx_mbuf_type = MBUF_9k;
}


// various

int CTRexExtendedDriverBase::stop_queue(CPhyEthIF * _if, uint16_t q_num) {
    repid_t repid =_if->get_repid();

    return (rte_eth_dev_rx_queue_stop(repid, q_num));
}

int CTRexExtendedDriverBase::wait_for_stable_link() {
    wait_x_sec(CGlobalInfo::m_options.m_wait_before_traffic);
    return 0;
}

void CTRexExtendedDriverBase::wait_after_link_up() {
    wait_x_sec(CGlobalInfo::m_options.m_wait_before_traffic);
}

CFlowStatParser *CTRexExtendedDriverBase::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser(CFlowStatParser::FLOW_STAT_PARSER_MODE_HW);
    assert (parser);
    return parser;
}

bool CTRexExtendedDriverBase::get_extended_stats_fixed(CPhyEthIF * _if, CPhyEthIFStats *stats, int fix_i, int fix_o) {
    struct rte_eth_stats stats1;
    struct rte_eth_stats *prev_stats = &stats->m_prev_stats;
    int res;
    
    /* fetch stats */
    res=rte_eth_stats_get(_if->get_repid(), &stats1);
    
    /* check the error flag */
    if (res!=0) {
        /* error (might happen on i40e_vf ) */
        return false;
    }

    stats->ipackets   += stats1.ipackets - prev_stats->ipackets;
    // Some drivers report input byte counts without Ethernet FCS (4 bytes), we need to fix the reported numbers
    stats->ibytes += stats1.ibytes - prev_stats->ibytes + (stats1.ipackets - prev_stats->ipackets) * fix_i;
    stats->opackets   += stats1.opackets - prev_stats->opackets;
    // Some drivers report output byte counts without Ethernet FCS (4 bytes), we need to fix the reported numbers
    stats->obytes += stats1.obytes - prev_stats->obytes + (stats1.opackets - prev_stats->opackets) * fix_o;
    stats->f_ipackets += 0;
    stats->f_ibytes   += 0;
    stats->ierrors    += stats1.imissed + stats1.ierrors + stats1.rx_nombuf
        - prev_stats->imissed - prev_stats->ierrors - prev_stats->rx_nombuf;
    stats->oerrors    += stats1.oerrors - prev_stats->oerrors;
    stats->imcasts    += 0;
    stats->rx_nombuf  += stats1.rx_nombuf - prev_stats->rx_nombuf;

    prev_stats->ipackets = stats1.ipackets;
    prev_stats->ibytes = stats1.ibytes;
    prev_stats->opackets = stats1.opackets;
    prev_stats->obytes = stats1.obytes;
    prev_stats->imissed = stats1.imissed;
    prev_stats->oerrors = stats1.oerrors;
    prev_stats->ierrors = stats1.ierrors;
    prev_stats->rx_nombuf = stats1.rx_nombuf;
    
    return true;
}

// in 1G we need to wait if links became ready to soon
void CTRexExtendedDriverBase1G::wait_after_link_up(){
    wait_x_sec(6 + CGlobalInfo::m_options.m_wait_before_traffic);
}

int CTRexExtendedDriverBase1G::wait_for_stable_link(){
    wait_x_sec(9 + CGlobalInfo::m_options.m_wait_before_traffic);
    return(0);
}

void CTRexExtendedDriverBase1G::update_configuration(port_cfg_t * cfg){
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH_1G;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = 0;
}

void CTRexExtendedDriverBase1G::update_global_config_fdir(port_cfg_t * cfg){
    // Configuration is done in configure_rx_filter_rules by writing to registers
}

#define E1000_RXDCTL_QUEUE_ENABLE	0x02000000
// e1000 driver does not support the generic stop/start queue API, so we need to implement ourselves
int CTRexExtendedDriverBase1G::stop_queue(CPhyEthIF * _if, uint16_t q_num) {
    uint32_t reg_val = _if->pci_reg_read( E1000_RXDCTL(q_num));
    reg_val &= ~E1000_RXDCTL_QUEUE_ENABLE;
    _if->pci_reg_write( E1000_RXDCTL(q_num), reg_val);
    return 0;
}

int CTRexExtendedDriverBase1G::configure_rx_filter_rules(CPhyEthIF * _if){
    if ( get_is_stateless() ) {
        return configure_rx_filter_rules_stateless(_if);
    } else {
        return configure_rx_filter_rules_statefull(_if);
    }

    return 0;
}

int CTRexExtendedDriverBase1G::configure_rx_filter_rules_statefull(CPhyEthIF * _if) {
    uint16_t hops = get_rx_check_hops();
    uint16_t v4_hops = (hops << 8)&0xff00;
    uint8_t protocol;

    if (CGlobalInfo::m_options.m_l_pkt_mode == 0) {
        protocol = IPPROTO_SCTP;
    } else {
        protocol = IPPROTO_ICMP;
    }
    /* enable filter to pass packet to rx queue 1 */
    _if->pci_reg_write( E1000_IMIR(0), 0x00020000);
    _if->pci_reg_write( E1000_IMIREXT(0), 0x00081000);
    _if->pci_reg_write( E1000_TTQF(0),   protocol
                        | 0x00008100 /* enable */
                        | 0xE0010000 /* RX queue is 1 */
                        );


    /* 16  :   12 MAC , (2)0x0800,2      | DW0 , DW1
       6 bytes , TTL , PROTO     | DW2=0 , DW3=0x0000FF06
    */
    int i;
    // IPv4: bytes being compared are {TTL, Protocol}
    uint16_t ff_rules_v4[6]={
        (uint16_t)(0xFF06 - v4_hops),
        (uint16_t)(0xFE11 - v4_hops),
        (uint16_t)(0xFF11 - v4_hops),
        (uint16_t)(0xFE06 - v4_hops),
        (uint16_t)(0xFF01 - v4_hops),
        (uint16_t)(0xFE01 - v4_hops),
    }  ;
    // IPv6: bytes being compared are {NextHdr, HopLimit}
    uint16_t ff_rules_v6[2]={
        (uint16_t)(0x3CFF - hops),
        (uint16_t)(0x3CFE - hops),
    }  ;
    uint16_t *ff_rules;
    uint16_t num_rules;
    uint32_t mask=0;
    int  rule_id;

    if (  CGlobalInfo::m_options.preview.get_ipv6_mode_enable() ){
        ff_rules = &ff_rules_v6[0];
        num_rules = sizeof(ff_rules_v6)/sizeof(ff_rules_v6[0]);
    }else{
        ff_rules = &ff_rules_v4[0];
        num_rules = sizeof(ff_rules_v4)/sizeof(ff_rules_v4[0]);
    }

    clear_rx_filter_rules(_if);

    uint8_t len = 24;
    for (rule_id=0; rule_id<num_rules; rule_id++ ) {
        /* clear rule all */
        for (i=0; i<0xff; i+=4) {
            _if->pci_reg_write( (E1000_FHFT(rule_id)+i) , 0);
        }

        if (CGlobalInfo::m_options.preview.get_vlan_mode() != CPreviewMode::VLAN_MODE_NONE) {
            len += 8;
            if (  CGlobalInfo::m_options.preview.get_ipv6_mode_enable() ){
                // IPv6 VLAN: NextHdr/HopLimit offset = 0x18
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(3*16)+0) , PKT_NTOHS(ff_rules[rule_id]) );
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(3*16)+8) , 0x03); /* MASK */
            }else{
                // IPv4 VLAN: TTL/Protocol offset = 0x1A
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(3*16)+0) , (PKT_NTOHS(ff_rules[rule_id])<<16) );
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(3*16)+8) , 0x0C); /* MASK */
            }
        }else{
            if (  CGlobalInfo::m_options.preview.get_ipv6_mode_enable() ){
                // IPv6: NextHdr/HopLimit offset = 0x14
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16)+4) , PKT_NTOHS(ff_rules[rule_id]) );
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16)+8) , 0x30); /* MASK */
            }else{
                // IPv4: TTL/Protocol offset = 0x16
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16)+4) , (PKT_NTOHS(ff_rules[rule_id])<<16) );
                _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16)+8) , 0xC0); /* MASK */
            }
        }

        // FLEX_PRIO[[18:16] = 1, RQUEUE[10:8] = 1
        _if->pci_reg_write( (E1000_FHFT(rule_id)+0xFC) , (1<<16) | (1<<8)  | len);

        mask |=(1<<rule_id);
    }

    /* enable all rules */
    _if->pci_reg_write(E1000_WUFC, (mask<<16) | (1<<14) );

    return (0);
}


// Sadly, DPDK has no support for i350 filters, so we need to implement by writing to registers.
int CTRexExtendedDriverBase1G::configure_rx_filter_rules_stateless(CPhyEthIF * _if) {
    /* enable filter to pass packet to rx queue 1 */
    _if->pci_reg_write( E1000_IMIR(0), 0x00020000);
    _if->pci_reg_write( E1000_IMIREXT(0), 0x00081000);

    uint8_t len = 24;
    uint32_t mask = 0;
    int rule_id;

    clear_rx_filter_rules(_if);

    rule_id = 0;
    mask |= 0x1 << rule_id;
    // filter for byte 18 of packet (msb of IP ID) should equal ff
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16)) ,  0x00ff0000);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 8) , 0x04); /* MASK */
    // + bytes 12 + 13 (ether type) should indicate IP.
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 4) ,  0x00000008);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 8) , 0x30); /* MASK */
    // FLEX_PRIO[[18:16] = 1, RQUEUE[10:8] = 1
    _if->pci_reg_write( (E1000_FHFT(rule_id) + 0xFC) , (1 << 16) | (1 << 8) | len);

    // same as 0, but with vlan. type should be vlan. Inside vlan, should be IP with lsb of IP ID equals 0xff
    rule_id = 1;
    mask |= 0x1 << rule_id;
    // filter for byte 22 of packet (msb of IP ID) should equal ff
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 4) ,  0x00ff0000);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 8) , 0x40 | 0x03); /* MASK */
    // + bytes 12 + 13 (ether type) should indicate VLAN.
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 4) ,  0x00000081);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 8) , 0x30); /* MASK */
    // + bytes 16 + 17 (vlan type) should indicate IP.
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) ) ,  0x00000008);
    // Was written together with IP ID filter
    // _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 8) , 0x03); /* MASK */
    // FLEX_PRIO[[18:16] = 1, RQUEUE[10:8] = 1
    _if->pci_reg_write( (E1000_FHFT(rule_id) + 0xFC) , (1 << 16) | (1 << 8) | len);

    rule_id = 2;
    mask |= 0x1 << rule_id;
    // ipv6 flow stat
    // filter for byte 16 of packet (part of flow label) should equal 0xff
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16)) ,  0x000000ff);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 8) , 0x01); /* MASK */
    // + bytes 12 + 13 (ether type) should indicate IPv6.
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 4) ,  0x0000dd86);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 8) , 0x30); /* MASK */
    // FLEX_PRIO[[18:16] = 1, RQUEUE[10:8] = 1
    _if->pci_reg_write( (E1000_FHFT(rule_id) + 0xFC) , (1 << 16) | (1 << 8) | len);

    rule_id = 3;
    mask |= 0x1 << rule_id;
    // same as 2, with vlan. Type is vlan. Inside vlan, IPv6 with flow label second bits 4-11 equals 0xff
    // filter for byte 20 of packet (part of flow label) should equal 0xff
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 4) ,  0x000000ff);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 8) , 0x10 | 0x03); /* MASK */
    // + bytes 12 + 13 (ether type) should indicate VLAN.
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 4) ,  0x00000081);
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 8) , 0x30); /* MASK */
    // + bytes 16 + 17 (vlan type) should indicate IP.
    _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) ) ,  0x0000dd86);
    // Was written together with flow label filter
    // _if->pci_reg_write( (E1000_FHFT(rule_id)+(2*16) + 8) , 0x03); /* MASK */
    // FLEX_PRIO[[18:16] = 1, RQUEUE[10:8] = 1
    _if->pci_reg_write( (E1000_FHFT(rule_id) + 0xFC) , (1 << 16) | (1 << 8) | len);

    /* enable rules */
    _if->pci_reg_write(E1000_WUFC, (mask << 16) | (1 << 14) );

    return (0);
}

// clear registers of rules
void CTRexExtendedDriverBase1G::clear_rx_filter_rules(CPhyEthIF * _if) {
    for (int rule_id = 0 ; rule_id < 8; rule_id++) {
        for (int i = 0; i < 0xff; i += 4) {
            _if->pci_reg_write( (E1000_FHFT(rule_id) + i) , 0);
        }
    }
}

int CTRexExtendedDriverBase1G::set_rcv_all(CPhyEthIF * _if, bool set_on) {
    // byte 12 equals 08 - for IPv4 and ARP
    //                86 - For IPv6
    //                81 - For VLAN
    //                88 - For MPLS
    uint8_t eth_types[] = {0x08, 0x86, 0x81, 0x88};
    uint32_t mask = 0;

    clear_rx_filter_rules(_if);

    if (set_on) {
        for (int rule_id = 0; rule_id < sizeof(eth_types); rule_id++) {
            mask |= 0x1 << rule_id;
            // Filter for byte 12 of packet
            _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 4) ,  0x000000 | eth_types[rule_id]);
            _if->pci_reg_write( (E1000_FHFT(rule_id)+(1*16) + 8) , 0x10); /* MASK */
            // FLEX_PRIO[[18:16] = 1, RQUEUE[10:8] = 1, len = 24
            _if->pci_reg_write( (E1000_FHFT(rule_id) + 0xFC) , (1 << 16) | (1 << 8) | 24);
        }
    } else {
        configure_rx_filter_rules(_if);
    }

    return 0;
}

bool CTRexExtendedDriverBase1G::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats){

    stats->ipackets     +=  _if->pci_reg_read(E1000_GPRC) ;

    stats->ibytes       +=  (_if->pci_reg_read(E1000_GORCL) );
    stats->ibytes       +=  (((uint64_t)_if->pci_reg_read(E1000_GORCH))<<32);


    stats->opackets     +=  _if->pci_reg_read(E1000_GPTC);
    stats->obytes       +=  _if->pci_reg_read(E1000_GOTCL) ;
    stats->obytes       +=  ( (((uint64_t)_if->pci_reg_read(IXGBE_GOTCH))<<32) );

    stats->f_ipackets   +=  0;
    stats->f_ibytes     += 0;


    stats->ierrors      +=  ( _if->pci_reg_read(E1000_RNBC) +
                              _if->pci_reg_read(E1000_CRCERRS) +
                              _if->pci_reg_read(E1000_ALGNERRC ) +
                              _if->pci_reg_read(E1000_SYMERRS ) +
                              _if->pci_reg_read(E1000_RXERRC ) +

                              _if->pci_reg_read(E1000_ROC)+
                              _if->pci_reg_read(E1000_RUC)+
                              _if->pci_reg_read(E1000_RJC) +

                              _if->pci_reg_read(E1000_XONRXC)+
                              _if->pci_reg_read(E1000_XONTXC)+
                              _if->pci_reg_read(E1000_XOFFRXC)+
                              _if->pci_reg_read(E1000_XOFFTXC)+
                              _if->pci_reg_read(E1000_FCRUC)
                              );

    stats->oerrors      +=  0;
    stats->imcasts      =  0;
    stats->rx_nombuf    =  0;
    
    return true;
}

void CTRexExtendedDriverBase1G::clear_extended_stats(CPhyEthIF * _if){
}


#if 0
int CTRexExtendedDriverBase1G::get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts
                                            ,uint32_t *bytes, uint32_t *prev_bytes, int min, int max) {
    repid_t repid = _if->get_repid();
    return g_trex.m_rx.get_rx_stats(repid, pkts, prev_pkts, bytes, prev_bytes, min, max);
}
#endif

void CTRexExtendedDriverBase10G::clear_extended_stats(CPhyEthIF * _if){
    _if->pci_reg_read(IXGBE_RXNFGPC);
}

void CTRexExtendedDriverBase10G::update_global_config_fdir(port_cfg_t * cfg) {
    cfg->m_port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT_MAC_VLAN;
    cfg->m_port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
    cfg->m_port_conf.fdir_conf.status = RTE_FDIR_NO_REPORT_STATUS;
    /* Offset of flexbytes field in RX packets (in 16-bit word units). */
    /* Note: divide by 2 to convert byte offset to word offset */
    if (get_is_stateless()) {
        cfg->m_port_conf.fdir_conf.flexbytes_offset = (14+4)/2;
        /* Increment offset 4 bytes for the case where we add VLAN */
        if (  CGlobalInfo::m_options.preview.get_vlan_mode() != CPreviewMode::VLAN_MODE_NONE) {
            cfg->m_port_conf.fdir_conf.flexbytes_offset += (4/2);
        }
    } else {
        if (  CGlobalInfo::m_options.preview.get_ipv6_mode_enable() ) {
            cfg->m_port_conf.fdir_conf.flexbytes_offset = (14+6)/2;
        } else {
            cfg->m_port_conf.fdir_conf.flexbytes_offset = (14+8)/2;
        }

        /* Increment offset 4 bytes for the case where we add VLAN */
        if (  CGlobalInfo::m_options.preview.get_vlan_mode() != CPreviewMode::VLAN_MODE_NONE ) {
            cfg->m_port_conf.fdir_conf.flexbytes_offset += (4/2);
        }
    }
    cfg->m_port_conf.fdir_conf.drop_queue = 1;
}

void CTRexExtendedDriverBase10G::update_configuration(port_cfg_t * cfg){
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
    if ( get_is_tcp_mode() ) {
        cfg->m_port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_CHECKSUM;
        cfg->m_port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_LRO;
    }
}

int CTRexExtendedDriverBase10G::configure_rx_filter_rules(CPhyEthIF * _if) {
    set_rcv_all(_if, false);
    if ( get_is_stateless() ) {
        return configure_rx_filter_rules_stateless(_if);
    } else {
        return configure_rx_filter_rules_statefull(_if);
    }

    return 0;
}

int CTRexExtendedDriverBase10G::configure_rx_filter_rules_stateless(CPhyEthIF * _if) {
    repid_t repid =_if->get_repid();

    uint8_t  ip_id_lsb;

    // 0..128-1 is for rules using ip_id.
    // 128 rule is for the payload rules. Meaning counter value is in the payload
    for (ip_id_lsb = 0; ip_id_lsb <= 128; ip_id_lsb++ ) {
        struct rte_eth_fdir_filter fdir_filter;
        int res = 0;

        memset(&fdir_filter,0,sizeof(fdir_filter));
        fdir_filter.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
        fdir_filter.soft_id = ip_id_lsb; // We can use the ip_id_lsb also as filter soft_id
        if (ip_id_lsb == 128) {
            // payload rule is for 0xffff
            fdir_filter.input.flow_ext.flexbytes[0] = 0xff;
            fdir_filter.input.flow_ext.flexbytes[1] = 0xff;
        } else {
            // less than 255 flow stats, so only byte 1 changes
            fdir_filter.input.flow_ext.flexbytes[0] = 0xff & (IP_ID_RESERVE_BASE >> 8);
            fdir_filter.input.flow_ext.flexbytes[1] = ip_id_lsb;
        }
        fdir_filter.action.rx_queue = 1;
        fdir_filter.action.behavior = RTE_ETH_FDIR_ACCEPT;
        fdir_filter.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;
        res = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &fdir_filter);

        if (res != 0) {
            rte_exit(EXIT_FAILURE, "Error: rte_eth_dev_filter_ctrl in configure_rx_filter_rules_stateless: %d\n",res);
        }
    }

    return 0;
}

int CTRexExtendedDriverBase10G::configure_rx_filter_rules_statefull(CPhyEthIF * _if) {
    repid_t repid=_if->get_repid();
    uint16_t base_hop = get_rx_check_hops();

    /* enable rule 0 SCTP -> queue 1 for latency  */
    /* 1 << 21 means send to queue */
    _if->pci_reg_write(IXGBE_L34T_IMIR(0),(1<<21));
    _if->pci_reg_write(IXGBE_FTQF(0),
                       IXGBE_FTQF_PROTOCOL_SCTP|
                       (IXGBE_FTQF_PRIORITY_MASK<<IXGBE_FTQF_PRIORITY_SHIFT)|
                       ((0x0f)<<IXGBE_FTQF_5TUPLE_MASK_SHIFT)|IXGBE_FTQF_QUEUE_ENABLE);

    // IPv4: bytes being compared are {TTL, Protocol}
    uint16_t ff_rules_v4[3] = {
        0xFF11,
        0xFF06,
        0xFF01,
    };
    // IPv6: bytes being compared are {NextHdr, HopLimit}
    uint16_t ff_rules_v6[1] = {
        0x3CFF
    };

    uint16_t *ff_rules;
    uint16_t num_rules;
    int  rule_id = 1;

    if (  CGlobalInfo::m_options.preview.get_ipv6_mode_enable() ){
        ff_rules = &ff_rules_v6[0];
        num_rules = sizeof(ff_rules_v6)/sizeof(ff_rules_v6[0]);
    }else{
        ff_rules = &ff_rules_v4[0];
        num_rules = sizeof(ff_rules_v4)/sizeof(ff_rules_v4[0]);
    }

    for (int rule_num = 0; rule_num < num_rules; rule_num++ ) {
        struct rte_eth_fdir_filter fdir_filter;
        uint16_t ff_rule = ff_rules[rule_num];
        int res = 0;
        uint16_t v4_hops;

        // configure rule sending packets to RX queue for 10 TTL values
        for (int hops = base_hop; hops < base_hop + 10; hops++) {
            memset(&fdir_filter, 0, sizeof(fdir_filter));
            /* TOS/PROTO */
            if (  CGlobalInfo::m_options.preview.get_ipv6_mode_enable() ) {
                fdir_filter.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV6_OTHER;
                fdir_filter.input.flow_ext.flexbytes[0] = (ff_rule >> 8) & 0xff;
                fdir_filter.input.flow_ext.flexbytes[1] = (ff_rule - hops) & 0xff;
            } else {
                v4_hops = hops << 8;
                fdir_filter.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
                fdir_filter.input.flow_ext.flexbytes[0] = ((ff_rule - v4_hops) >> 8) & 0xff;
                fdir_filter.input.flow_ext.flexbytes[1] = ff_rule & 0xff;
            }
            fdir_filter.soft_id = rule_id++;
            fdir_filter.action.rx_queue = 1;
            fdir_filter.action.behavior = RTE_ETH_FDIR_ACCEPT;
            fdir_filter.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;
            res = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &fdir_filter);

            if (res != 0) {
                rte_exit(EXIT_FAILURE
                         , "Error: rte_eth_dev_filter_ctrl in configure_rx_filter_rules_statefull rule_id:%d: %d\n"
                         , rule_id, res);
            }
        }
    }
    return (0);
}

int CTRexExtendedDriverBase10G::add_del_eth_filter(CPhyEthIF * _if, bool is_add, uint16_t ethertype) {
    int res = 0;
    repid_t repid =_if->get_repid();
    struct rte_eth_ethertype_filter filter;
    enum rte_filter_op op;

    memset(&filter, 0, sizeof(filter));
    filter.ether_type = ethertype;
    res = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_ETHERTYPE, RTE_ETH_FILTER_GET, &filter);

    if (is_add && (res >= 0))
        return 0;
    if ((! is_add) && (res == -ENOENT))
        return 0;

    if (is_add) {
        op = RTE_ETH_FILTER_ADD;
    } else {
        op = RTE_ETH_FILTER_DELETE;
    }

    filter.queue = 1;
    res = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_ETHERTYPE, op, &filter);
    if (res != 0) {
        printf("Error: %s L2 filter for ethertype 0x%04x returned %d\n", is_add ? "Adding":"Deleting", ethertype, res);
        exit(1);
    }
    return 0;
}

int CTRexExtendedDriverBase10G::set_rcv_all(CPhyEthIF * _if, bool set_on) {
    int res = 0;
    res = add_del_eth_filter(_if, set_on, ETHER_TYPE_ARP);
    res |= add_del_eth_filter(_if, set_on, ETHER_TYPE_IPv4);
    res |= add_del_eth_filter(_if, set_on, ETHER_TYPE_IPv6);
    res |= add_del_eth_filter(_if, set_on, ETHER_TYPE_VLAN);
    res |= add_del_eth_filter(_if, set_on, ETHER_TYPE_QINQ);

    return res;
}

bool CTRexExtendedDriverBase10G::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats){

    int i;
    uint64_t t=0;

    if ( !get_is_stateless() ) {

        for (i=0; i<8;i++) {
            t+=_if->pci_reg_read(IXGBE_MPC(i));
        }
    }

    stats->ipackets     +=  _if->pci_reg_read(IXGBE_GPRC) ;

    stats->ibytes       +=  (_if->pci_reg_read(IXGBE_GORCL) +(((uint64_t)_if->pci_reg_read(IXGBE_GORCH))<<32));



    stats->opackets     +=  _if->pci_reg_read(IXGBE_GPTC);
    stats->obytes       +=  (_if->pci_reg_read(IXGBE_GOTCL) +(((uint64_t)_if->pci_reg_read(IXGBE_GOTCH))<<32));

    stats->f_ipackets   +=  _if->pci_reg_read(IXGBE_RXDGPC);
    stats->f_ibytes     += (_if->pci_reg_read(IXGBE_RXDGBCL) +(((uint64_t)_if->pci_reg_read(IXGBE_RXDGBCH))<<32));


    stats->ierrors      +=  ( _if->pci_reg_read(IXGBE_RLEC) +
                              _if->pci_reg_read(IXGBE_ERRBC) +
                              _if->pci_reg_read(IXGBE_CRCERRS) +
                              _if->pci_reg_read(IXGBE_ILLERRC ) +
                              _if->pci_reg_read(IXGBE_ROC)+
                              _if->pci_reg_read(IXGBE_RUC)+t);

    stats->oerrors      +=  0;
    stats->imcasts      =  0;
    stats->rx_nombuf    =  0;

    return true;
}

int CTRexExtendedDriverBase10G::wait_for_stable_link(){
    wait_x_sec(1 + CGlobalInfo::m_options.m_wait_before_traffic);
    return (0);
}

CFlowStatParser *CTRexExtendedDriverBase10G::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser((CGlobalInfo::m_options.preview.get_vlan_mode()
                                                   != CPreviewMode::VLAN_MODE_NONE)
                                                  ? CFlowStatParser::FLOW_STAT_PARSER_MODE_82599_vlan
                                                  : CFlowStatParser::FLOW_STAT_PARSER_MODE_82599);
    assert (parser);
    return parser;
}


void CTRexExtendedDriverBase40G::clear_extended_stats(CPhyEthIF * _if){
    rte_eth_stats_reset(_if->get_repid());
}


void CTRexExtendedDriverBase40G::update_configuration(port_cfg_t * cfg){
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
    cfg->m_port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
    cfg->m_port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
    cfg->m_port_conf.fdir_conf.status = RTE_FDIR_NO_REPORT_STATUS;
    cfg->m_port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_SCATTER;
}

// What is the type of the rule the respective hw_id counter counts.
struct fdir_hw_id_params_t {
    uint16_t rule_type;
    uint8_t l4_proto;
};

static struct fdir_hw_id_params_t fdir_hw_id_rule_params[512];

/* Add rule to send packets with protocol 'type', and ttl 'ttl' to rx queue 1 */
// ttl is used in statefull mode, and ip_id in stateless. We configure the driver registers so that only one of them applies.
// So, the rule will apply if packet has either the correct ttl or IP ID, depending if we are in statfull or stateless.
void CTRexExtendedDriverBase40G::add_del_rules(enum rte_filter_op op, repid_t  repid, uint16_t type, uint8_t ttl
                                               , uint16_t ip_id, uint8_t l4_proto, int queue, uint16_t stat_idx) {
    int ret=rte_eth_dev_filter_supported(repid, RTE_ETH_FILTER_FDIR);
    static int filter_soft_id = 0;

    if ( ret != 0 ){
        rte_exit(EXIT_FAILURE, "rte_eth_dev_filter_supported "
                 "err=%d, port=%u \n",
                 ret, repid);
    }

    struct rte_eth_fdir_filter filter;

    memset(&filter,0,sizeof(struct rte_eth_fdir_filter));

#if 0
    printf("40g::%s rules: port:%d type:%d ttl:%d ip_id:%x l4:%d q:%d hw index:%d\n"
           , (op == RTE_ETH_FILTER_ADD) ?  "add" : "del"
           , repid, type, ttl, ip_id, l4_proto, queue, stat_idx);
#endif

    filter.action.rx_queue = queue;
    filter.action.behavior =RTE_ETH_FDIR_ACCEPT;
    filter.action.report_status =RTE_ETH_FDIR_NO_REPORT_STATUS;
    filter.action.stat_count_index = stat_idx;
    filter.soft_id = filter_soft_id++;
    filter.input.flow_type = type;

    if (op == RTE_ETH_FILTER_ADD) {
        fdir_hw_id_rule_params[stat_idx].rule_type = type;
        fdir_hw_id_rule_params[stat_idx].l4_proto = l4_proto;
    }

    switch (type) {
    case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
    case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
    case RTE_ETH_FLOW_NONFRAG_IPV4_SCTP:
    case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
        filter.input.flow.ip4_flow.ttl=ttl;
        filter.input.flow.ip4_flow.ip_id = ip_id;
        if (l4_proto != 0)
            filter.input.flow.ip4_flow.proto = l4_proto;
        break;
    case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
    case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
    case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
        filter.input.flow.ipv6_flow.hop_limits=ttl;
        filter.input.flow.ipv6_flow.flow_label = ip_id;
        filter.input.flow.ipv6_flow.proto = l4_proto;
        break;
    }

    ret = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_FDIR, op, (void*)&filter);

#if 0
    //todo: fix
    if ( ret != 0 ) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_filter_ctrl: err=%d, port=%u\n",
                 ret, repid);
    }
#endif
}

int CTRexExtendedDriverBase40G::add_del_eth_type_rule(repid_t  repid, enum rte_filter_op op, uint16_t eth_type) {
    int ret;
    struct rte_eth_ethertype_filter filter;

    memset(&filter, 0, sizeof(filter));
    filter.ether_type = eth_type;
    filter.flags = 0;
    filter.queue = MAIN_DPDK_RX_Q;
    ret = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_ETHERTYPE, op, (void *) &filter);

    return ret;
}

uint32_t CTRexExtendedDriverBase40G::get_flow_stats_offset(repid_t repid) {
    uint8_t pf_id;
    int ret = i40e_trex_get_pf_id(repid, &pf_id);
    assert(ret >= 0);
    assert((pf_id >= 0) && (pf_id <= 3));
    return pf_id * m_max_flow_stats;
}


// type - rule type. Currently we only support rules in IP ID.
// proto - Packet protocol: UDP or TCP
// id - Counter id in HW. We assume it is in the range 0..m_max_flow_stats
int CTRexExtendedDriverBase40G::add_del_rx_flow_stat_rule(CPhyEthIF * _if, enum rte_filter_op op, uint16_t l3_proto
                                                          , uint8_t l4_proto, uint8_t ipv6_next_h, uint16_t id) {
    repid_t repid = _if->get_repid();

    uint32_t rule_id = get_flow_stats_offset(repid) + id;
    uint16_t rte_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
    uint8_t next_proto;

    if (l3_proto == EthernetHeader::Protocol::IP) {
        next_proto = l4_proto;
        switch(l4_proto) {
        case IPPROTO_TCP:
            rte_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
            break;
        case IPPROTO_UDP:
            rte_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
            break;
        default:
            rte_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
            break;
        }
    } else {
        // IPv6
        next_proto = ipv6_next_h;
        switch(l4_proto) {
        case IPPROTO_TCP:
            rte_type = RTE_ETH_FLOW_NONFRAG_IPV6_TCP;
            break;
        case IPPROTO_UDP:
            rte_type = RTE_ETH_FLOW_NONFRAG_IPV6_UDP;
            break;
        default:
            rte_type = RTE_ETH_FLOW_NONFRAG_IPV6_OTHER;
            break;
        }
    }

    // If we count flow stat in hardware, we want all packets to be dropped.
    // If we count in software, we want to receive them.
    uint16_t queue;
    if (CGlobalInfo::m_options.preview.get_disable_hw_flow_stat()) {
        queue = MAIN_DPDK_RX_Q;
    } else {
        queue = MAIN_DPDK_DROP_Q;
    }

    add_del_rules(op, repid, rte_type, 0, IP_ID_RESERVE_BASE + id, next_proto, queue, rule_id);
    return 0;
}

int CTRexExtendedDriverBase40G::configure_rx_filter_rules_statefull(CPhyEthIF * _if) {
    repid_t repid=_if->get_repid();
    uint16_t hops = get_rx_check_hops();
    int i;

    rte_eth_fdir_stats_reset(repid, NULL, 0, 1);
    for (i = 0; i < 10; i++) {
        uint8_t ttl = TTL_RESERVE_DUPLICATE - i - hops;
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, ttl, 0, 0, MAIN_DPDK_RX_Q, 0);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, ttl, 0, 0, MAIN_DPDK_RX_Q, 0);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_UDP, ttl, 0, RX_CHECK_V6_OPT_TYPE, MAIN_DPDK_RX_Q, 0);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_TCP, ttl, 0, RX_CHECK_V6_OPT_TYPE, MAIN_DPDK_RX_Q, 0);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, ttl, 0, RX_CHECK_V6_OPT_TYPE, MAIN_DPDK_RX_Q, 0);
        /* Rules for latency measurement packets */
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, ttl, 0, IPPROTO_ICMP, MAIN_DPDK_RX_Q, 0);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_SCTP, ttl, 0, 0, MAIN_DPDK_RX_Q, 0);
    }
    return 0;
}

const uint32_t FDIR_TEMP_HW_ID = 511;
const uint32_t FDIR_PAYLOAD_RULES_HW_ID = 510;
extern const uint32_t FLOW_STAT_PAYLOAD_IP_ID;
int CTRexExtendedDriverBase40G::configure_rx_filter_rules(CPhyEthIF * _if) {
    repid_t repid=_if->get_repid();

    if (get_is_stateless()) {
        i40e_trex_fdir_reg_init(repid, I40E_TREX_INIT_STL);

        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, 0
                      , FLOW_STAT_PAYLOAD_IP_ID, 0, MAIN_DPDK_RX_Q, FDIR_PAYLOAD_RULES_HW_ID);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, 0
                      , FLOW_STAT_PAYLOAD_IP_ID, 0, MAIN_DPDK_RX_Q, FDIR_PAYLOAD_RULES_HW_ID);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 0
                      , FLOW_STAT_PAYLOAD_IP_ID, IPPROTO_ICMP, MAIN_DPDK_RX_Q, FDIR_PAYLOAD_RULES_HW_ID);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_UDP, 0
                      , FLOW_STAT_PAYLOAD_IP_ID, 0, MAIN_DPDK_RX_Q, FDIR_PAYLOAD_RULES_HW_ID);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_TCP, 0
                      , FLOW_STAT_PAYLOAD_IP_ID, 0, MAIN_DPDK_RX_Q, FDIR_PAYLOAD_RULES_HW_ID);
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 0
                      , FLOW_STAT_PAYLOAD_IP_ID, 0, MAIN_DPDK_RX_Q, FDIR_PAYLOAD_RULES_HW_ID);

        rte_eth_fdir_stats_reset(repid, NULL, FDIR_TEMP_HW_ID, 1);
        return 0; // Other rules are configured dynamically in stateless
    } else {
        i40e_trex_fdir_reg_init(repid, I40E_TREX_INIT_STF);
        return configure_rx_filter_rules_statefull(_if);
    }
}

void CTRexExtendedDriverBase40G::reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len) {

    repid_t repid = _if->get_repid();

    uint32_t rule_id = get_flow_stats_offset(repid) + min;

    // Since flow dir counters are not wrapped around as promised in the data sheet, but rather get stuck at 0xffffffff
    // we reset the HW value
    rte_eth_fdir_stats_reset(repid, NULL, rule_id, len);

    for (int i =0; i < len; i++) {
        stats[i] = 0;
    }
}


// get rx stats on _if, between min and max
// prev_pkts should be the previous values read from the hardware.
//            Getting changed to be equal to current HW values.
// pkts return the diff between prev_pkts and current hw values
// bytes and prev_bytes are not used. X710 fdir filters do not support byte count.
int CTRexExtendedDriverBase40G::get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts
                                             ,uint32_t *bytes, uint32_t *prev_bytes, int min, int max) {
    uint32_t hw_stats[MAX_FLOW_STATS_XL710];
    repid_t repid = _if->get_repid();

    uint32_t start = get_flow_stats_offset(repid) + min;
    uint32_t len = max - min + 1;

    rte_eth_fdir_stats_get(repid, hw_stats, start, len);
    for (int i = min; i <= max; i++) {
        if (unlikely(hw_stats[i - min] > CGlobalInfo::m_options.get_x710_fdir_reset_threshold())) {
            // When x710 fdir counters reach max of 32 bits (4G), they get stuck. To handle this, we temporarily
            // move to temp counter, reset the counter in danger, and go back to using it.
            // see trex-199 for more details
            uint32_t counter, temp_count=0;
            uint32_t hw_id = start - min + i;

            add_del_rules( RTE_ETH_FILTER_ADD, repid, fdir_hw_id_rule_params[hw_id].rule_type, 0
                           , IP_ID_RESERVE_BASE + i, fdir_hw_id_rule_params[hw_id].l4_proto, MAIN_DPDK_DROP_Q
                           , FDIR_TEMP_HW_ID);
            rte_eth_fdir_stats_reset(repid, &counter, hw_id, 1);
            add_del_rules( RTE_ETH_FILTER_ADD, repid, fdir_hw_id_rule_params[hw_id].rule_type, 0
                           , IP_ID_RESERVE_BASE + i, fdir_hw_id_rule_params[hw_id].l4_proto, MAIN_DPDK_DROP_Q, hw_id);
            rte_eth_fdir_stats_reset(repid, &temp_count, FDIR_TEMP_HW_ID, 1);
            pkts[i] = counter + temp_count - prev_pkts[i];
            prev_pkts[i] = 0;
        } else {
            pkts[i] = hw_stats[i - min] - prev_pkts[i];
            prev_pkts[i] = hw_stats[i - min];
        }
        bytes[i] = 0;
    }

    return 0;
}

// if fd != NULL, dump fdir stats of _if
// return num of filters
int CTRexExtendedDriverBase40G::dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd)
{
    repid_t repid = _if->get_repid();

    struct rte_eth_fdir_stats stat;
    int ret;

    ret = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_STATS, (void*)&stat);
    if (ret == 0) {
        if (fd)
            fprintf(fd, "Num filters on guarant poll:%d, best effort poll:%d\n", stat.guarant_cnt, stat.best_cnt);
        return (stat.guarant_cnt + stat.best_cnt);
    } else {
        if (fd)
            fprintf(fd, "Failed reading fdir statistics\n");
        return -1;
    }
}

bool CTRexExtendedDriverBase40G::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
    return get_extended_stats_fixed(_if, stats, 4, 4);
}

int CTRexExtendedDriverBase40G::wait_for_stable_link(){
    wait_x_sec(1 + CGlobalInfo::m_options.m_wait_before_traffic);
    return (0);
}


int CTRexExtendedDriverBase40G::verify_fw_ver(tvpid_t   tvpid) {
    uint32_t version;
    int ret;

    repid_t repid=CTVPort(tvpid).get_repid();

    ret = rte_eth_get_fw_ver(repid, &version);

    if (ret == 0) {
        if (CGlobalInfo::m_options.preview.getVMode() >= 1) {
            printf("port %d: FW ver %02d.%02d.%02d\n", (int)repid, ((version >> 12) & 0xf), ((version >> 4) & 0xff)
                   ,(version & 0xf));
        }

        if ((((version >> 12) & 0xf) < 5)  || ((((version >> 12) & 0xf) == 5) && ((version >> 4 & 0xff) == 0)
                                               && ((version & 0xf) < 4))) {
            printf("Error: In this TRex version, X710 firmware must be at least 05.00.04\n");
            printf("  Please refer to %s for upgrade instructions\n",
                   "https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_firmware_update_to_xl710_x710");
            exit(1);
        }
    }

    return ret;
}

CFlowStatParser *CTRexExtendedDriverBase40G::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser(CFlowStatParser::FLOW_STAT_PARSER_MODE_HW);
    assert (parser);
    return parser;
}

int CTRexExtendedDriverBase40G::set_rcv_all(CPhyEthIF * _if, bool set_on) {

    repid_t repid=_if->get_repid();

    enum rte_filter_op op = set_on ? RTE_ETH_FILTER_ADD : RTE_ETH_FILTER_DELETE;

    for (int i = 0; i < sizeof(all_eth_types)/sizeof(uint16_t); i++) {
        add_del_eth_type_rule(repid, op, all_eth_types[i]);
    }

    if (set_on) {
        i40e_trex_fdir_reg_init(repid, I40E_TREX_INIT_RCV_ALL);
    }

    // In order to receive packets, we also need to configure rules for each type.
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV4_SCTP, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV6_UDP, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV6_TCP, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV6_SCTP, 10, 0, 0, MAIN_DPDK_RX_Q, 0);
    add_del_rules(op, repid, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 10, 0, 0, MAIN_DPDK_RX_Q, 0);

    if (! set_on) {
        configure_rx_filter_rules(_if);
    }

    return 0;
}


void CTRexExtendedDriverMlnx4::update_configuration(port_cfg_t * cfg) {
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
}



/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/* MLX5 */


void CTRexExtendedDriverBaseMlnx5G::clear_extended_stats(CPhyEthIF * _if){
    repid_t repid=_if->get_repid();
    rte_eth_stats_reset(repid);
}

void CTRexExtendedDriverBaseMlnx5G::update_configuration(port_cfg_t * cfg){
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
    cfg->m_port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
    cfg->m_port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
    cfg->m_port_conf.fdir_conf.status = RTE_FDIR_NO_REPORT_STATUS;
}

void CTRexExtendedDriverBaseMlnx5G::reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len) {
    for (int i =0; i < len; i++) {
        stats[i] = 0;
    }
}

int CTRexExtendedDriverBaseMlnx5G::get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts
                                             ,uint32_t *bytes, uint32_t *prev_bytes, int min, int max) {
    /* not supported yet */
    return 0;
}

int CTRexExtendedDriverBaseMlnx5G::dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd)
{
    repid_t repid=_if->get_repid();
    struct rte_eth_fdir_stats stat;
    int ret;

    ret = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_STATS, (void*)&stat);
    if (ret == 0) {
        if (fd)
            fprintf(fd, "Num filters on guarant poll:%d, best effort poll:%d\n", stat.guarant_cnt, stat.best_cnt);
        return (stat.guarant_cnt + stat.best_cnt);
    } else {
        if (fd)
            fprintf(fd, "Failed reading fdir statistics\n");
        return -1;
    }
}

bool CTRexExtendedDriverBaseMlnx5G::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats){
    return get_extended_stats_fixed(_if, stats, 4, 4);
}

int CTRexExtendedDriverBaseMlnx5G::wait_for_stable_link(){
    delay(20);
    return (0);
}

CFlowStatParser *CTRexExtendedDriverBaseMlnx5G::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser(CFlowStatParser::FLOW_STAT_PARSER_MODE_HW);
    assert (parser);
    return parser;
}

//////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/* VIC */

void CTRexExtendedDriverBaseVIC::update_configuration(port_cfg_t * cfg){
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
    cfg->m_port_conf.rxmode.max_rx_pkt_len =9*1000-10;
    cfg->m_port_conf.fdir_conf.mask.ipv4_mask.tos = 0x01;
    cfg->m_port_conf.fdir_conf.mask.ipv6_mask.tc  = 0x01;
}

void CTRexExtendedDriverBaseVIC::add_del_rules(enum rte_filter_op op, repid_t  repid, uint16_t type
                                               , uint16_t id, uint8_t l4_proto, uint8_t tos, int queue) {
    int ret=rte_eth_dev_filter_supported(repid, RTE_ETH_FILTER_FDIR);

    if ( ret != 0 ){
        rte_exit(EXIT_FAILURE, "rte_eth_dev_filter_supported "
                 "err=%d, port=%u \n",
                 ret, repid);
    }

    struct rte_eth_fdir_filter filter;

    memset(&filter,0,sizeof(struct rte_eth_fdir_filter));

#if 0
    printf("VIC add_del_rules::%s rules: port:%d type:%d id:%d l4:%d tod:%d, q:%d\n"
           , (op == RTE_ETH_FILTER_ADD) ?  "add" : "del"
           , port_id, type, id, l4_proto, tos, queue);
#endif

    filter.action.rx_queue = queue;
    filter.action.behavior = RTE_ETH_FDIR_ACCEPT;
    filter.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;
    filter.soft_id = id;
    filter.input.flow_type = type;

    switch (type) {
    case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
    case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
    case RTE_ETH_FLOW_NONFRAG_IPV4_SCTP:
    case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
        filter.input.flow.ip4_flow.tos = tos;
        filter.input.flow.ip4_flow.proto = l4_proto;
        break;
    case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
    case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
    case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
        filter.input.flow.ipv6_flow.tc = tos;
        filter.input.flow.ipv6_flow.proto = l4_proto;
        break;
    }

    ret = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_FDIR, op, (void*)&filter);
    if ( ret != 0 ) {
        if (((op == RTE_ETH_FILTER_ADD) && (ret == -EEXIST)) || ((op == RTE_ETH_FILTER_DELETE) && (ret == -ENOENT)))
            return;

        rte_exit(EXIT_FAILURE, "rte_eth_dev_filter_ctrl: err=%d, port=%u\n",
                 ret, repid);
    }
}

int CTRexExtendedDriverBaseVIC::add_del_eth_type_rule(repid_t  repid, enum rte_filter_op op, uint16_t eth_type) {
    int ret;
    struct rte_eth_ethertype_filter filter;

    memset(&filter, 0, sizeof(filter));
    filter.ether_type = eth_type;
    filter.flags = 0;
    filter.queue = MAIN_DPDK_RX_Q;
    ret = rte_eth_dev_filter_ctrl(repid, RTE_ETH_FILTER_ETHERTYPE, op, (void *) &filter);

    return ret;
}

int CTRexExtendedDriverBaseVIC::configure_rx_filter_rules_statefull(CPhyEthIF * _if) {
    repid_t  repid = _if->get_repid();

    set_rcv_all(_if, false);

    // Rules to direct all IP packets with tos lsb bit 1 to RX Q.
    // IPv4
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, 1, 17, 0x1, MAIN_DPDK_RX_Q);
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, 1, 6,  0x1, MAIN_DPDK_RX_Q);
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_SCTP, 1, 132,  0x1, MAIN_DPDK_RX_Q); /*SCTP*/
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 1, 1,  0x1, MAIN_DPDK_RX_Q);  /*ICMP*/
    // Ipv6
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 1, 6,  0x1, MAIN_DPDK_RX_Q);
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_UDP, 1, 17,  0x1, MAIN_DPDK_RX_Q);

    // Because of some issue with VIC firmware, IPv6 UDP and ICMP go by default to q 1, so we
    // need these rules to make them go to q 0.
    // rule appply to all packets with 0 on tos lsb.
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 1, 6,  0, MAIN_DPDK_DROP_Q);
    add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV6_UDP, 1, 17,  0, MAIN_DPDK_DROP_Q);

    return 0;
}


int CTRexExtendedDriverBaseVIC::set_rcv_all(CPhyEthIF * _if, bool set_on) {
    repid_t repid=_if->get_repid();

    // soft ID 100 tells VIC driver to add rule for all ether types.
    // Added with highest priority (implicitly in the driver), so if it exists, it applies before all other rules
    if (set_on) {
        add_del_rules(RTE_ETH_FILTER_ADD, repid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, 100, 30, 0, MAIN_DPDK_RX_Q);
    } else {
        add_del_rules(RTE_ETH_FILTER_DELETE, repid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, 100, 30, 0, MAIN_DPDK_RX_Q);
    }

    return 0;

}

void CTRexExtendedDriverBaseVIC::clear_extended_stats(CPhyEthIF * _if){
    repid_t repid=_if->get_repid();
    rte_eth_stats_reset(repid);
}

bool CTRexExtendedDriverBaseVIC::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
    // In VIC, we need to reduce 4 bytes from the amount reported for each incoming packet
    return get_extended_stats_fixed(_if, stats, -4, 0);
}

int CTRexExtendedDriverBaseVIC::verify_fw_ver(tvpid_t   tvpid) {

    repid_t repid = CTVPort(tvpid).get_repid();

    if (CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_ONE_QUEUE
        || CGlobalInfo::get_queues_mode() == CGlobalInfo::Q_MODE_RSS) {
        return 0;
    }

    struct rte_eth_fdir_info fdir_info;

    if ( rte_eth_dev_filter_ctrl(repid,RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_INFO,(void *)&fdir_info) == 0 ){
        if ( fdir_info.flow_types_mask[0] & (1<< RTE_ETH_FLOW_NONFRAG_IPV4_OTHER) ) {
           /* support new features */
            if (CGlobalInfo::m_options.preview.getVMode() >= 1) {
                printf("VIC port %d: FW support advanced filtering \n", repid);
            }
            return 0;
        }
    }

    printf("Warning: In order to fully utilize the VIC NIC, firmware should be upgraded to support advanced filtering \n");
    printf("  Please refer to %s for upgrade instructions\n",
           "https://trex-tgn.cisco.com/trex/doc/trex_manual.html");
    printf("If this is an unsupported card, or you do not want to upgrade, you can use --software command line arg\n");
    printf("This will work without hardware support (meaning reduced performance)\n");
    exit(1);
}

int CTRexExtendedDriverBaseVIC::configure_rx_filter_rules(CPhyEthIF * _if) {

    if (get_is_stateless()) {
        /* both stateless and stateful work in the same way, might changed in the future TOS */
        return configure_rx_filter_rules_statefull(_if);
    } else {
        return configure_rx_filter_rules_statefull(_if);
    }
}

void CTRexExtendedDriverBaseVIC::reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len) {
}

int CTRexExtendedDriverBaseVIC::get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts
                                             ,uint32_t *bytes, uint32_t *prev_bytes, int min, int max) {
    printf(" NOT supported yet \n");
    return 0;
}

// if fd != NULL, dump fdir stats of _if
// return num of filters
int CTRexExtendedDriverBaseVIC::dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd)
{
 //printf(" NOT supported yet \n");
 return (0);
}

CFlowStatParser *CTRexExtendedDriverBaseVIC::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser(CFlowStatParser::FLOW_STAT_PARSER_MODE_HW);
    assert (parser);
    return parser;
}


//////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/* NTACC */

void CTRexExtendedDriverBaseNtAcc::update_configuration(port_cfg_t * cfg){
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
    cfg->m_port_conf.rxmode.max_rx_pkt_len =9000;
}

CTRexExtendedDriverBaseNtAcc::~CTRexExtendedDriverBaseNtAcc() {
    struct fid_s *fid, *tfid;
    TAILQ_FOREACH_SAFE(fid, &lh_fid, leTQ, tfid) {
        TAILQ_REMOVE(&lh_fid, fid, leTQ);
        ntacc_del_rules(fid->port_id, fid->rte_flow);
        free(fid);
    }
}

void CTRexExtendedDriverBaseNtAcc::add_del_rules(enum rte_filter_op op, uint8_t port_id, uint16_t type,
    uint8_t l4_proto, int queue, uint32_t f_id, char *ntpl_str) {
    int ret=rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_GENERIC);
    if ( ret != 0 ){
        rte_exit(EXIT_FAILURE, "rte_eth_dev_filter_supported "
                 "err=%d, port=%u \n",
                 ret, port_id);
    }

    // rte_flow.h cannot be included from C++ so we need to call a NtAcc specific C function.
    if (op == RTE_ETH_FILTER_ADD) {
        void *rte_flow = ntacc_add_rules(port_id, type, l4_proto, queue, ntpl_str);

        if (rte_flow == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to add RTE_FLOW\n");
        }

        fid_s *fid = (fid_s*)malloc(sizeof(fid_s));
        if (fid == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to allocate memory\n");
        }

        fid->id = f_id;
        fid->port_id = port_id;
        fid->rte_flow = rte_flow;
        TAILQ_INSERT_TAIL(&lh_fid, fid, leTQ);
    } else {
        fid_s *fid, *tfid;
        TAILQ_FOREACH_SAFE(fid, &lh_fid, leTQ, tfid) {
            if ((fid->id == f_id) && (fid->port_id == port_id)){
                TAILQ_REMOVE(&lh_fid, fid, leTQ);
                ntacc_del_rules(port_id, fid->rte_flow);
                free(fid);
            }
        }
    }
}

int CTRexExtendedDriverBaseNtAcc::add_del_eth_type_rule(uint8_t port_id, enum rte_filter_op op, uint16_t eth_type) {
    int ret=rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_GENERIC);

    if ( ret != 0 ){
        rte_exit(EXIT_FAILURE, "rte_eth_dev_filter_supported "
                 "err=%d, port=%u \n",
                 ret, port_id);
    }
    return ret;
}

int CTRexExtendedDriverBaseNtAcc::configure_rx_filter_rules_stateless(CPhyEthIF * _if) {
    set_rcv_all(_if, false);
    repid_t port_id =_if->get_repid();

#if 0
    // Enable this when all NICs have rte_flow support
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 1, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 6, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 17, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, 132, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 1, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 6, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 17, MAIN_DPDK_RX_Q, 0, NULL);
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, 132, MAIN_DPDK_RX_Q, 0, NULL);
#else
    // Not all NICs have proper rte_flow support. use the Napatech Filter Language for now.
    char ntpl_str[] =
        "((Data[DynOffset = DynOffIpv4Frame; Offset = 1; DataType = ByteStr1 ; DataMask = [0:0]] == 1) OR "
        " (Data[DynOffset = DynOffIpv6Frame; Offset = 0; DataType = ByteStr2 ; DataMask = [11:11]] == 1)) AND "
        "Layer4Protocol == ICMP,UDP,TCP,SCTP";
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NTPL, 0, MAIN_DPDK_RX_Q, 0, ntpl_str);
#endif
    return 0;
}

int CTRexExtendedDriverBaseNtAcc::configure_rx_filter_rules_statefull(CPhyEthIF * _if) {
    set_rcv_all(_if, false);
    repid_t port_id =_if->get_repid();

    char ntpl_str[] =
        "((Data[DynOffset = DynOffIpv4Frame; Offset = 1; DataType = ByteStr1 ; DataMask = [0:0]] == 1) OR "
        " (Data[DynOffset = DynOffIpv6Frame; Offset = 0; DataType = ByteStr2 ; DataMask = [11:11]] == 1) OR "
        " (Data[DynOffset = DynOffIpv4Frame; Offset = 8; DataType = ByteStr2] == 0xFF11,0xFF06,0xFF01) OR "
        " (Data[DynOffset = DynOffIpv6Frame; Offset = 6; DataType = ByteStr2] == 0x3CFF)) AND "
        "Layer4Protocol == ICMP,UDP,TCP,SCTP";
    add_del_rules(RTE_ETH_FILTER_ADD, port_id, RTE_ETH_FLOW_NTPL, 0, MAIN_DPDK_RX_Q, 0, ntpl_str);
    return 0;
}


int CTRexExtendedDriverBaseNtAcc::set_rcv_all(CPhyEthIF * _if, bool set_on) {
    repid_t port_id =_if->get_repid();
    add_del_rules(set_on == true ? RTE_ETH_FILTER_ADD : RTE_ETH_FILTER_DELETE,
        port_id, RTE_ETH_FLOW_RAW, 0, MAIN_DPDK_RX_Q, 1, NULL);
    return 0;
}

void CTRexExtendedDriverBaseNtAcc::clear_extended_stats(CPhyEthIF * _if){
    rte_eth_stats_reset(_if->get_repid());
}

bool CTRexExtendedDriverBaseNtAcc::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
    return get_extended_stats_fixed(_if, stats, 0, 0);
}

int CTRexExtendedDriverBaseNtAcc::verify_fw_ver(int port_id) {
    return 0;
}

int CTRexExtendedDriverBaseNtAcc::configure_rx_filter_rules(CPhyEthIF * _if) {
    if (get_is_stateless()) {
        /* Statefull currently work as stateless */
        return configure_rx_filter_rules_stateless(_if);
    } else {
        return configure_rx_filter_rules_statefull(_if);
    }
}

void CTRexExtendedDriverBaseNtAcc::reset_rx_stats(CPhyEthIF * _if, uint32_t *stats, int min, int len) {
}

int CTRexExtendedDriverBaseNtAcc::get_rx_stats(CPhyEthIF * _if, uint32_t *pkts, uint32_t *prev_pkts
                                             ,uint32_t *bytes, uint32_t *prev_bytes, int min, int max) {
  //TODO:
  return 0;
}

// if fd != NULL, dump fdir stats of _if
// return num of filters
int CTRexExtendedDriverBaseNtAcc::dump_fdir_global_stats(CPhyEthIF * _if, FILE *fd)
{
 return (0);
}

CFlowStatParser *CTRexExtendedDriverBaseNtAcc::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser(CFlowStatParser::FLOW_STAT_PARSER_MODE_HW);
    assert (parser);
    return parser;
}



/////////////////////////////////////////////////////////////////////////////////////
void CTRexExtendedDriverVirtBase::update_configuration(port_cfg_t * cfg) {
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH_1G;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = 0;
}

int CTRexExtendedDriverVirtBase::configure_rx_filter_rules(CPhyEthIF * _if){
    return (0);
}

void CTRexExtendedDriverVirtBase::clear_extended_stats(CPhyEthIF * _if){
    repid_t repid =_if->get_repid();
    rte_eth_stats_reset(repid);
}

int CTRexExtendedDriverVirtBase::stop_queue(CPhyEthIF * _if, uint16_t q_num) {
    return (0);
}

int CTRexExtendedDriverVirtBase::wait_for_stable_link(){
    wait_x_sec(CGlobalInfo::m_options.m_wait_before_traffic);
    return (0);
}

CFlowStatParser *CTRexExtendedDriverVirtBase::get_flow_stat_parser() {
    CFlowStatParser *parser = new CFlowStatParser(CFlowStatParser::FLOW_STAT_PARSER_MODE_SW);
    assert (parser);
    return parser;
}



void CTRexExtendedDriverVirtio::update_configuration(port_cfg_t * cfg) {
    CTRexExtendedDriverVirtBase::update_configuration(cfg);
    rte_eth_rxmode *rxmode = &cfg->m_port_conf.rxmode;
    if ( get_is_tcp_mode() ) {
        rxmode->offloads |= DEV_RX_OFFLOAD_TCP_LRO;
    }
    if (rxmode->max_rx_pkt_len > g_dev_info.max_rx_pktlen ) {
        rxmode->max_rx_pkt_len = g_dev_info.max_rx_pktlen;
    }
}


bool CTRexExtendedDriverVirtio::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
    return get_extended_stats_fixed(_if, stats, 4, 4);
}

bool CTRexExtendedDriverVmxnet3::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
    return get_extended_stats_fixed(_if, stats, 4, 4);
}

bool CTRexExtendedDriverAfPacket::get_extended_stats(CPhyEthIF * _if, CPhyEthIFStats *stats) {
    return get_extended_stats_fixed(_if, stats, 4, 4);
}

bool CTRexExtendedDriverBaseE1000::get_extended_stats(CPhyEthIF * _if,CPhyEthIFStats *stats) {
    return get_extended_stats_fixed(_if, stats, 0, 4);
}

void CTRexExtendedDriverBaseE1000::update_configuration(port_cfg_t * cfg) {
    CTRexExtendedDriverVirtBase::update_configuration(cfg);
    // We configure hardware not to strip CRC. Then DPDK driver removes the CRC.
    // If configuring "hardware" to remove CRC, due to bug in ESXI e1000 emulation, we got packets with CRC.
    cfg->m_port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_CRC_STRIP;
}


/////////////////////////////////////////////////////////// VMxnet3
void CTRexExtendedDriverVmxnet3::update_configuration(port_cfg_t * cfg){
    CTRexExtendedDriverVirtBase::update_configuration(cfg);
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH_1G;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = 0;
    if ( get_is_tcp_mode() ) {
        cfg->m_port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_LRO;
    }
    cfg->m_port_conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_CRC_STRIP;
}

void CTRexExtendedDriverAfPacket::update_configuration(port_cfg_t * cfg){
    CTRexExtendedDriverVirtBase::update_configuration(cfg);
    cfg->m_port_conf.rxmode.max_rx_pkt_len = 1514;
    cfg->m_port_conf.rxmode.offloads = 0;
}

///////////////////////////////////////////////////////// VF
void CTRexExtendedDriverI40evf::update_configuration(port_cfg_t * cfg) {
    CTRexExtendedDriverVirtBase::update_configuration(cfg);
    cfg->m_tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    cfg->m_tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    cfg->m_tx_conf.tx_thresh.wthresh = TX_WTHRESH;
}

