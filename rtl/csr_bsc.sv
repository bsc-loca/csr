/*
 * Copyright 2023 BSC*
 * *Barcelona Supercomputing Center (BSC)
 * 
 * SPDX-License-Identifier: Apache-2.0 WITH SHL-2.1
 * 
 * Licensed under the Solderpad Hardware License v 2.1 (the “License”); you
 * may not use this file except in compliance with the License, or, at your
 * option, the Apache License version 2.0. You may obtain a copy of the
 * License at
 * 
 * https://solderpad.org/licenses/SHL-2.1/
 * 
 * Unless required by applicable law or agreed to in writing, any work
 * distributed under the License is distributed on an “AS IS” BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

module csr_bsc#(
    parameter def_pkg::core_type_t CORE_TYPE = def_pkg::SARGANTANA_CORE,
    parameter WORD_WIDTH = 64,
    parameter PPN_WIDTH = 20,
    parameter PROGRAM_BUFFER_ADDR = 'h400,
    parameter CSR_ADDR_WIDTH = 12,
    parameter ASID_WIDTH = 13,
    parameter VMID_WIDTH = 11,
    parameter RETIRE_BW = 2,
    parameter VLEN_V = 16384
)(
    input logic                             clk_i,
    input logic                             rstn_i,

    input logic [WORD_WIDTH-1:0]            core_id_i,                    // hartid, for multicore systems
    `ifdef PITON_CINCORANCH
    input   logic [1:0]                     boot_main_id_i,             // CINCORANCH Specific boot id 
    `endif  // Custom for CincoRanch
    input logic [WORD_WIDTH-1:0]            trap_vector_addr_i,         // Address of trap vector, set on reset

    // RW interface with the core
    input logic [CSR_ADDR_WIDTH-1:0]        rw_addr_i,                  //read and write address form the core
    input logic [3:0]                       rw_cmd_i,                   //specific operation to execute from the core 
    input logic                             csr_hs_ld_st_inst_i,        //instruction is a Hypervisor Load/Store Instruction
    input logic [WORD_WIDTH-1:0]            w_data_core_i,              //write data from the core
    output logic [WORD_WIDTH-1:0]           r_data_core_o,              // read data to the core, address specified with the rw_addr_i

    //Exceptions 
    input logic                             ex_i,                       // exception produced in the core
    input logic [WORD_WIDTH-1:0]            ex_cause_i,                 //cause of the exception
    input logic [63:0]                      ex_origin_i,                //origin of the exception
    input logic [63:0]                      ex_origin2_i,               //origin of the exception when the causing exception in a guest exception
    input logic [63:0]                      ex_tinst_i,                 //transformed instruction information
    input logic                             ex_gva_i,                   //signals when a guest virtual address is written to tval
    input logic [63:0]                      pc_i,                       //pc were the exception is produced

    input logic [RETIRE_BW-1:0]             retire_i,                   // shows if a instruction is retired from the core.
    
    `ifdef LOX
    `ifdef SIM_COMMIT_LOG_DPI
    input logic                             torture_dpi_we_i,
    `endif
    `endif

    //Interruptions
    input logic                             time_irq_i,                 // timer interrupt
    input logic [1:0]                       irq_i,                      // external interrupt input - [0] = Machine, [1] = Supervisor
    input logic                             m_soft_irq_i,               // Machine software interrupt form the axi module
    output logic                            interrupt_o,                // Inerruption wire to the core
    output logic [WORD_WIDTH-1:0]           interrupt_cause_o,          // Interruption cause

    input  logic [WORD_WIDTH-1:0]           time_i,                    // time passed since the core is reset

`ifdef CONF_SARGANTANA_ENABLE_PCR
    //PCR req inputs
    input  logic                            pcr_req_ready_i,            // ready bit of the pcr

    //PCR resp inputs
    input  logic                            pcr_resp_valid_i,           // ready bit of the pcr
    input  logic [WORD_WIDTH-1:0]           pcr_resp_data_i,            // read data from performance counter module
    input  logic [WORD_WIDTH-1:0]           pcr_resp_core_id_i,         // core id of the tile that the date is sended

    //PCR outputs request
    output logic                            pcr_req_valid_o,            // valid bit to make a pcr request
    output logic  [CSR_ADDR_WIDTH-1:0]      pcr_req_addr_o,             // read/write address to performance counter module (up to 29 aux counters possible in riscv encoding.h)
    output logic  [63:0]                    pcr_req_data_o,             // write data to performance counter module
    output logic  [2:0]                     pcr_req_we_o,               // Cmd of the petition
    output logic  [WORD_WIDTH-1:0]          pcr_req_core_id_o,          // core id of the tile
`endif // CONF_SARGANTANA_ENABLE_PCR

`ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
    output logic [63:0]                     dyn_fpga_mem_latency_o,
`endif // CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY

    // floating point flags
    input logic                             freg_modified_i,
    input logic                             fcsr_flags_valid_i,
    input logic [4:0]                       fcsr_flags_bits_i,
    output logic [2:0]                      fcsr_rm_o,
    output logic [1:0]                      fcsr_fs_o,

    // CMO conf flag
    output logic [3:0]                      csr_m_cmo_cfg_o,           // M mode cmo related flags (CBIE, CBCFE, CBZE)
    output logic [3:0]                      csr_s_cmo_cfg_o,           // S mode cmo related flags (CBIE, CBCFE, CBZE)
    output logic [3:0]                      csr_h_cmo_cfg_o,           // H extension cmo related flags (CBIE, CBCFE, CBZE)

    output logic [1:0]                      vcsr_vs_o,
    input logic                             vreg_modified_i,
    input logic                             vxsat_i,

    output logic                            csr_replay_o,               // replay send to the core because there are some parts that are bussy
    output logic                            csr_stall_o,                // The csr are waiting a resp and de core is stalled
    output logic                            csr_xcpt_o,                 // Exeption pproduced by the csr   
    output logic [63:0]                     csr_xcpt_cause_o,           // Exception cause
    output logic [63:0]                     csr_tval_o,                 // Value written to the tval registers
    output logic [63:0]                     csr_tval2_o,                // Value written to the tval2 registers
    output logic                            eret_o,

    output logic [WORD_WIDTH-1:0]           mstatus_o,                  //actual mstatus of the core
    output logic [WORD_WIDTH-1:0]           vsstatus_o,                 //actual vsstatus of the core
    output logic [1:0]                      priv_lvl_o,                 // actual privialge level of the core
    output logic                            v_mode_o,                   // Current virtualization mode state the CPU is in
    output logic [1:0]                      ld_st_priv_lvl_o,
    output logic                            ld_st_v_mode_o,
    output logic                            en_ld_st_translation_o,
    output logic                            en_ld_st_g_translation_o,
    output logic                            en_translation_o,
    output logic                            en_g_translation_o,
    output logic                            csr_hu_o,

    output logic [PPN_WIDTH-1:0]            satp_ppn_o,                 // Page table base pointer for the PTW
    output logic [PPN_WIDTH-1:0]            vsatp_ppn_o,                // Page table base pointer for the PTW
    output logic [PPN_WIDTH-1:0]            hgatp_ppn_o,                // Page table base pointer for the PTW

    output logic [63:0]                     evec_o,                      // virtual address of the PC to execute after a Interrupt or exception

    output logic                            flush_o,                    // the core is executing a sfence.vm instruction and a tlb flush is needed
    output logic                            flush_satp_o,               // invalidate tlb entries controlled by the current satp
    output logic                            flush_vsatp_o,              // invalidate tlb entries controlled by the current vsatp
    output logic                            flush_hgatp_o,              // invalidate tlb entries controlled by the current hgatp
    output logic [42:0]                     vpu_csr_o,

    output logic [CSR_ADDR_WIDTH-1:0]       perf_addr_o,                // read/write address to performance counter module
    output logic [63:0]                     perf_data_o,                // write data to performance counter module
    input  logic [63:0]                     perf_data_i,                // read data from performance counter module
    output logic                            perf_we_o,
    output logic [31:0]                     perf_mcountinhibit_o,
    input  logic                            perf_count_ovf_int_req_i,
    input  logic [31:3]                     perf_mhpm_ovf_bits_i,

    // Debug extension
    input logic                             debug_halt_req_i,
    input logic                             debug_halt_ack_i,
    input logic                             debug_resume_ack_i,
    output logic                            debug_ebreak_o,
    output logic                            debug_step_o
);

    localparam int MHPM_TO_HPM_DIST = riscv_pkg::CSR_HPM_COUNTER_3 - riscv_pkg::CSR_MHPM_COUNTER_3;

    function [1:0] trunc_sum_2bits(input [2:0] val_in);
        trunc_sum_2bits = val_in[1:0];
    endfunction

    function [5:0] trunc_sum_6bits(input [6:0] val_in);
        trunc_sum_6bits = val_in[5:0];
    endfunction

    function [11:0] trunc_sum_12bits(input [12:0] val_in);
        trunc_sum_12bits = val_in[11:0];
    endfunction

    function [63:0] trunc_sum_64bits(input [64:0] val_in);
        trunc_sum_64bits = val_in[63:0];
    endfunction

    
    // This functions converts S-mode CSR addresses into VS-mode CSR addresses
    // when V=1 (i.e., running in VS-mode).
    function automatic riscv_pkg::csr_t convert_vs_access_csr(riscv_pkg::csr_t csr_addr, logic v_mode);
    riscv_pkg::csr_t ret;
    ret = csr_addr;
    unique case (csr_addr.address) inside
      [riscv_pkg::CSR_SSTATUS : riscv_pkg::CSR_STVEC], [riscv_pkg::CSR_SSCRATCH : riscv_pkg::CSR_SATP]: begin
        if (v_mode) begin
          ret.csr_decode.priv_lvl = riscv_pkg::PRIV_LVL_HS;
        end
        return ret;
      end
      default: return ret;
    endcase
  endfunction

    //////////////////////////////////////////////
    // Registers declaration
    //////////////////////////////////////////////
    
    riscv_pkg::status_rv64_t  mstatus_q,  mstatus_d;
    riscv_pkg::hstatus_rv64_t  hstatus_q,  hstatus_d;
    riscv_pkg::status_rv64_t  vsstatus_q,  vsstatus_d;
    riscv_pkg::hgatp_t        hgatp_q, hgatp_d;
    riscv_pkg::satp_t         satp_q, satp_d;
    riscv_pkg::satp_t         vsatp_q, vsatp_d;
    riscv_pkg::csr_t  csr_addr;
    riscv_pkg::csr_t conv_csr_addr;
    // privilege level register
    riscv_pkg::priv_lvl_t   priv_lvl_d, priv_lvl_q;
    logic                   v_mode_d, v_mode_q;
    
    logic [63:0] hedeleg_q,   hedeleg_d;
    logic [63:0] hideleg_q,   hideleg_d;
    logic [63:0] henvcfg_q,   henvcfg_d;
    logic [31:0] hcounteren_q,hcounteren_d;
    logic [63:0] htval_q,     htval_d;
    logic [63:0] htinst_q,    htinst_d;
    logic [63:0] htimedelta_q,htimedelta_d;
    riscv_pkg::hstateen0_t hstateen0_q, hstateen0_d;
    riscv_pkg::hstateen1_t hstateen1_q, hstateen1_d;
    riscv_pkg::hstateen2_t hstateen2_q, hstateen2_d;
    riscv_pkg::hstateen3_t hstateen3_q, hstateen3_d;
    
    logic [63:0] vstvec_q,    vstvec_d;
    logic [63:0] vsscratch_q, vsscratch_d;
    logic [63:0] vsepc_q,     vsepc_d;
    logic [63:0] vscause_q,   vscause_d;
    logic [63:0] vstval_q,    vstval_d;

    logic        mtvec_rst_load_q;// used to determine whether we came out of reset
    logic [63:0] mtvec_q,     mtvec_d;
    logic [63:0] medeleg_q,   medeleg_d;
    logic [63:0] mideleg_q,   mideleg_d;
    logic [63:0] mip_q,       mip_d;
    logic [63:0] mie_q,       mie_d;
    logic [31:0] mcounteren_q,mcounteren_d;
    logic [31:0] mcountinhibit_q,mcountinhibit_d;
    logic [63:0] mcyclecfg_q, mcyclecfg_d;
    logic [63:0] minstretcfg_q, minstretcfg_d;
    logic [63:0] mscratch_q,  mscratch_d;
    logic [63:0] mepc_q,      mepc_d;
    logic [63:0] mcause_q,    mcause_d;
    logic [63:0] mtval_q,     mtval_d;
    logic [63:0] mtinst_q,    mtinst_d;
    logic [63:0] mtval2_q,    mtval2_d;
    logic [63:0] menvcfg_q,   menvcfg_d;
    riscv_pkg::mstateen0_t mstateen0_q, mstateen0_d;
    riscv_pkg::mstateen1_t mstateen1_q, mstateen1_d;
    riscv_pkg::mstateen2_t mstateen2_q, mstateen2_d;
    riscv_pkg::mstateen3_t mstateen3_q, mstateen3_d;

    logic [63:0] stvec_q,     stvec_d;
    logic [31:0] scounteren_q,scounteren_d;
    logic [63:0] senvcfg_q,   senvcfg_d;
    logic [63:0] sscratch_q,  sscratch_d;
    logic [63:0] sepc_q,      sepc_d;
    logic [63:0] scause_q,    scause_d;
    logic [63:0] stval_q,     stval_d;
    riscv_pkg::sstateen0_t sstateen0_q, sstateen0_d;
    riscv_pkg::sstateen1_t sstateen1_q, sstateen1_d;
    riscv_pkg::sstateen2_t sstateen2_q, sstateen2_d;
    riscv_pkg::sstateen3_t sstateen3_q, sstateen3_d;

    // Vector extension registers
    logic [63:0] vl_q,        vl_d;
    logic [63:0] vtype_q,     vtype_d;

    logic [63:0] cycle_q,     cycle_d;
    logic [63:0] instret_q,   instret_d;
    logic [31:0] scountovf_q, scountovf_d;

    riscv_pkg::dcsr_t dcsr_q, dcsr_d;
    logic [63:0] dpc_q, dpc_d;
    logic [63:0] dscratch0_q, dscratch0_d;
    logic [63:0] dscratch1_q, dscratch1_d;
    logic debug_mode_en_q, debug_mode_en_d;
    logic debug_ebreak_q, debug_ebreak_d;

    riscv_pkg::fcsr_t fcsr_q, fcsr_d;
    riscv_pkg::vcsr_t vcsr_q, vcsr_d;

    //////////////////////////////////////////////
    // Intermidiet wires and regs declaration
    //////////////////////////////////////////////

    // internal signal to keep track of access exceptions
    logic        read_access_exception, update_access_exception, update_access_exception_vs, privilege_violation;
    logic        virtual_read_access_exception, virtual_update_access_exception, virtual_privilege_violation;
    logic        csr_we, csr_read;
    logic        csr_xcpt;          // Internal csr exception bit.
    logic [63:0] csr_xcpt_cause;    // cause of the internal csr exception
    logic [63:0] ex_tval, ex_tval2;
    logic [63:0] csr_wdata, csr_rdata;
    logic [63:0] trap_vector_base;
    riscv_pkg::priv_lvl_t   trap_to_priv_lvl;
    logic                   trap_to_v_mode;
    // register for enabling load store address translation, this is critical, hence the register
    logic en_ld_st_translation_d, en_ld_st_translation_q;
    logic en_ld_st_g_translation_d, en_ld_st_g_translation_q;
    logic  mprv;
    logic  mret;  // return from M-mode exception
    logic  sret;  // return from S-mode exception
    // CSR write causes us to mark the FPU state as dirty
    logic  dirty_fp_state_csr;
    logic  dirty_v_state_csr;

    // actual state wires
    logic system_insn;
    logic priv_sufficient;
    logic wfi_d, wfi_q;
    logic [1:0] irq_q;

    // instruction wires
    logic insn_call;
    logic insn_break; 
    logic insn_mret;
    logic insn_sret;
    logic insn_sfence_vm; 
    logic insn_hfence_vvma; 
    logic insn_hfence_gvma; 
    logic insn_wfi;

    // vector instruction wires
    logic vsetvl_insn;
    logic [10:0] vtype_new;
    logic [63:0] vlmax;
    logic vnarrow_wide_en_d, vnarrow_wide_en_q;

    // Time value from timer
    logic [63:0] reg_time_d, reg_time_q;

    `ifdef CONF_SARGANTANA_ENABLE_PCR
        logic pcr_wait_resp_d, pcr_wait_resp_q; // the csr regfile is waiting the response of the PCR
        logic pcr_req_valid; // the csr regfile requests data to the PCR
        logic cpu_ren; // is needed a read to the csr (write, read, set and clear)
        logic pcr_addr_valid; // the address requested is a pcr address.
    `endif // CONF_SARGANTANA_ENABLE_PCR

    `ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
        logic [63:0] dyn_fpga_mem_latency_d, dyn_fpga_mem_latency_q;
    `endif // CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY

    //interruption wires
    logic [63:0] interrupt_cause_q, interrupt_cause_d, interrupt_cause;
    logic interrupt_d, interrupt_q;
    logic global_enable;

    // flush caused by a sfence instruction
    logic flush_sfence;
    // flush caused by a hfence instruction
    logic flush_hfence_vvma;
    logic flush_hfence_gvma;
    
    logic [11:0] perf_addr_dist;


    //////////////////////////////////////////////
    // System Instructions Decode
    //////////////////////////////////////////////
    // indicates if the request is a system instuction
    assign system_insn = (rw_cmd_i == 4'b0100) ? 1'b1 : 1'b0;
    assign priv_sufficient = (def_pkg::RVH && !v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) ?
                              riscv_pkg::PRIV_LVL_HS >= rw_addr_i[9:8]
                            : priv_lvl_q >= rw_addr_i[9:8];
    // the instructions are codified using the rw_addr_i
    assign insn_call = ((10'b0000000000 == rw_addr_i[9:0]) && system_insn) ? 1'b1 : 1'b0;
    assign insn_break = ((10'b0000000001 == rw_addr_i[9:0]) && system_insn) ? 1'b1 : 1'b0;
    assign insn_mret =  ((10'b1100000010 == rw_addr_i[9:0]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_sret =  ((10'b0100000010 == rw_addr_i[9:0]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_sfence_vm = ((5'b01001 == rw_addr_i[9:5]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_hfence_vvma = (def_pkg::RVH && (6'b010001 == rw_addr_i[10:5]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_hfence_gvma = (def_pkg::RVH && (6'b110001 == rw_addr_i[10:5]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_wfi = ((10'b0100000101 == rw_addr_i[9:0]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;

    //////////////////////////////////////////////
    // Vector Instructions Decode
    //////////////////////////////////////////////
    assign vsetvl_insn = ((rw_cmd_i == 4'b0110) || (rw_cmd_i == 4'b0111)) ? 1'b1 : 1'b0;

    //////////////////////////////////////////////
    // VPU Instructions Decode
    //////////////////////////////////////////////
    // indicates if the request is a system instuction

    // ----------------
    // Assignments
    // ----------------
    assign csr_addr = riscv_pkg::csr_t'(rw_addr_i);
    assign conv_csr_addr = (def_pkg::RVH) ? convert_vs_access_csr(
        (riscv_pkg::csr_t'(rw_addr_i)), v_mode_q
    ) : csr_addr;

    // ----------------
    // HPM Assignments
    // ----------------

    assign perf_mcountinhibit_o = mcountinhibit_q;
    assign perf_addr_o = trunc_sum_12bits(csr_addr.address[11:0] - perf_addr_dist);

    // ----------------
    // CSR Read logic
    // ----------------
    always_comb begin : csr_read_process
        // a read access exception can only occur if we attempt to read a CSR which does not exist
        read_access_exception = 1'b0;
        virtual_read_access_exception = 1'b0;

        `ifdef CONF_SARGANTANA_ENABLE_PCR
            pcr_addr_valid = 1'b0;
        `endif // CONF_SARGANTANA_ENABLE_PCR

        csr_rdata = 64'b0;
        perf_addr_dist = '0;

        if (csr_read) begin
            unique case (conv_csr_addr.address)
                riscv_pkg::CSR_FFLAGS: begin
                    if ((mstatus_q.fs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.fs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {59'b0, fcsr_q.fflags};
                    end
                end
                riscv_pkg::CSR_FRM: begin
                    if ((mstatus_q.fs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.fs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {61'b0, fcsr_q.frm};
                    end
                end
                riscv_pkg::CSR_FCSR: begin
                    if ((mstatus_q.fs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.fs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {56'b0, fcsr_q.frm, fcsr_q.fflags};
                    end
                end
                riscv_pkg::CSR_VCSR: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {61'b0, vcsr_q.vxrm, vcsr_q.vxsat};
                    end
                end

                riscv_pkg::CSR_VXRM: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {62'b0, vcsr_q.vxrm};

                    end
                end

                riscv_pkg::CSR_VXSAT: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {63'b0, vcsr_q.vxsat};
                    end
                end
                riscv_pkg::CSR_VSTART: begin // not supported
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {64'b0};
                    end
                end
                riscv_pkg::CSR_VL: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = vl_q;
                    end
                end

                riscv_pkg::CSR_VTYPE: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = vtype_q;
                    end
                end
                
                riscv_pkg::CSR_VLENB: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        read_access_exception = 1'b1;
                    end else begin
                            csr_rdata = (CORE_TYPE == def_pkg::LKA_CORE) ? VLEN_V >> 3 
                                                                         : riscv_pkg::VLEN >> 3;
                    end
                end

                // debug registers
                riscv_pkg::CSR_DCSR:               csr_rdata = {{32{1'b0}}, dcsr_q}; // not implemented
                riscv_pkg::CSR_DPC:                csr_rdata = dpc_q; // not implemented
                riscv_pkg::CSR_DSCRATCH0:          csr_rdata = dscratch0_q; // not implemented
                riscv_pkg::CSR_DSCRATCH1:          csr_rdata = dscratch1_q; // not implemented
                // trigger module registers
                riscv_pkg::CSR_TSELECT:; // not implemented
                riscv_pkg::CSR_TDATA1:;  // not implemented
                riscv_pkg::CSR_TDATA2:;  // not implemented
                riscv_pkg::CSR_TDATA3:;  // not implemented
                // supervisor registers
                riscv_pkg::CSR_SSTATUS: begin
                    csr_rdata = mstatus_q & def_pkg::SMODE_STATUS_READ_MASK;
                end
                riscv_pkg::CSR_SIE:                csr_rdata = (def_pkg::RVH) ? mie_q & mideleg_q & ~def_pkg::HS_DELEG_INTERRUPTS : mie_q & mideleg_q;
                riscv_pkg::CSR_SIP:                csr_rdata = (def_pkg::RVH) ? mip_q & mideleg_q & ~def_pkg::HS_DELEG_INTERRUPTS : mip_q & mideleg_q;
                riscv_pkg::CSR_STVEC:              csr_rdata = stvec_q;
                riscv_pkg::CSR_SCOUNTEREN:         csr_rdata = {{32{1'b0}}, scounteren_q};
                riscv_pkg::CSR_SENVCFG:            csr_rdata = {56'b0, senvcfg_q[7:4], 3'b0, senvcfg_q[0]}; // only implemented FIOM & CMO
                riscv_pkg::CSR_SSCRATCH:           csr_rdata = sscratch_q;
                riscv_pkg::CSR_SEPC:               csr_rdata = sepc_q;
                riscv_pkg::CSR_SCAUSE:             csr_rdata = scause_q;
                riscv_pkg::CSR_STVAL:              csr_rdata = stval_q;
                riscv_pkg::CSR_SATP: begin
                    csr_rdata = satp_q;
                    // intercept reads to SATP if in S-Mode and TVM is enabled
                    if ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && mstatus_q.tvm) begin
                        read_access_exception = 1'b1;
                    end
                end
                riscv_pkg::CSR_SSTATEEN0: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    csr_rdata = {{32{1'b0}}, sstateen0_q} &
                                (mstateen0_q & 
                                (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                    hstateen0_q : 64'hFFFFFFFF));
                end
                riscv_pkg::CSR_SSTATEEN1: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    csr_rdata = {{32{1'b0}}, sstateen1_q} &
                                (mstateen0_q & 
                                (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                    hstateen0_q : 64'hFFFFFFFF));
                end
                riscv_pkg::CSR_SSTATEEN2: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    csr_rdata = {{32{1'b0}}, sstateen2_q} &
                                (mstateen0_q & 
                                (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                    hstateen0_q : 64'hFFFFFFFF));
                end
                riscv_pkg::CSR_SSTATEEN3: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    csr_rdata = {{32{1'b0}}, sstateen3_q} &
                                (mstateen0_q & 
                                (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                    hstateen0_q : 64'hFFFFFFFF));
                end
                // hypervisor mode registers
                riscv_pkg::CSR_HSTATUS:
                    if (def_pkg::RVH)   csr_rdata = hstatus_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HEDELEG:
                    if (def_pkg::RVH)   csr_rdata = hedeleg_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HIDELEG:
                    if (def_pkg::RVH)   csr_rdata = hideleg_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HVIP:
                    if (def_pkg::RVH)   csr_rdata = mip_q & def_pkg::VS_DELEG_INTERRUPTS;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HIP:
                    if (def_pkg::RVH)   csr_rdata = mip_q & def_pkg::HS_DELEG_INTERRUPTS;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HIE:
                    if (def_pkg::RVH)   csr_rdata = mie_q & def_pkg::HS_DELEG_INTERRUPTS;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HGEIP:
                    if (def_pkg::RVH)   csr_rdata = 64'h0;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HGEIE:
                    if (def_pkg::RVH)   csr_rdata = 64'h0;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HENVCFG:
                    if (def_pkg::RVH)   csr_rdata = {56'b0, henvcfg_q[7:4], 3'b0, henvcfg_q[0]}; // only implemented FIOM & CMO

                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HCOUNTEREN:
                    if (def_pkg::RVH)   csr_rdata = {{32{1'b0}}, hcounteren_q};
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HTVAL:
                    if (def_pkg::RVH)   csr_rdata = htval_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HTINST:
                    if (def_pkg::RVH)   csr_rdata = htinst_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HGATP: begin
                  if (def_pkg::RVH) begin
                    // intercept reads to HGATP if in HS-Mode and TVM is enabled
                    if ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && !v_mode_q && mstatus_q.tvm) begin
                      read_access_exception = 1'b1;
                    end else begin
                      csr_rdata = hgatp_q;
                    end
                  end else begin
                    read_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_HTIMEDELTA:
                    if (def_pkg::RVH)   csr_rdata = htimedelta_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HSTATEEN0:
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    if (def_pkg::RVH)   csr_rdata = hstateen0_q & mstateen0_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HSTATEEN1:
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    if (def_pkg::RVH)   csr_rdata = hstateen1_q & mstateen1_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HSTATEEN2:
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    if (def_pkg::RVH)   csr_rdata = hstateen2_q & mstateen2_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_HSTATEEN3:
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    if (def_pkg::RVH)   csr_rdata = hstateen3_q & mstateen3_q;
                    else                read_access_exception = 1'b1;

                // virtual supervisor mode registers
                riscv_pkg::CSR_VSSTATUS:
                    if (def_pkg::RVH)   csr_rdata = vsstatus_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSIP:
                    if (def_pkg::RVH)   csr_rdata = (mip_q & def_pkg::VS_DELEG_INTERRUPTS & hideleg_q) >> 1;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSIE:
                    if (def_pkg::RVH)   csr_rdata = (mie_q & def_pkg::VS_DELEG_INTERRUPTS & hideleg_q) >> 1;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSTVEC:
                    if (def_pkg::RVH)   csr_rdata = vstvec_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSSCRATCH:
                    if (def_pkg::RVH)   csr_rdata = vsscratch_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSEPC:
                    if (def_pkg::RVH)   csr_rdata = vsepc_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSCAUSE:
                    if (def_pkg::RVH)   csr_rdata = vscause_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSTVAL:
                    if (def_pkg::RVH)   csr_rdata = vstval_q;
                    else                read_access_exception = 1'b1;
                riscv_pkg::CSR_VSATP:
                // intercept reads to VSATP if in VS-Mode and VTVM is enabled
                if (def_pkg::RVH) begin
                  if ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && hstatus_q.vtvm && v_mode_q)
                    virtual_read_access_exception = 1'b1;
                  else csr_rdata = vsatp_q;
                end else begin
                  read_access_exception = 1'b1;
                end

                // machine mode registers
                riscv_pkg::CSR_MSTATUS:            csr_rdata = mstatus_q;
                riscv_pkg::CSR_MISA:               csr_rdata = def_pkg::ISA_CODE; 
                riscv_pkg::CSR_MEDELEG:            csr_rdata = medeleg_q;
                riscv_pkg::CSR_MIDELEG:            csr_rdata = mideleg_q;
                riscv_pkg::CSR_MIE:                csr_rdata = mie_q;
                riscv_pkg::CSR_MTVEC:              csr_rdata = mtvec_q;
                riscv_pkg::CSR_MCOUNTEREN:         csr_rdata = {{32{1'b0}}, mcounteren_q};
                riscv_pkg::CSR_MCOUNTINHIBIT:      csr_rdata = {{32{1'b0}}, mcountinhibit_q[31:2], 1'b0, mcountinhibit_q[0]};
                riscv_pkg::CSR_MCYCLECFG:          csr_rdata = mcyclecfg_q;
                riscv_pkg::CSR_MINSTRETCFG:        csr_rdata = minstretcfg_q;
                riscv_pkg::CSR_MSCRATCH:           csr_rdata = mscratch_q;
                riscv_pkg::CSR_MEPC:               csr_rdata = mepc_q;
                riscv_pkg::CSR_MCAUSE:             csr_rdata = mcause_q;
                riscv_pkg::CSR_MTVAL:              csr_rdata = mtval_q;
                riscv_pkg::CSR_MIP:                csr_rdata = mip_q;
                riscv_pkg::CSR_MTINST:
                    if (def_pkg::RVH) csr_rdata = mtinst_q;
                    else              read_access_exception = 1'b1;
                riscv_pkg::CSR_MTVAL2:
                    if (def_pkg::RVH) csr_rdata = mtval2_q;
                    else              read_access_exception = 1'b1;
                riscv_pkg::CSR_MENVCFG:            csr_rdata = {56'b0, menvcfg_q[7:4], 3'b0, menvcfg_q[0]}; // only FIOM & CMO bits implemented
                riscv_pkg::CSR_MVENDORID:          csr_rdata = 64'b0; // not implemented
                riscv_pkg::CSR_MARCHID:            csr_rdata = 64'd51; // RISC-V Manual
                riscv_pkg::CSR_MIMPID:             csr_rdata = 64'h300; //v3.0.0
                riscv_pkg::CSR_MHARTID:            csr_rdata = core_id_i; 
                riscv_pkg::CSR_MCONFIGPTR:         csr_rdata = 64'b0; // not implemented
                `ifdef PITON_CINCORANCH
                riscv_pkg::CSR_MBOOT_MAIN_ID:      csr_rdata = {62'b0, boot_main_id_i};
                `endif  // Custom for CincoRanch
                riscv_pkg::CSR_MSTATEEN0:          csr_rdata = mstateen0_q;
                riscv_pkg::CSR_MSTATEEN1:          csr_rdata = mstateen1_q;
                riscv_pkg::CSR_MSTATEEN2:          csr_rdata = mstateen2_q;
                riscv_pkg::CSR_MSTATEEN3:          csr_rdata = mstateen3_q;
                // Counters and Timers
                riscv_pkg::CSR_MCYCLE:             csr_rdata = cycle_q;
                riscv_pkg::CSR_MINSTRET:           csr_rdata = instret_q;
                riscv_pkg::CSR_MHPM_COUNTER_3,
                riscv_pkg::CSR_MHPM_COUNTER_4,
                riscv_pkg::CSR_MHPM_COUNTER_5,
                riscv_pkg::CSR_MHPM_COUNTER_6,
                riscv_pkg::CSR_MHPM_COUNTER_7,
                riscv_pkg::CSR_MHPM_COUNTER_8,
                riscv_pkg::CSR_MHPM_COUNTER_9,
                riscv_pkg::CSR_MHPM_COUNTER_10,
                riscv_pkg::CSR_MHPM_COUNTER_11,
                riscv_pkg::CSR_MHPM_COUNTER_12,
                riscv_pkg::CSR_MHPM_COUNTER_13,
                riscv_pkg::CSR_MHPM_COUNTER_14,
                riscv_pkg::CSR_MHPM_COUNTER_15,
                riscv_pkg::CSR_MHPM_COUNTER_16,
                riscv_pkg::CSR_MHPM_COUNTER_17,
                riscv_pkg::CSR_MHPM_COUNTER_18,
                riscv_pkg::CSR_MHPM_COUNTER_19,
                riscv_pkg::CSR_MHPM_COUNTER_20,
                riscv_pkg::CSR_MHPM_COUNTER_21,
                riscv_pkg::CSR_MHPM_COUNTER_22,
                riscv_pkg::CSR_MHPM_COUNTER_23,
                riscv_pkg::CSR_MHPM_COUNTER_24,
                riscv_pkg::CSR_MHPM_COUNTER_25,
                riscv_pkg::CSR_MHPM_COUNTER_26,
                riscv_pkg::CSR_MHPM_COUNTER_27,
                riscv_pkg::CSR_MHPM_COUNTER_28,
                riscv_pkg::CSR_MHPM_COUNTER_29,
                riscv_pkg::CSR_MHPM_COUNTER_30,
                riscv_pkg::CSR_MHPM_COUNTER_31: begin
                    csr_rdata = perf_data_i;
                end

                riscv_pkg::CSR_CYCLE:              csr_rdata = cycle_q;
                riscv_pkg::CSR_TIME: begin
                    csr_rdata = reg_time_q;
                    if(def_pkg::RVH) begin
                        if (v_mode_q && ((priv_lvl_q == riscv_pkg::PRIV_LVL_S) || (priv_lvl_q == riscv_pkg::PRIV_LVL_U)))
                            csr_rdata = reg_time_q + htimedelta_q;
                    end
                end
                riscv_pkg::CSR_INSTRET:            csr_rdata = instret_q;
                riscv_pkg::CSR_HPM_COUNTER_3,
                riscv_pkg::CSR_HPM_COUNTER_4,
                riscv_pkg::CSR_HPM_COUNTER_5,
                riscv_pkg::CSR_HPM_COUNTER_6,
                riscv_pkg::CSR_HPM_COUNTER_7,
                riscv_pkg::CSR_HPM_COUNTER_8,
                riscv_pkg::CSR_HPM_COUNTER_9,
                riscv_pkg::CSR_HPM_COUNTER_10,
                riscv_pkg::CSR_HPM_COUNTER_11,
                riscv_pkg::CSR_HPM_COUNTER_12,
                riscv_pkg::CSR_HPM_COUNTER_13,
                riscv_pkg::CSR_HPM_COUNTER_14,
                riscv_pkg::CSR_HPM_COUNTER_15,
                riscv_pkg::CSR_HPM_COUNTER_16,
                riscv_pkg::CSR_HPM_COUNTER_17,
                riscv_pkg::CSR_HPM_COUNTER_18,
                riscv_pkg::CSR_HPM_COUNTER_19,
                riscv_pkg::CSR_HPM_COUNTER_20,
                riscv_pkg::CSR_HPM_COUNTER_21,
                riscv_pkg::CSR_HPM_COUNTER_22,
                riscv_pkg::CSR_HPM_COUNTER_23,
                riscv_pkg::CSR_HPM_COUNTER_24,
                riscv_pkg::CSR_HPM_COUNTER_25,
                riscv_pkg::CSR_HPM_COUNTER_26,
                riscv_pkg::CSR_HPM_COUNTER_27,
                riscv_pkg::CSR_HPM_COUNTER_28,
                riscv_pkg::CSR_HPM_COUNTER_29,
                riscv_pkg::CSR_HPM_COUNTER_30,
                riscv_pkg::CSR_HPM_COUNTER_31: begin
                    perf_addr_dist = MHPM_TO_HPM_DIST;
                    csr_rdata = perf_data_i;
                end
                riscv_pkg::CSR_SCOUNTOVF:         csr_rdata = {{32{1'b0}}, scountovf_q & mcounteren_q};
                riscv_pkg::CSR_MHPM_EVENT_3,
                riscv_pkg::CSR_MHPM_EVENT_4,
                riscv_pkg::CSR_MHPM_EVENT_5,
                riscv_pkg::CSR_MHPM_EVENT_6,
                riscv_pkg::CSR_MHPM_EVENT_7,
                riscv_pkg::CSR_MHPM_EVENT_8,
                riscv_pkg::CSR_MHPM_EVENT_9,
                riscv_pkg::CSR_MHPM_EVENT_10,
                riscv_pkg::CSR_MHPM_EVENT_11,
                riscv_pkg::CSR_MHPM_EVENT_12,
                riscv_pkg::CSR_MHPM_EVENT_13,
                riscv_pkg::CSR_MHPM_EVENT_14,
                riscv_pkg::CSR_MHPM_EVENT_15,
                riscv_pkg::CSR_MHPM_EVENT_16,
                riscv_pkg::CSR_MHPM_EVENT_17,
                riscv_pkg::CSR_MHPM_EVENT_18,
                riscv_pkg::CSR_MHPM_EVENT_19,
                riscv_pkg::CSR_MHPM_EVENT_20,
                riscv_pkg::CSR_MHPM_EVENT_21,
                riscv_pkg::CSR_MHPM_EVENT_22,
                riscv_pkg::CSR_MHPM_EVENT_23,
                riscv_pkg::CSR_MHPM_EVENT_24,
                riscv_pkg::CSR_MHPM_EVENT_25,
                riscv_pkg::CSR_MHPM_EVENT_26,
                riscv_pkg::CSR_MHPM_EVENT_27,
                riscv_pkg::CSR_MHPM_EVENT_28,
                riscv_pkg::CSR_MHPM_EVENT_29,
                riscv_pkg::CSR_MHPM_EVENT_30,
                riscv_pkg::CSR_MHPM_EVENT_31:   begin
                    csr_rdata = perf_data_i;
                end

                `ifdef CONF_SARGANTANA_ENABLE_PCR
                riscv_pkg::CSR_MEM_MAP_0,
                riscv_pkg::CSR_MEM_MAP_1,
                riscv_pkg::CSR_MEM_MAP_2,
                riscv_pkg::CSR_MEM_MAP_3,
                riscv_pkg::CSR_MEM_MAP_4,
                riscv_pkg::CSR_MEM_MAP_5,
                riscv_pkg::CSR_MEM_MAP_6,
                riscv_pkg::CSR_MEM_MAP_7,
                riscv_pkg::CSR_MEM_MAP_8,
                riscv_pkg::CSR_MEM_MAP_9,
                riscv_pkg::CSR_MEM_MAP_10,                
                riscv_pkg::CSR_MEM_MAP_11,                
                riscv_pkg::CSR_MEM_MAP_12,                
                riscv_pkg::CSR_MEM_MAP_13,                
                riscv_pkg::CSR_MEM_MAP_14,                
                riscv_pkg::CSR_MEM_MAP_15,
                riscv_pkg::CSR_IO_MAP_0,
                riscv_pkg::CSR_IO_MAP_1,
                riscv_pkg::CSR_IO_MAP_2,
                riscv_pkg::CSR_IO_MAP_3,
                riscv_pkg::CSR_IO_MAP_4,
                riscv_pkg::CSR_IO_MAP_5,
                riscv_pkg::CSR_IO_MAP_6,
                riscv_pkg::CSR_IO_MAP_7,
                riscv_pkg::CSR_IO_MAP_8,
                riscv_pkg::CSR_IO_MAP_9,
                riscv_pkg::CSR_IO_MAP_10,
                riscv_pkg::CSR_IO_MAP_11,
                riscv_pkg::CSR_IO_MAP_12,
                riscv_pkg::CSR_IO_MAP_13,
                riscv_pkg::CSR_IO_MAP_14,
                riscv_pkg::CSR_IO_MAP_15,
                riscv_pkg::CSR_IRQ_MAP_0,
                riscv_pkg::CSR_IRQ_MAP_1,
                riscv_pkg::CSR_IRQ_MAP_2,
                riscv_pkg::CSR_IRQ_MAP_3,
                riscv_pkg::CSR_IRQ_MAP_4,
                riscv_pkg::CSR_IRQ_MAP_5,
                riscv_pkg::CSR_IRQ_MAP_6,
                riscv_pkg::CSR_IRQ_MAP_7,
                riscv_pkg::CSR_IRQ_MAP_8,
                riscv_pkg::CSR_IRQ_MAP_9,
                riscv_pkg::CSR_IRQ_MAP_10,
                riscv_pkg::CSR_IRQ_MAP_11,
                riscv_pkg::CSR_IRQ_MAP_12,
                riscv_pkg::CSR_IRQ_MAP_13,
                riscv_pkg::CSR_IRQ_MAP_14,
                riscv_pkg::CSR_IRQ_MAP_15,
                riscv_pkg::FROM_HOST,
                riscv_pkg::CSR_HYPERRAM_CONFIG, 
                riscv_pkg::CSR_SPI_CONFIG, 
                riscv_pkg::CSR_CNM_CONFIG,
                riscv_pkg::TO_HOST,
                riscv_pkg::CLEAR_MIP: begin 
                        csr_rdata = pcr_resp_data_i;
                        pcr_addr_valid = 1'b1;
                    
                end
                `endif // CONF_SARGANTANA_ENABLE_PCR

                `ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
                riscv_pkg::CSR_DYN_MEM_LATENCY:
                    csr_rdata = dyn_fpga_mem_latency_q;
                `endif

                riscv_pkg::CSR_PMPCFG_0:;
                riscv_pkg::CSR_PMPCFG_1:;
                riscv_pkg::CSR_PMPCFG_2:;
                riscv_pkg::CSR_PMPCFG_3:;

                riscv_pkg::CSR_PMPADDR_0:;
                riscv_pkg::CSR_PMPADDR_1:;
                riscv_pkg::CSR_PMPADDR_2:;
                riscv_pkg::CSR_PMPADDR_3:;
                riscv_pkg::CSR_PMPADDR_4:;
                riscv_pkg::CSR_PMPADDR_5:;
                riscv_pkg::CSR_PMPADDR_6:;
                riscv_pkg::CSR_PMPADDR_7:;
                riscv_pkg::CSR_PMPADDR_8:;
                riscv_pkg::CSR_PMPADDR_9:;
                riscv_pkg::CSR_PMPADDR_10:;
                riscv_pkg::CSR_PMPADDR_11:;
                riscv_pkg::CSR_PMPADDR_12:;
                riscv_pkg::CSR_PMPADDR_13:;
                riscv_pkg::CSR_PMPADDR_14:;
                riscv_pkg::CSR_PMPADDR_15:;
                //
                default: read_access_exception = 1'b1;
            endcase
        end
    end


    logic [$clog2(RETIRE_BW+1)-1:0] retire_cnt;

    // ---------------------------
    // CSR Write and update logic
    // ---------------------------
    logic [63:0] mask;
    always_comb begin : csr_update
        automatic riscv_pkg::satp_t satp,satp_temp; // temporal values to correct the structure of the writing on the satp reg
        automatic riscv_pkg::satp_t vsatp; // temporal values to correct the structure of the writing on the vsatp reg
        automatic riscv_pkg::hgatp_t hgatp; // temporal values to correct the structure of the writing on the hgatp reg
        automatic logic [63:0] instret;
        automatic logic [63:0] mstatus_int, mstatus_clear ,mstatus_set; //Used to set and clear some bits of the mstatus_d
        automatic logic flush; //temporal flush value before the exceptions logic
        automatic logic flush_satp;  //temporal flush value before the exceptions logic
        automatic logic flush_vsatp; //temporal flush value before the exceptions logic
        automatic logic flush_hgatp; //temporal flush value before the exceptions logic
        automatic logic [63:0] mcause_int; // temporal value of mcause
        automatic logic [63:0] scause_int; // temporal value of scause
        automatic logic [63:0] mtval_int; // temporal value of mtval
        automatic logic [63:0] stval_int; // temporal value of stval
        automatic logic [63:0] mepc_int; // temporal value of mepc
        automatic logic [63:0] sepc_int; // temporal value of sepc

        satp = satp_q;
        hgatp = (def_pkg::RVH) ? hgatp_q : 0;
        vsatp = (def_pkg::RVH) ? vsatp_q : 0;
        
        instret = instret_q;

        // --------------------
        // Counters
        // --------------------
        // increase instruction retired counter

        retire_cnt = {$clog2(RETIRE_BW+1){1'b0}};
        for (int i=0; i<RETIRE_BW; i++) begin
            retire_cnt = trunc_sum_2bits(retire_cnt + retire_i[i]);
        end

        if (!ex_i && ~mcountinhibit_q[2])  begin
            case (priv_lvl_o)
                riscv_pkg::PRIV_LVL_M: instret = trunc_sum_64bits(instret + ({{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt} & {64{~minstretcfg_q[62]}}));
                riscv_pkg::PRIV_LVL_S: begin
                    if (def_pkg::RVH && v_mode_q) begin
                        instret = trunc_sum_64bits(instret + ({{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt} & {64{~minstretcfg_q[59]}}));
                    end else begin
                        instret = trunc_sum_64bits(instret + ({{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt} & {64{~minstretcfg_q[61]}}));
                    end
                end
                riscv_pkg::PRIV_LVL_U: begin
                    if (def_pkg::RVH && v_mode_q) begin
                        instret = trunc_sum_64bits(instret + ({{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt} & {64{~minstretcfg_q[58]}}));
                    end else begin
                        instret = trunc_sum_64bits(instret + ({{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt} & {64{~minstretcfg_q[60]}}));
                    end
                end
                default: instret = trunc_sum_64bits(instret + ({{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt}));
            endcase
        end
        instret_d = instret;
        // increment the cycle count 
        case (priv_lvl_o)
            riscv_pkg::PRIV_LVL_M: cycle_d = trunc_sum_64bits(cycle_q + {63'b0,((~mcountinhibit_q[0]) & (~mcyclecfg_q[62]))});
            riscv_pkg::PRIV_LVL_S: begin
                if (def_pkg::RVH && v_mode_q) begin
                    cycle_d = trunc_sum_64bits(cycle_q + {63'b0,((~mcountinhibit_q[0]) & (~mcyclecfg_q[59]))});
                end else begin
                    cycle_d = trunc_sum_64bits(cycle_q + {63'b0,((~mcountinhibit_q[0]) & (~mcyclecfg_q[61]))});
                end
            end
            riscv_pkg::PRIV_LVL_U: begin
                if (def_pkg::RVH && v_mode_q) begin
                    cycle_d = trunc_sum_64bits(cycle_q + {63'b0,((~mcountinhibit_q[0]) & (~mcyclecfg_q[58]))});
                end else begin
                    cycle_d = trunc_sum_64bits(cycle_q + {63'b0,((~mcountinhibit_q[0]) & (~mcyclecfg_q[60]))});
                end
            end
            default: cycle_d = trunc_sum_64bits(cycle_q + {63'b0,~mcountinhibit_q[0]});
        endcase
        
        scountovf_d = {perf_mhpm_ovf_bits_i, 3'b000};

        eret_o                  = 1'b0;
        flush                   = 1'b0;
        flush_satp              = 1'b0;
        flush_vsatp             = 1'b0;
        flush_hgatp             = 1'b0;
        update_access_exception = 1'b0;
        virtual_update_access_exception = 1'b0;

        perf_we_o               = 1'b0;
        perf_data_o             = 'b0;

        fcsr_d                  = fcsr_q;
        vcsr_d                  = vcsr_q;

        priv_lvl_d              = priv_lvl_q;
        v_mode_d                = v_mode_q;

        mstatus_clear = riscv_pkg::MSTATUS_UXL | riscv_pkg::MSTATUS_SXL | riscv_pkg::MSTATUS64_SD;
        mstatus_set =   (((mstatus_q.xs == riscv_pkg::Dirty) || (mstatus_q.fs == riscv_pkg::Dirty) || (mstatus_q.vs == riscv_pkg::Dirty))<<63) |
                        {30'b0,riscv_pkg::XLEN_64,32'b0} |
                        {28'b0,riscv_pkg::XLEN_64,34'b0};
        mstatus_int   = (mstatus_q & ~mstatus_clear) | mstatus_set;

        hstatus_d  = (def_pkg::RVH) ? hstatus_q  : 0;
        vsstatus_d = (def_pkg::RVH) ? vsstatus_q : 0;

        // hardwired extension registers

        // write the floating point status register
        if (fcsr_flags_valid_i) begin
            fcsr_d.fflags = fcsr_flags_bits_i | fcsr_q.fflags;
        end
       

        // check whether we come out of reset
        // this is a workaround. some tools have issues
        // having trap_vector_addr_i in the asynchronous
        // reset assignment to mtvec_d, even though
        // trap_vector_addr_i will be assigned a constant
        // on the top-level.
        mtvec_d = mtvec_q;
        if (mtvec_rst_load_q) begin
            mtvec_d             = trap_vector_addr_i;
        end 

        dirty_v_state_csr = 1'b0;
        if ((vsetvl_insn | vreg_modified_i) && (mstatus_q.vs != riscv_pkg::Off)) begin
            dirty_v_state_csr = 1'b1;
        end 

        dirty_fp_state_csr      = 1'b0;
        if (freg_modified_i && (mstatus_q.fs != riscv_pkg::Off)) begin
            dirty_fp_state_csr = 1'b1;
        end

        if (vxsat_i) begin
            vcsr_d.vxsat = 1'b1;
        end

        // ---------------------
        // External Interrupts
        // ---------------------
        // the IRQ_M_EXT = irq_i || rocc_interrupt_i, IRQ_M_SOFT = m_soft_irq_i and IRQ_M_TIMER = time_irq_i
        mip_d = {mip_q[63:14], perf_count_ovf_int_req_i || mip_q[13], mip_q[12], irq_q[0], mip_q[10:8], time_irq_i, mip_q[6:4], m_soft_irq_i, mip_q[2:0]};

        hedeleg_d               = (def_pkg::RVH) ? hedeleg_q    : 0;
        hideleg_d               = (def_pkg::RVH) ? hideleg_q    : 0;
        henvcfg_d               = (def_pkg::RVH) ? henvcfg_q    : 0;
        hcounteren_d            = (def_pkg::RVH) ? hcounteren_q : 0;
        htinst_d                = (def_pkg::RVH) ? htinst_q     : 0;
        htval_d                 = (def_pkg::RVH) ? htval_q      : 0;
        hgatp_d                 = (def_pkg::RVH) ? hgatp_q      : 0;
        htimedelta_d            = (def_pkg::RVH) ? htimedelta_q : 0;
        hstateen0_d             = (def_pkg::RVH) ? hstateen0_q  : 0;
        hstateen1_d             = (def_pkg::RVH) ? hstateen1_q  : 0;
        hstateen2_d             = (def_pkg::RVH) ? hstateen2_q  : 0;
        hstateen3_d             = (def_pkg::RVH) ? hstateen3_q  : 0;

        vstvec_d                = (def_pkg::RVH) ? vstvec_q     : 0;
        vsscratch_d             = (def_pkg::RVH) ? vsscratch_q  : 0;
        vscause_d               = (def_pkg::RVH) ? vscause_q    : 0;
        vstval_d                = (def_pkg::RVH) ? vstval_q     : 0;
        vsatp_d                 = (def_pkg::RVH) ? vsatp_q      : 0;
        vsepc_d                 = (def_pkg::RVH) ? vsepc_q      : 0;
        en_ld_st_g_translation_d = (def_pkg::RVH) ? en_ld_st_g_translation_q : 0;

        medeleg_d               = medeleg_q;
        mideleg_d               = mideleg_q;
        
        mie_d                   = mie_q;
        mepc_int                = mepc_q;
        mcause_int              = mcause_q;
        mcounteren_d            = mcounteren_q;
        mcountinhibit_d         = mcountinhibit_q;
        mcyclecfg_d             = mcyclecfg_q;
        minstretcfg_d           = minstretcfg_q;
        mscratch_d              = mscratch_q;
        mtval_int               = mtval_q;

        mtinst_d                = (def_pkg::RVH) ? mtinst_q : 0;
        mtval2_d                = (def_pkg::RVH) ? mtval2_q : 0;

        menvcfg_d               = menvcfg_q;

        mstateen0_d             = mstateen0_q;
        mstateen1_d             = mstateen1_q;
        mstateen2_d             = mstateen2_q;
        mstateen3_d             = mstateen3_q;

        sepc_int                = sepc_q;
        scause_int              = scause_q;
        stvec_d                 = stvec_q;
        scounteren_d            = scounteren_q;
        senvcfg_d               = senvcfg_q;
        sscratch_d              = sscratch_q;
        stval_int               = stval_q;
        satp_d                  = satp_q;
        sstateen0_d             = sstateen0_q;
        sstateen1_d             = sstateen1_q;
        sstateen2_d             = sstateen2_q;
        sstateen3_d             = sstateen3_q;

        en_ld_st_translation_d  = en_ld_st_translation_q;

        dcsr_d = dcsr_q;
        dpc_d = dpc_q;
        dscratch0_d = dscratch0_q;
        dscratch1_d = dscratch1_q;

        `ifdef CONF_SARGANTANA_ENABLE_PCR
            pcr_req_data_o          = 'b0;
        `endif // CONF_SARGANTANA_ENABLE_PCR

        `ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
            dyn_fpga_mem_latency_d = dyn_fpga_mem_latency_q;
        `endif

        mask                    = 64'h0;
        satp_temp='0;

        // check for correct access rights and that we are writing
        if (csr_we) begin
            unique case (conv_csr_addr.address)
                // Floating-Point
                riscv_pkg::CSR_FFLAGS: begin
                    if ((mstatus_q.fs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.fs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_fp_state_csr = 1'b1;
                        fcsr_d.fflags = csr_wdata[4:0];
                        // this instruction has side-effects
                    end
                end
                riscv_pkg::CSR_FRM: begin
                    if ((mstatus_q.fs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.fs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_fp_state_csr = 1'b1;
                        fcsr_d.frm    = csr_wdata[2:0];
                        // this instruction has side-effects
                    end
                end
                riscv_pkg::CSR_FCSR: begin
                    if ((mstatus_q.fs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.fs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_fp_state_csr = 1'b1;
                        fcsr_d[7:0] = csr_wdata[7:0]; // ignore writes to reserved space
                        // this instruction has side-effects
                    end
                end
                riscv_pkg::CSR_VXSAT: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_v_state_csr  = 1'b1;
                        vcsr_d.vxsat    = csr_wdata[0];
                        // this instruction has side-effects
                    end
                    
                end
                riscv_pkg::CSR_VXRM: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_v_state_csr  = 1'b1;
                        vcsr_d.vxrm    = csr_wdata[1:0];

                        // this instruction has side-effects
                    end
                end
                riscv_pkg::CSR_VCSR: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_v_state_csr = 1'b1;
                        vcsr_d.vxsat = csr_wdata[0];
                        vcsr_d.vxrm = csr_wdata[2:1];
                        // this instruction has side-effects
                    end
                end
                riscv_pkg::CSR_VSTART: begin
                    if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                        update_access_exception = 1'b1;
                    end
                end
                // debug CSR
                riscv_pkg::CSR_DCSR: begin
                    if (csr_wdata[1:0] == 2'b10) begin // illegal value for prv, maintain old
                        dcsr_d = {dcsr_q[31:16], csr_wdata[15], 1'b0, csr_wdata[13:12], dcsr_q[11:5], csr_wdata[4], dcsr_q[3], csr_wdata[2], dcsr_q[1:0]};
                    end else begin
                        dcsr_d = {dcsr_q[31:16], csr_wdata[15], 1'b0, csr_wdata[13:12], dcsr_q[11:5], csr_wdata[4], dcsr_q[3], csr_wdata[2:0]};
                    end
                end
                riscv_pkg::CSR_DPC:         dpc_d = csr_wdata;
                riscv_pkg::CSR_DSCRATCH0:   dscratch0_d = csr_wdata;
                riscv_pkg::CSR_DSCRATCH1:   dscratch1_d = csr_wdata;
                // trigger module CSRs
                riscv_pkg::CSR_TSELECT:; // not implemented
                riscv_pkg::CSR_TDATA1:;  // not implemented
                riscv_pkg::CSR_TDATA2:;  // not implemented
                riscv_pkg::CSR_TDATA3:;  // not implemented
                // sstatus is a subset of mstatus - mask it accordingly
                riscv_pkg::CSR_SSTATUS: begin
                    mask = def_pkg::SMODE_STATUS_WRITE_MASK;
                    mstatus_int = (mstatus_q & ~mask) | (csr_wdata & mask);
                    // If h-extension is not enabled, priv level HS is reserved
                    if (!def_pkg::RVH) begin
                      if (mstatus_int[12:11] == riscv_pkg::PRIV_LVL_HS) begin
                        mstatus_int[12:11] = mstatus_q.mpp;
                      end
                    end
                    // this instruction has side-effects
                end
                // even machine mode interrupts can be visible and set-able to supervisor
                // if the corresponding bit in mideleg is set
                riscv_pkg::CSR_SIE: begin
                    // the mideleg makes sure only delegate-able register (and therefore also only implemented registers) are written
                    //mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_LCOFIP;
                    mask  = (def_pkg::RVH) ? mideleg_q & ~def_pkg::HS_DELEG_INTERRUPTS : mideleg_q;
                    mie_d = (mie_q & ~mask) | (csr_wdata & mask);
                end

                riscv_pkg::CSR_SIP: begin
                    // only the supervisor software interrupt is write-able, iff delegated
                    mask = (riscv_pkg::MIP_SSIP | riscv_pkg::MIP_LCOFIP) & mideleg_q;
                    mip_d = (mip_q & ~mask) | (csr_wdata & mask);
                end

                riscv_pkg::CSR_SCOUNTEREN:         scounteren_d =  {csr_wdata[31:0]};
                riscv_pkg::CSR_STVEC:              stvec_d     = {csr_wdata[63:2], 1'b0, csr_wdata[0]};
                riscv_pkg::CSR_SENVCFG:            senvcfg_d   = csr_wdata;
                riscv_pkg::CSR_SSCRATCH:           sscratch_d  = csr_wdata;
                riscv_pkg::CSR_SEPC:               sepc_int    = {csr_wdata[63:1], 1'b0};
                riscv_pkg::CSR_SCAUSE:             scause_int  = csr_wdata;
                riscv_pkg::CSR_STVAL:              stval_int   = csr_wdata;
                // supervisor address translation and protection
                riscv_pkg::CSR_SATP: begin
                    // intercept SATP writes if in S-Mode and TVM is enabled
                    if ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && mstatus_q.tvm)
                        update_access_exception = 1'b1;
                    else begin
                        satp_temp      = riscv_pkg::satp_t'(csr_wdata);
                        // only make ASID_LEN - 1 bit stick, that way software can figure out how many ASID bits are supported
                        satp.asid = satp_temp.asid & {{(16-ASID_WIDTH){1'b0}}, {ASID_WIDTH{1'b1}}};
                        satp.mode = satp_temp.mode;
                        satp.ppn = satp_temp.ppn;
                        // only update if we actually support this mode
                        if ((satp.mode == def_pkg::MODE_OFF) || (satp.mode == def_pkg::MODE_SV39)) satp_d = satp;
                    end
                    // changing the mode can have side-effects on address translation (e.g.: other instructions), re-fetch
                    // the next instruction by executing a flush
                end
                riscv_pkg::CSR_SSTATEEN0: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    mask =  64'h00000000 & // Reserved for future use, all bits are read-only zero
                            (mstateen0_q & 
                            (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                hstateen0_q : 64'hFFFFFFFF));
                    sstateen0_d = (sstateen0_q & ~mask[31:0]) | (csr_wdata[31:0] & mask[31:0]);
                end
                riscv_pkg::CSR_SSTATEEN1: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    mask =  64'h00000000 & // Reserved for future use, all bits are read-only zero
                            (mstateen1_q & 
                            (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                hstateen1_q : 64'hFFFFFFFF));
                    sstateen1_d = (sstateen1_q & ~mask[31:0]) | (csr_wdata[31:0] & mask[31:0]);
                end
                riscv_pkg::CSR_SSTATEEN2: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    mask =  64'h00000000 & // Reserved for future use, all bits are read-only zero
                            (mstateen2_q & 
                            (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                hstateen2_q : 64'hFFFFFFFF));
                    sstateen2_d = (sstateen2_q & ~mask[31:0]) | (csr_wdata[31:0] & mask[31:0]);
                end
                riscv_pkg::CSR_SSTATEEN3: begin
                    // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                    // For every bit in an hstateen CSR that is zero (whether read-only zero or set to zero),
                    // the same bit appears as read-only zero in sstateen when accessed in VS-mode.
                    mask =  64'h00000000 & // Reserved for future use, all bits are read-only zero
                            (mstateen3_q & 
                            (((def_pkg::RVH) && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) ?
                                hstateen3_q : 64'hFFFFFFFF));
                    sstateen3_d = (sstateen3_q & ~mask[31:0]) | (csr_wdata[31:0] & mask[31:0]);
                end

                //hypervisor mode registers
                riscv_pkg::CSR_HSTATUS: begin
                    if (def_pkg::RVH) begin
                      mask      = def_pkg::HSTATUS_WRITE_MASK;
                      hstatus_d = (hstatus_q & ~mask) | (csr_wdata & mask);
                      // this register has side-effects on other registers, flush the pipeline
                    end else begin
                      update_access_exception = 1'b1;
                    end
                end
                // hypervisor exception delegation register
                riscv_pkg::CSR_HEDELEG: begin
                    if (def_pkg::RVH) begin
                      mask = (1 << riscv_pkg::INSTR_ADDR_MISALIGNED) |
                             (1 << riscv_pkg::INSTR_ACCESS_FAULT) |
                             (1 << riscv_pkg::ILLEGAL_INSTR) |
                             (1 << riscv_pkg::BREAKPOINT) |
                             (1 << riscv_pkg::LD_ADDR_MISALIGNED) |
                             (1 << riscv_pkg::LD_ACCESS_FAULT) |
                             (1 << riscv_pkg::ST_AMO_ADDR_MISALIGNED) |
                             (1 << riscv_pkg::ST_AMO_ACCESS_FAULT) |
                             (1 << riscv_pkg::USER_ECALL) |
                             ((def_pkg::RVH ? 1 : 0) << riscv_pkg::VIRTUALSUPERVISOR_ECALL) |
                             (1 << riscv_pkg::INSTR_PAGE_FAULT) |
                             (1 << riscv_pkg::LD_PAGE_FAULT) |
                             (1 << riscv_pkg::ST_AMO_PAGE_FAULT) |
                             ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::INSTR_GUEST_PAGE_FAULT) |
                             ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::LD_GUEST_PAGE_FAULT) |
                             ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::VIRTUAL_INSTRUCTION) |
                             ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::ST_GUEST_AMO_PAGE_FAULT);
                      hedeleg_d = (hedeleg_q & ~mask) | (csr_wdata & mask);
                    end else begin
                      update_access_exception = 1'b1;
                    end
                end
                // hypervisor interrupt delegation register
                riscv_pkg::CSR_HIDELEG: begin
                  if (def_pkg::RVH) begin
                    hideleg_d = (hideleg_q & ~def_pkg::VS_DELEG_INTERRUPTS) | (csr_wdata & def_pkg::VS_DELEG_INTERRUPTS);
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_HVIP: begin
                  if (def_pkg::RVH) begin
                    mask  = def_pkg::VS_DELEG_INTERRUPTS;
                    mip_d = (mip_q & ~mask) | (csr_wdata & mask);
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_HIP: begin
                  if (def_pkg::RVH) begin
                    mask  = riscv_pkg::MIP_VSSIP;
                    mip_d = (mip_q & ~mask) | (csr_wdata & mask);
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_HIE: begin
                  if (def_pkg::RVH) begin
                    mask  = def_pkg::HS_DELEG_INTERRUPTS;
                    mie_d = (mie_q & ~mask) | (csr_wdata & mask);
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_HGEIE: begin
                    if (!def_pkg::RVH) begin
                      update_access_exception = 1'b1;
                    end
                end
                riscv_pkg::CSR_HENVCFG:
                    if (def_pkg::RVH)   henvcfg_d   = csr_wdata;
                    else                update_access_exception = 1'b1;
                riscv_pkg::CSR_HCOUNTEREN: begin
                    if (def_pkg::RVH)   hcounteren_d = csr_wdata[31:0];
                    else                update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HTVAL: begin
                    if (def_pkg::RVH)   htval_d = csr_wdata;
                    else                update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HTINST: begin
                    if (def_pkg::RVH)   htinst_d = {{32{1'b0}}, csr_wdata[31:0]};
                    else                update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HGATP: begin
                  if (def_pkg::RVH) begin
                    // intercept HGATP writes if in HS-Mode and TVM is enabled
                    if ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && !v_mode_q && mstatus_q.tvm)
                      update_access_exception = 1'b1;
                    else begin
                      hgatp = riscv_pkg::hgatp_t'(csr_wdata);
                      //hardwire PPN[1:0] to zero
                      hgatp[1:0] = 2'b0;
                      // only make VMID_LEN - 1 bit stick, that way software can figure out how many VMID bits are supported
                      hgatp.vmid = hgatp.vmid & {{(14 - VMID_WIDTH) {1'b0}}, {VMID_WIDTH{1'b1}}};
                      hgatp_d = hgatp;
                      // HGATP mode is WARL
                      if ((hgatp.mode != def_pkg::MODE_OFF) && (hgatp.mode != def_pkg::MODE_SV39x4))
                        hgatp_d.mode = hgatp_q.mode;
                    end
                    // changing the mode can have side-effects on address translation (e.g.: other instructions), re-fetch
                    // the next instruction by executing a flush
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_HTIMEDELTA: begin
                    if (def_pkg::RVH)   htimedelta_d = csr_wdata;
                    else                update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HSTATEEN0: begin
                    if (def_pkg::RVH) begin
                        // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                        // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                        mask = (riscv_pkg::HSTATEEN0_SE | riscv_pkg::HSTATEEN0_ENVCFG) & mstateen0_q; // all other bits are read-only zero
                        hstateen0_d = (hstateen0_q & ~mask) | (csr_wdata & mask);
                    end
                    else update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HSTATEEN1: begin
                    if (def_pkg::RVH) begin
                        // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                        // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                        mask = (mstateen1_q & riscv_pkg::HSTATEEN1_SE); // all other bits are reserved for future use
                        hstateen1_d = (hstateen1_q & ~mask) | (csr_wdata & mask);
                    end
                    else update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HSTATEEN2: begin
                    if (def_pkg::RVH) begin
                        // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                        // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                        mask = (mstateen2_q & riscv_pkg::HSTATEEN2_SE); // all other bits are reserved for future use
                        hstateen2_d = (hstateen2_q & ~mask) | (csr_wdata & mask);
                    end
                    else update_access_exception = 1'b1;
                end
                riscv_pkg::CSR_HSTATEEN3: begin
                    if (def_pkg::RVH) begin
                        // For every bit in an mstateen CSR that is zero (whether read-only zero or set to zero),
                        // the same bit appears as read-only zero in the matching hstateen and sstateen CSRs
                        mask = (mstateen3_q & riscv_pkg::HSTATEEN3_SE); // all other bits are reserved for future use
                        hstateen3_d = (hstateen3_q & ~mask) | (csr_wdata & mask);
                    end
                    else update_access_exception = 1'b1;
                end
                
                // virtual supervisor registers
                riscv_pkg::CSR_VSSTATUS: begin
                  if (def_pkg::RVH) begin
                    mask          = def_pkg::SMODE_STATUS_WRITE_MASK;
                    vsstatus_d    = (vsstatus_q & ~mask) | (csr_wdata & mask);
                    vsstatus_d.xs = riscv_pkg::Off;
                    // this register has side-effects on other registers, flush the pipeline
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_VSIP: begin
                  if (def_pkg::RVH) begin
                    // only the virtual supervisor software interrupt is write-able, iff delegated
                    mask  = riscv_pkg::MIP_VSSIP & hideleg_q;
                    mip_d = (mip_q & ~mask) | (({csr_wdata[63-1:0], 1'b0}) & mask); //(csr_wdata << 1) & mask
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end
                riscv_pkg::CSR_VSIE:
                    if (def_pkg::RVH)   mie_d = (mie_q & ~hideleg_q) | (({csr_wdata[63-1:0], 1'b0}) & hideleg_q); //(csr_wdata << 1) & hideleg_q
                    else                update_access_exception = 1'b1;
                riscv_pkg::CSR_VSTVEC: begin
                    if (def_pkg::RVH) begin
                        vstvec_d = {csr_wdata[63:2], 1'b0, csr_wdata[0]};
                    end else begin
                        update_access_exception = 1'b1;
                    end
                end
                riscv_pkg::CSR_VSSCRATCH:
                    if (def_pkg::RVH)   vsscratch_d = csr_wdata;
                    else                update_access_exception = 1'b1;
                riscv_pkg::CSR_VSEPC:
                    if (def_pkg::RVH)   vsepc_d = {csr_wdata[63:1], 1'b0};
                    else                update_access_exception = 1'b1;
                riscv_pkg::CSR_VSCAUSE:
                    if (def_pkg::RVH)   vscause_d = csr_wdata;
                    else                update_access_exception = 1'b1;
                riscv_pkg::CSR_VSTVAL:
                    if (def_pkg::RVH)   vstval_d = csr_wdata;
                    else                update_access_exception = 1'b1;
                riscv_pkg::CSR_VSATP: begin
                  if (def_pkg::RVH) begin
                    if ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && hstatus_q.vtvm && v_mode_q) begin
                      virtual_update_access_exception = 1'b1;
                    end else begin
                      vsatp = riscv_pkg::satp_t'(csr_wdata);
                      // only make ASID_LEN - 1 bit stick, that way software can figure out how many ASID bits are supported
                      vsatp.asid = vsatp.asid & {{(16 - ASID_WIDTH) {1'b0}}, {ASID_WIDTH{1'b1}}};
                      // only update if we actually support this mode
                      if ((vsatp.mode == def_pkg::MODE_OFF) || (vsatp.mode == def_pkg::MODE_SV39))
                        vsatp_d = vsatp;
                    end
                    // changing the mode can have side-effects on address translation (e.g.: other instructions), re-fetch
                    // the next instruction by executing a flush
                  end else begin
                    update_access_exception = 1'b1;
                  end
                end

                riscv_pkg::CSR_MSTATUS: begin
                    // mask of the bits that are set to zero
                    mask = riscv_pkg::MSTATUS_UIE | riscv_pkg::MSTATUS_UPIE | riscv_pkg::MSTATUS_XS | riscv_pkg::MSTATUS64_WPRI;
                    mstatus_int      = csr_wdata & ~mask;
                    // If h-extension is not enabled, priv level HS is reserved
                    if (!def_pkg::RVH) begin
                      if (mstatus_int[12:11] == riscv_pkg::PRIV_LVL_HS) begin
                        mstatus_int[12:11] = mstatus_q.mpp;
                      end
                    end
                    // this register has side-effects on other registers, flush the pipeline
                end
                // MISA is WARL (Write Any Value, Reads Legal Value)
                riscv_pkg::CSR_MISA:;
                // machine exception delegation register
                riscv_pkg::CSR_MEDELEG: begin
                    mask = (1 << riscv_pkg::INSTR_ADDR_MISALIGNED) |
                           (1 << riscv_pkg::INSTR_ACCESS_FAULT) |
                           (1 << riscv_pkg::ILLEGAL_INSTR) |
                           (1 << riscv_pkg::BREAKPOINT) |
                           (1 << riscv_pkg::LD_ADDR_MISALIGNED) |
                           (1 << riscv_pkg::LD_ACCESS_FAULT) |
                           (1 << riscv_pkg::ST_AMO_ADDR_MISALIGNED) |
                           (1 << riscv_pkg::ST_AMO_ACCESS_FAULT) |
                           (1 << riscv_pkg::USER_ECALL) |
                           ((def_pkg::RVH ? 1 : 0) << riscv_pkg::VIRTUALSUPERVISOR_ECALL) |
                           (1 << riscv_pkg::INSTR_PAGE_FAULT) |
                           (1 << riscv_pkg::LD_PAGE_FAULT) |
                           (1 << riscv_pkg::ST_AMO_PAGE_FAULT) |
                           ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::INSTR_GUEST_PAGE_FAULT) |
                           ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::LD_GUEST_PAGE_FAULT) |
                           ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::VIRTUAL_INSTRUCTION) |
                           ((def_pkg::RVH ? 1 : 0)  << riscv_pkg::ST_GUEST_AMO_PAGE_FAULT);
                    medeleg_d = (medeleg_q & ~mask) | (csr_wdata & mask);
                end
                // machine interrupt delegation register
                // we do not support user interrupt delegation
                riscv_pkg::CSR_MIDELEG: begin
                    mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_LCOFIP;
                    if (def_pkg::RVH) begin
                      mideleg_d = (mideleg_q & ~mask) | (csr_wdata & mask) | def_pkg::HS_DELEG_INTERRUPTS;
                    end else begin
                      mideleg_d = (mideleg_q & ~mask) | (csr_wdata & mask);
                    end
                end
                // mask the register so that unsupported interrupts can never be set
                riscv_pkg::CSR_MIE: begin
                  if (def_pkg::RVH) begin
                    mask = def_pkg::HS_DELEG_INTERRUPTS
                         | riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP
                         | riscv_pkg::MIP_MSIP | riscv_pkg::MIP_MTIP | riscv_pkg::MIP_MEIP
                         | riscv_pkg::MIP_LCOFIP;
                  end else begin
                      mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP
                           | riscv_pkg::MIP_MSIP | riscv_pkg::MIP_MTIP | riscv_pkg::MIP_MEIP
                           | riscv_pkg::MIP_LCOFIP;
                  end
                  mie_d = (mie_q & ~mask) | (csr_wdata & mask); // we only support supervisor and M-mode interrupts
                end

                riscv_pkg::CSR_MTVEC: begin
                    mtvec_d = {csr_wdata[63:2], 1'b0, csr_wdata[0]};
                    // we are in vector mode, this implementation requires the additional
                    // alignment constraint of 64 * 4 bytes
                    if (csr_wdata[0]) mtvec_d = {csr_wdata[63:8], 7'b0, csr_wdata[0]};
                end

                riscv_pkg::CSR_MCOUNTEREN:         mcounteren_d = csr_wdata[31:0];
                riscv_pkg::CSR_MCOUNTINHIBIT:      mcountinhibit_d = csr_wdata[31:0];
                riscv_pkg::CSR_MCYCLECFG:          mcyclecfg_d = csr_wdata;
                riscv_pkg::CSR_MINSTRETCFG:        minstretcfg_d = csr_wdata;
                riscv_pkg::CSR_MSCRATCH:           mscratch_d  = csr_wdata;
                riscv_pkg::CSR_MEPC:               mepc_int    = {csr_wdata[63:2], 2'b0}; // we only support IALIGN=32 since we do not support C extension
                riscv_pkg::CSR_MCAUSE:             mcause_int  = csr_wdata;
                riscv_pkg::CSR_MTVAL:              mtval_int   = csr_wdata;
                riscv_pkg::CSR_MENVCFG:            menvcfg_d   = csr_wdata;
                riscv_pkg::CSR_MTINST:
                    if (def_pkg::RVH) mtinst_d = {{32{1'b0}}, csr_wdata[31:0]};
                    else update_access_exception = 1'b1;
                riscv_pkg::CSR_MTVAL2,
                riscv_pkg::CSR_MIP: begin
                  if (def_pkg::RVH) begin
                    mask = riscv_pkg::MIP_SSIP
                         | riscv_pkg::MIP_STIP
                         | riscv_pkg::MIP_SEIP
                         | riscv_pkg::MIP_LCOFIP
                         | riscv_pkg::MIP_VSSIP;
                  end else begin
                    mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_LCOFIP;
                  end
                  mip_d = (mip_q & ~mask) | (csr_wdata & mask);
                end
                riscv_pkg::CSR_MSTATEEN0: begin
                    // all other bits are read-only zero
                    mask = riscv_pkg::MSTATEEN0_SE | riscv_pkg::MSTATEEN0_ENVCFG;
                    mstateen0_d = (csr_wdata & mask);
                end
                riscv_pkg::CSR_MSTATEEN1: begin
                    // all other bits are reserved for future use
                    mask = riscv_pkg::MSTATEEN1_SE;
                    mstateen1_d = (csr_wdata & mask);
                end
                riscv_pkg::CSR_MSTATEEN2: begin
                    // all other bits are reserved for future use
                    mask = riscv_pkg::MSTATEEN2_SE;
                    mstateen2_d = (csr_wdata & mask);
                end
                riscv_pkg::CSR_MSTATEEN3: begin
                    // all other bits are reserved for future use
                    mask = riscv_pkg::MSTATEEN3_SE;
                    mstateen3_d = (csr_wdata & mask);
                end
                // performance counters
                riscv_pkg::CSR_MCYCLE:             cycle_d     = csr_wdata;
                riscv_pkg::CSR_MINSTRET:           instret_d     = csr_wdata;

                riscv_pkg::CSR_MHPM_COUNTER_3,
                riscv_pkg::CSR_MHPM_COUNTER_4,
                riscv_pkg::CSR_MHPM_COUNTER_5,
                riscv_pkg::CSR_MHPM_COUNTER_6,
                riscv_pkg::CSR_MHPM_COUNTER_7,
                riscv_pkg::CSR_MHPM_COUNTER_8,
                riscv_pkg::CSR_MHPM_COUNTER_9,
                riscv_pkg::CSR_MHPM_COUNTER_10,
                riscv_pkg::CSR_MHPM_COUNTER_11,
                riscv_pkg::CSR_MHPM_COUNTER_12,
                riscv_pkg::CSR_MHPM_COUNTER_13,
                riscv_pkg::CSR_MHPM_COUNTER_14,
                riscv_pkg::CSR_MHPM_COUNTER_15,
                riscv_pkg::CSR_MHPM_COUNTER_16,
                riscv_pkg::CSR_MHPM_COUNTER_17,
                riscv_pkg::CSR_MHPM_COUNTER_18,
                riscv_pkg::CSR_MHPM_COUNTER_19,
                riscv_pkg::CSR_MHPM_COUNTER_20,
                riscv_pkg::CSR_MHPM_COUNTER_21,
                riscv_pkg::CSR_MHPM_COUNTER_22,
                riscv_pkg::CSR_MHPM_COUNTER_23,
                riscv_pkg::CSR_MHPM_COUNTER_24,
                riscv_pkg::CSR_MHPM_COUNTER_25,
                riscv_pkg::CSR_MHPM_COUNTER_26,
                riscv_pkg::CSR_MHPM_COUNTER_27,
                riscv_pkg::CSR_MHPM_COUNTER_28,
                riscv_pkg::CSR_MHPM_COUNTER_29,
                riscv_pkg::CSR_MHPM_COUNTER_30,
                riscv_pkg::CSR_MHPM_COUNTER_31: begin
                    perf_we_o = 1'b1;
                    perf_data_o = csr_wdata;
                end

                riscv_pkg::CSR_MHPM_EVENT_3,
                riscv_pkg::CSR_MHPM_EVENT_4,
                riscv_pkg::CSR_MHPM_EVENT_5,
                riscv_pkg::CSR_MHPM_EVENT_6,
                riscv_pkg::CSR_MHPM_EVENT_7,
                riscv_pkg::CSR_MHPM_EVENT_8,
                riscv_pkg::CSR_MHPM_EVENT_9,
                riscv_pkg::CSR_MHPM_EVENT_10,
                riscv_pkg::CSR_MHPM_EVENT_11,
                riscv_pkg::CSR_MHPM_EVENT_12,
                riscv_pkg::CSR_MHPM_EVENT_13,
                riscv_pkg::CSR_MHPM_EVENT_14,
                riscv_pkg::CSR_MHPM_EVENT_15,
                riscv_pkg::CSR_MHPM_EVENT_16,
                riscv_pkg::CSR_MHPM_EVENT_17,
                riscv_pkg::CSR_MHPM_EVENT_18,
                riscv_pkg::CSR_MHPM_EVENT_19,
                riscv_pkg::CSR_MHPM_EVENT_20,
                riscv_pkg::CSR_MHPM_EVENT_21,
                riscv_pkg::CSR_MHPM_EVENT_22,
                riscv_pkg::CSR_MHPM_EVENT_23,
                riscv_pkg::CSR_MHPM_EVENT_24,
                riscv_pkg::CSR_MHPM_EVENT_25,
                riscv_pkg::CSR_MHPM_EVENT_26,
                riscv_pkg::CSR_MHPM_EVENT_27,
                riscv_pkg::CSR_MHPM_EVENT_28,
                riscv_pkg::CSR_MHPM_EVENT_29,
                riscv_pkg::CSR_MHPM_EVENT_30,
                riscv_pkg::CSR_MHPM_EVENT_31: begin
                    perf_we_o = 1'b1;
                    perf_data_o = csr_wdata;
                end

                riscv_pkg::CSR_CYCLE,
                riscv_pkg::CSR_TIME,
                riscv_pkg::CSR_INSTRET,
                riscv_pkg::CSR_HPM_COUNTER_3,
                riscv_pkg::CSR_HPM_COUNTER_4,
                riscv_pkg::CSR_HPM_COUNTER_5,
                riscv_pkg::CSR_HPM_COUNTER_6,
                riscv_pkg::CSR_HPM_COUNTER_7,
                riscv_pkg::CSR_HPM_COUNTER_8,
                riscv_pkg::CSR_HPM_COUNTER_9,
                riscv_pkg::CSR_HPM_COUNTER_10,
                riscv_pkg::CSR_HPM_COUNTER_11,
                riscv_pkg::CSR_HPM_COUNTER_12,
                riscv_pkg::CSR_HPM_COUNTER_13,
                riscv_pkg::CSR_HPM_COUNTER_14,
                riscv_pkg::CSR_HPM_COUNTER_15,
                riscv_pkg::CSR_HPM_COUNTER_16,
                riscv_pkg::CSR_HPM_COUNTER_17,
                riscv_pkg::CSR_HPM_COUNTER_18,
                riscv_pkg::CSR_HPM_COUNTER_19,
                riscv_pkg::CSR_HPM_COUNTER_20,
                riscv_pkg::CSR_HPM_COUNTER_21,
                riscv_pkg::CSR_HPM_COUNTER_22,
                riscv_pkg::CSR_HPM_COUNTER_23,
                riscv_pkg::CSR_HPM_COUNTER_24,
                riscv_pkg::CSR_HPM_COUNTER_25,
                riscv_pkg::CSR_HPM_COUNTER_26,
                riscv_pkg::CSR_HPM_COUNTER_27,
                riscv_pkg::CSR_HPM_COUNTER_28,
                riscv_pkg::CSR_HPM_COUNTER_29,
                riscv_pkg::CSR_HPM_COUNTER_30,
                riscv_pkg::CSR_HPM_COUNTER_31,
                riscv_pkg::CSR_SCOUNTOVF:
                    update_access_exception = 1'b1;

                `ifdef CONF_SARGANTANA_ENABLE_PCR
                riscv_pkg::CSR_MEM_MAP_0,
                riscv_pkg::CSR_MEM_MAP_1,
                riscv_pkg::CSR_MEM_MAP_2,
                riscv_pkg::CSR_MEM_MAP_3,
                riscv_pkg::CSR_MEM_MAP_4,
                riscv_pkg::CSR_MEM_MAP_5,
                riscv_pkg::CSR_MEM_MAP_6,
                riscv_pkg::CSR_MEM_MAP_7,
                riscv_pkg::CSR_MEM_MAP_8,
                riscv_pkg::CSR_MEM_MAP_9,
                riscv_pkg::CSR_MEM_MAP_10,                
                riscv_pkg::CSR_MEM_MAP_11,                
                riscv_pkg::CSR_MEM_MAP_12,                
                riscv_pkg::CSR_MEM_MAP_13,                
                riscv_pkg::CSR_MEM_MAP_14,                
                riscv_pkg::CSR_MEM_MAP_15,
                riscv_pkg::CSR_IO_MAP_0,
                riscv_pkg::CSR_IO_MAP_1,
                riscv_pkg::CSR_IO_MAP_2,
                riscv_pkg::CSR_IO_MAP_3,
                riscv_pkg::CSR_IO_MAP_4,
                riscv_pkg::CSR_IO_MAP_5,
                riscv_pkg::CSR_IO_MAP_6,
                riscv_pkg::CSR_IO_MAP_7,
                riscv_pkg::CSR_IO_MAP_8,
                riscv_pkg::CSR_IO_MAP_9,
                riscv_pkg::CSR_IO_MAP_10,
                riscv_pkg::CSR_IO_MAP_11,
                riscv_pkg::CSR_IO_MAP_12,
                riscv_pkg::CSR_IO_MAP_13,
                riscv_pkg::CSR_IO_MAP_14,
                riscv_pkg::CSR_IO_MAP_15,
                riscv_pkg::CSR_IRQ_MAP_0,
                riscv_pkg::CSR_IRQ_MAP_1,
                riscv_pkg::CSR_IRQ_MAP_2,
                riscv_pkg::CSR_IRQ_MAP_3,
                riscv_pkg::CSR_IRQ_MAP_4,
                riscv_pkg::CSR_IRQ_MAP_5,
                riscv_pkg::CSR_IRQ_MAP_6,
                riscv_pkg::CSR_IRQ_MAP_7,
                riscv_pkg::CSR_IRQ_MAP_8,
                riscv_pkg::CSR_IRQ_MAP_9,
                riscv_pkg::CSR_IRQ_MAP_10,
                riscv_pkg::CSR_IRQ_MAP_11,
                riscv_pkg::CSR_IRQ_MAP_12,
                riscv_pkg::CSR_IRQ_MAP_13,
                riscv_pkg::CSR_IRQ_MAP_14,
                riscv_pkg::CSR_IRQ_MAP_15,
                riscv_pkg::FROM_HOST,
                riscv_pkg::CSR_HYPERRAM_CONFIG, 
                riscv_pkg::CSR_SPI_CONFIG, 
                riscv_pkg::CSR_CNM_CONFIG,
                riscv_pkg::TO_HOST,
                riscv_pkg::CLEAR_MIP: begin
                        pcr_req_data_o = csr_wdata;
                end
                `endif // CONF_SARGANTANA_ENABLE_PCR

                `ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
                riscv_pkg::CSR_DYN_MEM_LATENCY:
                    dyn_fpga_mem_latency_d = csr_wdata;
                `endif

                riscv_pkg::CSR_PMPCFG_0:;
                riscv_pkg::CSR_PMPCFG_1:;
                riscv_pkg::CSR_PMPCFG_2:;
                riscv_pkg::CSR_PMPCFG_3:;

                riscv_pkg::CSR_PMPADDR_0:;
                riscv_pkg::CSR_PMPADDR_1:;
                riscv_pkg::CSR_PMPADDR_2:;
                riscv_pkg::CSR_PMPADDR_3:;
                riscv_pkg::CSR_PMPADDR_4:;
                riscv_pkg::CSR_PMPADDR_5:;
                riscv_pkg::CSR_PMPADDR_6:;
                riscv_pkg::CSR_PMPADDR_7:;
                riscv_pkg::CSR_PMPADDR_8:;
                riscv_pkg::CSR_PMPADDR_9:;
                riscv_pkg::CSR_PMPADDR_10:;
                riscv_pkg::CSR_PMPADDR_11:;
                riscv_pkg::CSR_PMPADDR_12:;
                riscv_pkg::CSR_PMPADDR_13:;
                riscv_pkg::CSR_PMPADDR_14:;
                riscv_pkg::CSR_PMPADDR_15:;
                default: update_access_exception = 1'b1;
            endcase
        end 

        // assign the temporal value to _d values to avoid multiples assign in the same cicle
        mstatus_d   = mstatus_int;
        mcause_d    = mcause_int;
        scause_d    = scause_int;
        mtval_d     = mtval_int;
        stval_d     = stval_int;
        mepc_d      = mepc_int;
        sepc_d      = sepc_int;


        if (def_pkg::RVH) begin
          hstatus_d.vsxl = riscv_pkg::XLEN_64;
          vsstatus_d.uxl = riscv_pkg::XLEN_64;
        end
        // mark the floating point extension register as dirty 
        if (def_pkg::FP_PRESENT && (dirty_fp_state_csr)) begin
            mstatus_d.fs = riscv_pkg::Dirty;
            if (def_pkg::RVH && v_mode_q) begin
              vsstatus_d.fs = riscv_pkg::Dirty;
            end
        end
        // hardwire to zero if floating point extension is not present
        else if (!def_pkg::FP_PRESENT) begin
            mstatus_d.fs = riscv_pkg::Off;
            if (def_pkg::RVH && v_mode_q) begin
              vsstatus_d.fs = riscv_pkg::Off;
            end
        end

        // mark the vector extension register as dirty 
        if (def_pkg::V_PRESENT && (dirty_v_state_csr)) begin
            mstatus_d.vs = riscv_pkg::Dirty;
            if (def_pkg::RVH && v_mode_q) begin
              vsstatus_d.vs = riscv_pkg::Dirty;
            end
        end
        // hardwire to zero if vector extension is not present
        else if (!def_pkg::V_PRESENT) begin
            mstatus_d.vs = riscv_pkg::Off;
            if (def_pkg::RVH && v_mode_q) begin
              vsstatus_d.vs = riscv_pkg::Off;
            end
        end
        if (def_pkg::RVH) begin
          vsstatus_d.sd = (vsstatus_q.xs == riscv_pkg::Dirty) | (vsstatus_q.fs == riscv_pkg::Dirty);
        end


        // -----------------
        // Interrupt Control
        // -----------------
        // we decode an interrupt the same as an exception, hence it will be taken if the instruction did not
        // throw any previous exception.
        // we have three interrupt sources: external interrupts, software interrupts, timer interrupts (order of precedence)
        // for two privilege levels: Supervisor and Machine Mode
        
        interrupt_cause_d = interrupt_cause_q;
        interrupt_d = 1'b0;
        interrupt_cause = 64'b0;
        ex_tval = 64'b0;
        ex_tval2 = 64'b0;
        // Machine Mode External Interrupt
        if (mip_q[riscv_pkg::M_EXT_INTERRUPT[5:0]] && mie_q[riscv_pkg::M_EXT_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::M_EXT_INTERRUPT;
        end
        // Machine Mode Software Interrupt
        else if (mip_q[riscv_pkg::M_SW_INTERRUPT[5:0]] && mie_q[riscv_pkg::M_SW_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::M_SW_INTERRUPT;
        end
        // Machine Timer Interrupt
        else if (mip_q[riscv_pkg::M_TIMER_INTERRUPT[5:0]] && mie_q[riscv_pkg::M_TIMER_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::M_TIMER_INTERRUPT;
        end
        // Supervisor External Interrupt
        else if (mie_q[riscv_pkg::S_EXT_INTERRUPT[5:0]] && ( (mip_q[riscv_pkg::S_EXT_INTERRUPT[5:0]]) || irq_q[1] ) ) begin
            interrupt_cause = riscv_pkg::S_EXT_INTERRUPT;
        end
        // Supervisor Software Interrupt
        else if (mie_q[riscv_pkg::S_SW_INTERRUPT[5:0]] && mip_q[riscv_pkg::S_SW_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::S_SW_INTERRUPT;
        end
        // Supervisor Timer Interrupt
        else if (mie_q[riscv_pkg::S_TIMER_INTERRUPT[5:0]] && mip_q[riscv_pkg::S_TIMER_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::S_TIMER_INTERRUPT;
        end
        // Local Count Overflow Interrupt
        else if (mip_q[riscv_pkg::LCOF_INTERRUPT[5:0]] && mie_q[riscv_pkg::LCOF_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::LCOF_INTERRUPT;
        end
        // Virtual Supervisor External Interrupt
        else if (mie_q[riscv_pkg::VS_EXT_INTERRUPT[5:0]] && ( (mip_q[riscv_pkg::VS_EXT_INTERRUPT[5:0]]) || irq_q[1] ) ) begin
            interrupt_cause = riscv_pkg::VS_EXT_INTERRUPT;
        end
        // Virtual Supervisor Software Interrupt
        else if (mie_q[riscv_pkg::VS_SW_INTERRUPT[5:0]] && mip_q[riscv_pkg::VS_SW_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::VS_SW_INTERRUPT;
        end
        // Virtual Supervisor Timer Interrupt
        else if (mie_q[riscv_pkg::VS_TIMER_INTERRUPT[5:0]] && mip_q[riscv_pkg::VS_TIMER_INTERRUPT[5:0]]) begin
            interrupt_cause = riscv_pkg::VS_TIMER_INTERRUPT;
        end
        
        // if the priv is different of M or the mie is 1, the interrups are enable
        global_enable = ((mstatus_q.mie && (priv_lvl_o == riscv_pkg::PRIV_LVL_M))
                                        || (priv_lvl_o != riscv_pkg::PRIV_LVL_M)) && (~debug_mode_en_q) && (~dcsr_q.step);

        if (interrupt_cause[63] && global_enable) begin
            // However, if bit i in mideleg is set, interrupts are considered to be globally enabled if the hart’s current privilege
            // mode equals the delegated privilege mode (S or U) and that mode’s interrupt enable bit
            // (SIE or UIE in mstatus) is set, or if the current privilege mode is less than the delegated privilege mode.
            if (mideleg_q[interrupt_cause[5:0]] && (~def_pkg::RVH || ~hideleg_q[interrupt_cause[5:0]])) begin
                if ((~def_pkg::RVH || ~v_mode_q) && ((mstatus_q.sie && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) || (priv_lvl_q == riscv_pkg::PRIV_LVL_U))) begin
                    interrupt_d = 1'b1;
                    interrupt_cause_d = interrupt_cause;
                end else if (def_pkg::RVH && v_mode_q && ((priv_lvl_q == riscv_pkg::PRIV_LVL_S) || (priv_lvl_q == riscv_pkg::PRIV_LVL_U))) begin
                  interrupt_d = 1'b1;
                  interrupt_cause_d = interrupt_cause;
                end
            end else if (def_pkg::RVH && hideleg_q[interrupt_cause[5:0]]) begin
                if ((~def_pkg::RVH || ~v_mode_q) && ((mstatus_q.sie && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) || (priv_lvl_q == riscv_pkg::PRIV_LVL_U))) begin
                  interrupt_d = 1'b1;
                  interrupt_cause_d = interrupt_cause;
                end else if (def_pkg::RVH && v_mode_q && ((vsstatus_q.sie && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) || (priv_lvl_q == riscv_pkg::PRIV_LVL_U))) begin
                  interrupt_d = 1'b1;
                  interrupt_cause_d = interrupt_cause;
                  interrupt_cause_d[5:0] = interrupt_cause[5:0] - 1;
                end
            end else begin
                interrupt_d = 1'b1;
                interrupt_cause_d = interrupt_cause;
            end
        end
        
        // a sfence is executed and a flush is needed
        if (flush_sfence) begin
          if(!def_pkg::RVH)
            flush = 1'b1;
          else begin
            if((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && v_mode_q) //Virtual supervisor mode
              flush_vsatp = 1'b1;
            else if((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && !v_mode_q) //HS-mode
              flush_satp = 1'b1;
            else flush = 1'b1;
          end
        end
        // a hfence is executed and a flush is needed
        if (def_pkg::RVH && flush_hfence_vvma) begin
            flush_vsatp = 1'b1;
        end
        // a hfence is executed and a flush is needed
        if (def_pkg::RVH && flush_hfence_gvma) begin
            flush_hgatp = 1'b1;
        end
        flush_o = flush;
        flush_satp_o = flush_satp;
        flush_vsatp_o = flush_vsatp;
        flush_hgatp_o = flush_hgatp;

        //Output connection
        interrupt_o = interrupt_q;
        interrupt_cause_o = interrupt_cause_q;
        // -----------------------
        // Manage Exception Stack
        // -----------------------
        // update exception CSRs
        // we got an exception update cause, pc and stval register
        trap_to_priv_lvl = riscv_pkg::PRIV_LVL_M;
        trap_to_v_mode = 1'b0;
        // Exception is taken and we are not in debug mode
        // exceptions in debug mode don't update any fields
        
        if ((((ex_cause_i != riscv_pkg::DEBUG_REQUEST) && ex_i) || csr_xcpt) && (~debug_mode_en_q)) begin
            // do not flush, flush is reserved for CSR writes with side effects
            flush_o   = 1'b0;
            flush_satp_o = 1'b0;
            flush_vsatp_o = 1'b0;
            flush_hgatp_o = 1'b0;
            ex_tval = pc_i;
            ex_tval2 = 64'b0;
            //tval is the actual pc except for the data access exeptions
            if (ex_i && ex_cause_i inside {riscv_pkg::LD_ADDR_MISALIGNED, riscv_pkg::LD_ACCESS_FAULT, 
                                    riscv_pkg::ST_AMO_ADDR_MISALIGNED, riscv_pkg::ST_AMO_ACCESS_FAULT,
                                    riscv_pkg::LD_PAGE_FAULT, riscv_pkg::ST_AMO_PAGE_FAULT,
                                    riscv_pkg::LD_GUEST_PAGE_FAULT, riscv_pkg::ST_GUEST_AMO_PAGE_FAULT,
                                    riscv_pkg::INSTR_PAGE_FAULT, riscv_pkg::INSTR_ADDR_MISALIGNED,
                                    riscv_pkg::INSTR_GUEST_PAGE_FAULT, riscv_pkg::INSTR_ACCESS_FAULT}) begin
                ex_tval = ex_origin_i;
            end else if ((ex_i && (ex_cause_i inside {riscv_pkg::ILLEGAL_INSTR, riscv_pkg::VIRTUAL_INSTRUCTION})) || 
                         (csr_xcpt && (csr_xcpt_cause inside {riscv_pkg::ILLEGAL_INSTR, riscv_pkg::VIRTUAL_INSTRUCTION}))) begin
                ex_tval = ex_origin_i;
	        end else if (csr_xcpt && (csr_xcpt_cause == riscv_pkg::BREAKPOINT)) begin
                ex_tval = pc_i;
            end else begin
                ex_tval = 64'b0;
            end
            if(def_pkg::RVH) begin
                if ((ex_i && ex_cause_i inside {riscv_pkg::LD_GUEST_PAGE_FAULT,
                                        riscv_pkg::ST_GUEST_AMO_PAGE_FAULT, riscv_pkg::INSTR_GUEST_PAGE_FAULT}) ||
                    (csr_xcpt && (csr_xcpt_cause inside {riscv_pkg::LD_GUEST_PAGE_FAULT,
                                        riscv_pkg::ST_GUEST_AMO_PAGE_FAULT, riscv_pkg::INSTR_GUEST_PAGE_FAULT}))) begin
                    ex_tval2 = ex_origin2_i;
                end else begin
                    ex_tval2 = 64'b0;
                end
            end
            // figure out where to trap to
            // a m-mode trap might be delegated if we are taking it in S mode
            // first figure out if this was an exception or an interrupt e.g.: look at bit (XLEN-1)
            // the cause register can only be $clog2(XLEN) bits long (as we only support XLEN exceptions)
            if (def_pkg::RVH) begin
                    if(ex_i && (
                        (ex_cause_i[63] && mideleg_q[interrupt_cause[5:0]]) || // Check original interrupt cause
                        (~ex_cause_i[63] && medeleg_q[ex_cause_i[5:0]]))
                    ) begin
                        trap_to_priv_lvl = (priv_lvl_o == riscv_pkg::PRIV_LVL_M) ? riscv_pkg::PRIV_LVL_M : riscv_pkg::PRIV_LVL_S;
                        if(
                            (ex_cause_i[63] && hideleg_q[interrupt_cause[5:0]]) || // Check original interrupt cause
                            (~ex_cause_i[63] && hedeleg_q[ex_cause_i[5:0]])
                        ) begin
                            trap_to_v_mode = v_mode_q;
                        end
                    end else if (csr_xcpt && (
                        (csr_xcpt_cause[63] && mideleg_q[interrupt_cause[5:0]]) || // Check original interrupt cause
                        (~csr_xcpt_cause[63] && medeleg_q[csr_xcpt_cause[5:0]]))
                    ) begin
                        trap_to_priv_lvl = (priv_lvl_o == riscv_pkg::PRIV_LVL_M) ? riscv_pkg::PRIV_LVL_M : riscv_pkg::PRIV_LVL_S;
                        if(
                            (csr_xcpt_cause[63] && hideleg_q[interrupt_cause[5:0]]) || // Check original interrupt cause
                            (~csr_xcpt_cause[63] && hedeleg_q[csr_xcpt_cause[5:0]])
                        ) begin
                            trap_to_v_mode = v_mode_q;
                        end
                    end
            end else begin
                if ((ex_i &&((ex_cause_i[63] && mideleg_q[interrupt_cause[5:0]]) ||  // Check original interrupt cause
                    (~ex_cause_i[63] && medeleg_q[ex_cause_i[5:0]]))) ||
                    (csr_xcpt && ((csr_xcpt_cause[63] && mideleg_q[interrupt_cause[5:0]]) ||  // Check original interrupt cause
                    (~csr_xcpt_cause[63] && medeleg_q[csr_xcpt_cause[5:0]])))) begin
                    // traps never transition from a more-privileged mode to a less privileged mode
                    // so if we are already in M mode, stay there
                    trap_to_priv_lvl = (priv_lvl_o == riscv_pkg::PRIV_LVL_M) ? riscv_pkg::PRIV_LVL_M : riscv_pkg::PRIV_LVL_S;
                end
            end
    
          // trap to supervisor mode
          if (trap_to_priv_lvl == riscv_pkg::PRIV_LVL_S) begin
            if (def_pkg::RVH) begin
              if (trap_to_v_mode) begin
                // update sstatus
                vsstatus_d.sie = 1'b0;
                vsstatus_d.spie = vsstatus_q.sie;
                // this can either be user or supervisor mode
                vsstatus_d.spp = priv_lvl_q[0];
                // set cause
                vscause_d = csr_xcpt ? csr_xcpt_cause : ex_cause_i;
                // set epc
                vsepc_d = pc_i;
                // set vstval
                vstval_d = ex_tval;
              end else begin
                htinst_d       = ((ex_cause_i inside {
                                    riscv_pkg::INSTR_ACCESS_FAULT,
                                    riscv_pkg::ILLEGAL_INSTR,
                                    riscv_pkg::BREAKPOINT,
                                    riscv_pkg::USER_ECALL,
                                    riscv_pkg::SUPERVISOR_ECALL,
                                    riscv_pkg::ECALL_MMODE,
                                    riscv_pkg::INSTR_PAGE_FAULT,
                                    riscv_pkg::INSTR_GUEST_PAGE_FAULT,
                                    riscv_pkg::VIRTUAL_INSTRUCTION
                                  } || ex_cause_i[63])) ? '0 : {{32 {1'b0}}, ex_tinst_i};
                hstatus_d.spvp = v_mode_q ? priv_lvl_q[0] : hstatus_d.spvp;
                htval_d = {{25{1'b0}}, ex_tval2};
                hstatus_d.gva = ex_gva_i;
                hstatus_d.spv = v_mode_q;
              end
            end
            if (!def_pkg::RVH || (def_pkg::RVH && !trap_to_v_mode)) begin
              // update sstatus
              mstatus_d.sie = 1'b0;
              mstatus_d.spie = mstatus_q.sie;
              // this can either be user or supervisor mode
              mstatus_d.spp = priv_lvl_q[0];
              // set cause
              scause_d = csr_xcpt ? csr_xcpt_cause : ex_cause_i;
              // set epc
              sepc_d = pc_i;
              // set mtval or stval
              stval_d = ex_tval;
            end
            // trap to machine mode
          end else begin
            // update mstatus
            mstatus_d.mie = 1'b0;
            mstatus_d.mpie = mstatus_q.mie;
            // save the previous privilege mode
            mstatus_d.mpp = priv_lvl_q;
            mcause_d = csr_xcpt ? csr_xcpt_cause : ex_cause_i;
            // set epc
            mepc_d = pc_i;
            // set mtval or stval
            mtval_d = ex_tval;
    
            if (def_pkg::RVH) begin
              // save previous virtualization mode
              mstatus_d.mpv = v_mode_q;
              mtinst_d      = ((ex_cause_i inside {
                                riscv_pkg::INSTR_ADDR_MISALIGNED,
                                riscv_pkg::INSTR_ACCESS_FAULT,
                                riscv_pkg::ILLEGAL_INSTR,
                                riscv_pkg::BREAKPOINT,
                                riscv_pkg::USER_ECALL,
                                riscv_pkg::SUPERVISOR_ECALL,
                                riscv_pkg::ECALL_MMODE,
                                riscv_pkg::INSTR_PAGE_FAULT,
                                riscv_pkg::INSTR_GUEST_PAGE_FAULT,
                                riscv_pkg::VIRTUAL_INSTRUCTION
                                } || ex_cause_i[63])) ? '0 : {{32{1'b0}}, ex_tinst_i};
              mtval2_d = {{25{1'b0}}, ex_tval2};
              mstatus_d.gva = ex_gva_i;
            end
          end
    
          priv_lvl_d = trap_to_priv_lvl;
          if (def_pkg::RVH) begin
            v_mode_d = trap_to_v_mode;
          end
        end

        // ------------------------------
        // Return from Environment
        // ------------------------------
        // When executing an xRET instruction, supposing xPP holds the value y, xIE is set to xPIE; the privilege
        // mode is changed to y; xPIE is set to 1; and xPP is set to U
        else if (mret) begin
            // return from exception, IF doesn't care from where we are returning
            eret_o = 1'b1;
            // return to the previous privilege level and restore all enable flags
            // get the previous machine interrupt enable flag
            mstatus_d.mie  = mstatus_q.mpie;
            // restore the previous privilege level
            priv_lvl_d     = mstatus_q.mpp;
            // set mpp to user mode
            mstatus_d.mpp  = riscv_pkg::PRIV_LVL_U;
            // set mpie to 1
            mstatus_d.mpie = 1'b1;
            if (def_pkg::RVH) begin
              // set virtualization mode
              v_mode_d           = mstatus_q.mpv;
              //set mstatus mpv to false
              mstatus_d.mpv = 1'b0;
              if (mstatus_q.mpp != riscv_pkg::PRIV_LVL_M) mstatus_d.mprv = 1'b0;
            end
            // // clear mprv if returning from machine mode to any other mode
            // if ((priv_lvl_d != riscv_pkg::PRIV_LVL_M) && (priv_lvl_d != priv_lvl_q)) begin
            //     mstatus_d.mprv = 1'b0;
            // end
        end 
        else if (sret) begin
          if (!((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && (mstatus_q.tsr == 1'b1)) && ((def_pkg::RVH && !v_mode_q) || !def_pkg::RVH)) begin
            // return from exception, IF doesn't care from where we are returning
            eret_o         = 1'b1;
            // return the previous supervisor interrupt enable flag
            mstatus_d.sie  = mstatus_q.spie;
            // restore the previous privilege level
            priv_lvl_d     = riscv_pkg::priv_lvl_t'({1'b0, mstatus_q.spp});
            // set spp to user mode
            mstatus_d.spp  = 1'b0;
            // set spie to 1
            mstatus_d.spie = 1'b1;
            if (def_pkg::RVH) begin
              // set virtualization mode
              v_mode_d       = hstatus_q.spv;
              //set hstatus spv to false
              hstatus_d.spv  = 1'b0;
              mstatus_d.mprv = 1'b0;
            end
          end else if (def_pkg::RVH) begin
            if (!((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && (hstatus_q.vtsr == 1'b1)) && v_mode_q) begin
              // return from exception, IF doesn't care from where we are returning
              eret_o          = 1'b1;
              // return the previous supervisor interrupt enable flag
              vsstatus_d.sie  = vsstatus_q.spie;
              // restore the previous privilege level
              priv_lvl_d      = riscv_pkg::priv_lvl_t'({1'b0, vsstatus_q.spp});
              // set spp to user mode
              vsstatus_d.spp  = 1'b0;
              // set spie to 1
              vsstatus_d.spie = 1'b1;
            end
          end
        end

        // ------------------------------
        // MPRV - Modify Privilege Level
        // ------------------------------
        // Set the address translation at which the load and stores should occur
        // we can use the previous values since changing the address translation will always involve a pipeline flush
        if(def_pkg::RVH) begin
          if (mprv && (mstatus_q.mpv == 1'b0) && (satp_q.mode == def_pkg::MODE_SV39) && (mstatus_q.mpp != riscv_pkg::PRIV_LVL_M) && ((~debug_mode_en_q) || dcsr_q.mprven)) begin
              en_ld_st_translation_d = 1'b1;
          end else if(mprv && (mstatus_q.mpv == 1'b1)) begin
            if (vsatp_q.mode == def_pkg::MODE_SV39) begin
              en_ld_st_translation_d = 1'b1;
            end else begin
              en_ld_st_translation_d = 1'b0;
            end
          end else begin // otherwise we go with the regular settings
              en_ld_st_translation_d = en_translation_o;
          end

          if (mprv && (mstatus_q.mpv == 1'b1)) begin
            if (hgatp_q.mode == def_pkg::MODE_SV39) begin
              en_ld_st_g_translation_d = 1'b1;
            end else begin
              en_ld_st_g_translation_d = 1'b0;
            end
          end else begin
            en_ld_st_g_translation_d = en_g_translation_o;
          end
              
          if (csr_hs_ld_st_inst_i) ld_st_priv_lvl_o = riscv_pkg::priv_lvl_t'({1'b0, hstatus_q.spvp});
          else ld_st_priv_lvl_o = (mprv &&  ((~debug_mode_en_q) || dcsr_q.mprven)) ? mstatus_q.mpp : priv_lvl_o;
          ld_st_v_mode_o = ((mprv ? mstatus_q.mpv : v_mode_q) || (csr_hs_ld_st_inst_i));
          en_ld_st_translation_o = (en_ld_st_translation_q && !csr_hs_ld_st_inst_i) || ((vsatp_q.mode == def_pkg::MODE_SV39) && csr_hs_ld_st_inst_i);
          en_ld_st_g_translation_o = (en_ld_st_g_translation_q && !csr_hs_ld_st_inst_i) || (csr_hs_ld_st_inst_i && (hgatp_q.mode == def_pkg::MODE_SV39) && csr_hs_ld_st_inst_i);
        end else begin
          if (mprv && (satp_q.mode == def_pkg::MODE_SV39) && (mstatus_q.mpp != riscv_pkg::PRIV_LVL_M) && ((~debug_mode_en_q) || dcsr_q.mprven)) begin
              en_ld_st_translation_d = 1'b1;
          end else begin // otherwise we go with the regular settings
              en_ld_st_translation_d = en_translation_o;
              //ld_st_priv_lvl_o = (mprv) ? mstatus_q.mpp : priv_lvl_o;
              //en_ld_st_translation_o = en_ld_st_translation_q;
          end
    
          ld_st_priv_lvl_o = (mprv &&  ((~debug_mode_en_q) || dcsr_q.mprven)) ? mstatus_q.mpp : priv_lvl_o;
          en_ld_st_translation_o = en_ld_st_translation_q;
          ld_st_v_mode_o = 1'b0;
          en_ld_st_g_translation_o = 1'b0;
        end

        debug_mode_en_d = debug_mode_en_q;
        debug_ebreak_d = 1'b0;

        if (insn_break & (~debug_mode_en_q)) begin
            if (((priv_lvl_q == riscv_pkg::PRIV_LVL_M) && (dcsr_q.ebreakm)) || 
                ((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && (dcsr_q.ebreaks)) ||
                ((priv_lvl_q == riscv_pkg::PRIV_LVL_U) && (dcsr_q.ebreaku))) begin
                dcsr_d.cause = 3'h1;
                dcsr_d.prv = priv_lvl_q;
                dcsr_d.v   = (!def_pkg::RVH) ? 1'b0 : v_mode_q;
                dpc_d = pc_i; // pc of the ebreak_instruction
                debug_mode_en_d = 1'b1;
                priv_lvl_d = riscv_pkg::PRIV_LVL_M;
                debug_ebreak_d = 1'b1;
            end
        end else if (debug_halt_ack_i) begin
            dcsr_d.cause = 3'h3;
            dcsr_d.prv = priv_lvl_q;
            dcsr_d.v   = (!def_pkg::RVH) ? 1'b0 : v_mode_q;
            dpc_d = pc_i; // pc of the next instruction to be executed
            debug_mode_en_d = 1'b1;
            priv_lvl_d = riscv_pkg::PRIV_LVL_M;
        end else if ((~debug_mode_en_q) & dcsr_q.step & ((|retire_i)| ex_i)) begin
            if ( ex_i | csr_xcpt) begin
                dpc_d = trap_vector_base;
                dcsr_d.prv = priv_lvl_d;
                dcsr_d.v   = (!def_pkg::RVH) ? 1'b0 : v_mode_d;
            end else if( sret ) begin
                dpc_d = sepc_q;
                dcsr_d.prv = priv_lvl_d;
                dcsr_d.v   = (!def_pkg::RVH) ? 1'b0 : v_mode_d;
            end else if( mret) begin
                dpc_d = mepc_q;
                dcsr_d.prv = priv_lvl_d;
                dcsr_d.v   = (!def_pkg::RVH) ? 1'b0 : v_mode_d;
            end else begin
                dcsr_d.prv = priv_lvl_q;
                dcsr_d.v   = (!def_pkg::RVH) ? 1'b0 : v_mode_q;
                dpc_d = pc_i; // pc of the next instruction to be executed
            end
            dcsr_d.cause = 3'h4;
            debug_mode_en_d = 1'b1;
            priv_lvl_d = riscv_pkg::PRIV_LVL_M;
            debug_ebreak_d = 1'b1;
        end else if (debug_resume_ack_i & debug_mode_en_q) begin
            eret_o = 1'b1;
            priv_lvl_d = dcsr_q.prv;
            if(def_pkg::RVH) v_mode_d = dcsr_q.v;
            if (dcsr_q.prv != riscv_pkg::PRIV_LVL_M) begin
                mstatus_d.mprv = 1'b0;
            end
            debug_mode_en_d = 1'b0;
        end else if (insn_break & debug_mode_en_q) begin // exit program buffer
            debug_ebreak_d = 1'b1;
        end

    end
    
    assign debug_step_o = dcsr_q.step;

    // ---------------------------
    // CSR OP Select Logic
    // ---------------------------
    always_comb begin : csr_op_logic
        flush_sfence = 1'b0;
        flush_hfence_vvma = 1'b0;
        flush_hfence_gvma = 1'b0;
        csr_wdata = w_data_core_i;
        csr_we    = 1'b1;
        csr_read  = 1'b1;
        mret      = 1'b0;
        sret      = 1'b0;

        unique case (rw_cmd_i)
            4'b0001: csr_wdata = w_data_core_i;                // Write and Read
            4'b0010: csr_wdata = w_data_core_i | csr_rdata;    // Set and Read
            4'b0011: csr_wdata = (~w_data_core_i) & csr_rdata; // Clear and Read
            4'b0101: csr_we    = 1'b0;                         // Read only
            4'b1000: csr_read  = 1'b0;                         // Write only
            default: begin
                csr_we   = 1'b0;
                csr_read = 1'b0;
            end
        endcase
        if (insn_sret) begin
            // the return should not have any write or read side-effects
            sret     = 1'b1; // signal a return from supervisor mode
        end else if (insn_mret) begin
            // the return should not have any write or read side-effects
            mret     = 1'b1; // signal a return from machine mode
        end else if (insn_sfence_vm) begin // flush_o can not be changed here, it changes in csr_update process
            flush_sfence = 1'b1;
        end else if (def_pkg::RVH && insn_hfence_vvma) begin // flush_o can not be changed here, it changes in csr_update process
            flush_hfence_vvma = 1'b1;
        end else if (def_pkg::RVH && insn_hfence_gvma) begin // flush_o can not be changed here, it changes in csr_update process
            flush_hfence_gvma = 1'b1;
        end
        // if we are violating our privilges do not update the architectural state
        if (privilege_violation || (def_pkg::RVH && virtual_privilege_violation)) begin
            csr_we = 1'b0;
            csr_read = 1'b0;
        end
    end

    // -----------------
    // Privilege Check
    // -----------------
    always_comb begin : privilege_check
        if(def_pkg::RVH) begin
          automatic logic [1:0] access_priv;
          automatic logic [4:0] sel_cnt_en;
          // transforms S mode accesses into HS mode
          access_priv = ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && !v_mode_q) ? riscv_pkg::PRIV_LVL_HS : priv_lvl_o;
          sel_cnt_en = csr_addr.address[4:0];
          // -----------------
          // Privilege Check
          // -----------------
          privilege_violation = 1'b0;
          virtual_privilege_violation = 1'b0;
          // if we are reading or writing, check for the correct privilege level this has
          // precedence over interrupts
          if (rw_cmd_i inside {4'b0001, 4'b0010, 4'b0011, 4'b0101, 4'b1000}) begin // inside of: rw, set, clear, read, write
            if (access_priv < csr_addr.csr_decode.priv_lvl) begin
              if (v_mode_q && (csr_addr.csr_decode.priv_lvl <= riscv_pkg::PRIV_LVL_HS))
                virtual_privilege_violation = 1'b1;
              else privilege_violation = 1'b1;
            end
            // check access to debug mode only CSRs
            if ((rw_addr_i[11:4] == 8'h7b) && (~debug_mode_en_q)) begin
              privilege_violation = 1'b1;
            end
            // check counter-enabled counter CSR accesses
            // counter address range is C00 to C1F
            if (csr_addr.address inside {[riscv_pkg::CSR_CYCLE:riscv_pkg::CSR_HPM_COUNTER_31]}) begin
              if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                privilege_violation = 1'b0;
              end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                virtual_privilege_violation = v_mode_q & mcounteren_q[sel_cnt_en] & ~hcounteren_q[sel_cnt_en];
                privilege_violation = ~mcounteren_q[sel_cnt_en];
              end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                virtual_privilege_violation = v_mode_q & mcounteren_q[sel_cnt_en] & ~hcounteren_q[sel_cnt_en];
                if (v_mode_q) begin
                  privilege_violation = ~mcounteren_q[sel_cnt_en] & ~scounteren_q[sel_cnt_en] & hcounteren_q[sel_cnt_en];
                end else begin
                  privilege_violation = ~mcounteren_q[sel_cnt_en] & ~scounteren_q[sel_cnt_en];
                end
              end
            end
            // check state-enable CSR accesses
            unique case (csr_addr.address)
                riscv_pkg::CSR_SSTATEEN0: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.se & ~hstateen0_q.se;
                        privilege_violation = ~mstateen0_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen0_q.se;
                    end
                end
                riscv_pkg::CSR_SSTATEEN1: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen1_q.se & ~hstateen1_q.se;
                        privilege_violation = ~mstateen1_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen1_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen1_q.se;
                    end
                end
                riscv_pkg::CSR_SSTATEEN2: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen2_q.se & ~hstateen2_q.se;
                        privilege_violation = ~mstateen2_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen2_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen2_q.se;
                    end
                end
                riscv_pkg::CSR_SSTATEEN3: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen3_q.se & ~hstateen3_q.se;
                        privilege_violation = ~mstateen3_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen3_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen3_q.se;
                    end
                end
                riscv_pkg::CSR_HSTATEEN0: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.se;
                        privilege_violation = ~mstateen0_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen0_q.se;
                    end
                end
                riscv_pkg::CSR_HSTATEEN1: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen1_q.se;
                        privilege_violation = ~mstateen1_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen1_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen1_q.se;
                    end
                end
                riscv_pkg::CSR_HSTATEEN2: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen2_q.se;
                        privilege_violation = ~mstateen2_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen2_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen2_q.se;
                    end
                end
                riscv_pkg::CSR_HSTATEEN3: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen3_q.se;
                        privilege_violation = ~mstateen3_q.se;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen3_q.se;
                        if(v_mode_q) privilege_violation = ~mstateen3_q.se;
                    end
                end
                riscv_pkg::CSR_SENVCFG: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.envcfg & ~hstateen0_q.envcfg;
                        privilege_violation = ~mstateen0_q.envcfg;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.envcfg;
                        if(v_mode_q) privilege_violation = ~mstateen0_q.envcfg;
                    end
                end
                riscv_pkg::CSR_HENVCFG: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.envcfg;
                        privilege_violation = ~mstateen0_q.envcfg;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_U) begin
                        virtual_privilege_violation = v_mode_q & mstateen0_q.envcfg;
                        if(v_mode_q) privilege_violation = ~mstateen0_q.envcfg;
                    end
                end
                default:;
            endcase
          end
          //checks the level of the system instruction or sfence with tvm = 1 or sret and tsr = 1
          if ((system_insn && !priv_sufficient && !v_mode_q) || 
              ((insn_sfence_vm && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) && (mstatus_q.tvm == 1'b1)) || 
              ((insn_hfence_gvma && (!v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) && (mstatus_q.tvm == 1'b1)) || 
              ((insn_sret && ((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && !v_mode_q)) && (mstatus_q.tsr == 1'b1))) begin
              privilege_violation = 1'b1;
          end else if ((system_insn && !priv_sufficient && v_mode_q) || 
                       ((insn_sfence_vm && (v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S))) && (hstatus_q.vtvm == 1'b1)) ||
                       ((insn_hfence_gvma || insn_hfence_vvma) && v_mode_q) ||
                       ((insn_sret && ((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && v_mode_q)) && (hstatus_q.vtsr == 1'b1))) begin
              virtual_privilege_violation = 1'b1;
          end
        end else begin
          privilege_violation = 1'b0;
          // if we are reading or writing, check for the correct privilege level this has
          // precedence over interrupts
          if (rw_cmd_i inside {4'b0001, 4'b0010, 4'b0011, 4'b0101, 4'b1000}) begin // inside of: rw, set, clear, read, write
              if ((riscv_pkg::priv_lvl_t'(priv_lvl_o & csr_addr.csr_decode.priv_lvl) != csr_addr.csr_decode.priv_lvl)) begin
                  privilege_violation = 1'b1;
              end
              // check access to debug mode only CSRs 
              if ((rw_addr_i[11:4] == 8'h7b) && (~debug_mode_en_q)) begin
                  privilege_violation = 1'b1;
              end
              if (csr_addr.address inside {[riscv_pkg::CSR_CYCLE:riscv_pkg::CSR_HPM_COUNTER_31]}) begin
                  unique case (priv_lvl_o)
                      riscv_pkg::PRIV_LVL_M: privilege_violation = 1'b0;
                      riscv_pkg::PRIV_LVL_S: privilege_violation = ~mcounteren_q[csr_addr.address[4:0]];
                      riscv_pkg::PRIV_LVL_U: privilege_violation = ~mcounteren_q[csr_addr.address[4:0]] & ~scounteren_q[csr_addr.address[4:0]];
                      default: privilege_violation = 1'b1;
                  endcase
              end
            // check state-enable CSR accesses
            unique case (csr_addr.address)
                riscv_pkg::CSR_SSTATEEN0: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        privilege_violation = ~mstateen0_q.se;
                    end
                end
                riscv_pkg::CSR_SSTATEEN1: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        privilege_violation = ~mstateen1_q.se;
                    end
                end
                riscv_pkg::CSR_SSTATEEN2: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        privilege_violation = ~mstateen2_q.se;
                    end
                end
                riscv_pkg::CSR_SSTATEEN3: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        privilege_violation = ~mstateen3_q.se;
                    end
                end
                riscv_pkg::CSR_SENVCFG: begin
                    if (priv_lvl_o == riscv_pkg::PRIV_LVL_M) begin
                        privilege_violation = 1'b0;
                    end else if (priv_lvl_o == riscv_pkg::PRIV_LVL_S) begin
                        privilege_violation = ~mstateen0_q.envcfg;
                    end
                end
                default:;
            endcase
          end
          //checks the level of the system instruction or sfence with tvm = 1 or sret and tsr = 1
          if ((system_insn && !priv_sufficient) || 
              ((insn_sfence_vm && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) && (mstatus_q.tvm == 1'b1)) || 
              ((insn_sret && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) && (mstatus_q.tsr == 1'b1))) begin
              privilege_violation = 1'b1;
          end
        end
    end

    // -------------------
    // Vector instruccions excecution
    // -------------------
    always_comb begin : vsetvl_ctrl
        vtype_new = rw_addr_i[10:0];

        // new vlmax depending on the vtype config
        if(CORE_TYPE == def_pkg::LKA_CORE) begin
            vlmax = ((VLEN_V << vtype_new[2:0]) >> 3) >> vtype_new[5:3];
        end else begin
            case(vtype_new[2:0])
                3'b101:  vlmax = ((riscv_pkg::VLEN >> 3) >> vtype_new[5:3]) >> 3;
                3'b110:  vlmax = ((riscv_pkg::VLEN >> 3) >> vtype_new[5:3]) >> 2;
                3'b111:  vlmax = ((riscv_pkg::VLEN >> 3) >> vtype_new[5:3]) >> 1;
                default: vlmax = ((riscv_pkg::VLEN >> 3) >> vtype_new[5:3]);
            endcase
        end

        update_access_exception_vs = 1'b0;
        if (vsetvl_insn) begin

            if ((mstatus_q.vs == riscv_pkg::Off) || (def_pkg::RVH && v_mode_q && (vsstatus_q.vs == riscv_pkg::Off))) begin
                update_access_exception_vs = 1'b1;
                // default, keeps the old value
                vl_d = vl_q;
                vtype_d = vtype_q;
                vnarrow_wide_en_d = vnarrow_wide_en_q;

            end else begin
                // vl assignation depending on the AVL respect VLMAX
                if (rw_cmd_i[2:0] == 3'b111) begin //vsetvl with x0
                    if (w_data_core_i == 64'b1) begin  
                        vl_d = (CORE_TYPE == def_pkg::LKA_CORE) ? 
                            vlmax : vl_q; //TODO: Why is this swapped in lka case? idk, but its how it worked until now.
                    end else begin
                        vl_d = (CORE_TYPE == def_pkg::LKA_CORE) ? 
                            vl_q : vlmax;
                    end
                end else if (vlmax >= w_data_core_i) begin
                    vl_d = w_data_core_i;
                end else if ((vlmax<<1) >= w_data_core_i) begin
                    vl_d = (w_data_core_i>>1) + w_data_core_i[0];
                end else begin
                    vl_d = vlmax;
                end

                // vtype assignation
                if(CORE_TYPE == def_pkg::LKA_CORE) begin

                    if ((vtype_new[10:8] != 6'b0)) begin // unsupported SEW,LMUL configuration (rvv1.0 page 11)
                        vtype_d = {1'b1,63'b0};
                    end else begin
                        vtype_d = {53'b0,vtype_new};
                    end
                end else begin
                // vtype assignation
                    if ((vtype_new[10:8] != 3'b0) || (vtype_new[5] == 1'b1) || 
                        ((vtype_new[2:0] > 3'b0) && ((vtype_new[2:0] < 3'b101) || (vtype_new[1:0] <= vtype_new[4:3])))) begin // unsupported SEW/LMUL configuration (rvv1.0 page 11)
                        vtype_d = {1'b1,63'b0};
                        vl_d = 'h0;
                    end else begin
                        vtype_d = {53'b0,vtype_new};
                    end
                end
            
                if (vtype_new[2] || (vl_d <= (vlmax >> 1))) begin
                    vnarrow_wide_en_d = 1'b1;
                end else begin
                    vnarrow_wide_en_d = 1'b0;
                end 
            end              
        end else if (rw_cmd_i == 4'b1001) begin //VLEFF
            vl_d = w_data_core_i;
            vtype_d = vtype_q;
            vnarrow_wide_en_d = vnarrow_wide_en_q;
        end else begin
            // default, keeps the old value
            vl_d = vl_q;
            vtype_d = vtype_q;
            vnarrow_wide_en_d = vnarrow_wide_en_q;
        end
    end

    assign vpu_csr_o = {vtype_q[63], vtype_q[7:0], fcsr_q.frm, vcsr_q.vxrm, vl_q[14:0], vnarrow_wide_en_q, 13'b0};


    // ----------------------
    // CSR Exception Control
    // ----------------------
    assign csr_xcpt_o = csr_xcpt;
    assign csr_xcpt_cause_o = csr_xcpt_cause;
    assign csr_tval_o = ex_tval;
    assign csr_tval2_o = ex_tval2;

    always_comb begin : exception_ctrl
        csr_xcpt_cause = 64'b0;
        csr_xcpt = 1'b0;
        // ----------------------------------
        // Illegal Access (decode exception)
        // ----------------------------------
        // we got an exception in one of the processes above
        // throw an illegal instruction exception
        if (update_access_exception || update_access_exception_vs || read_access_exception) begin
            csr_xcpt_cause = riscv_pkg::ILLEGAL_INSTR;
            // we don't set the tval field as this will be set by the commit stage
            // this spares the extra wiring from commit to CSR and back to commit
            csr_xcpt = 1'b1;
        end else if (privilege_violation) begin
          csr_xcpt_cause = riscv_pkg::ILLEGAL_INSTR;
          csr_xcpt = 1'b1;
        end else if (insn_call) begin
          if (def_pkg::RVH && v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) csr_xcpt_cause = riscv_pkg::VIRTUALSUPERVISOR_ECALL;
          else csr_xcpt_cause = riscv_pkg::USER_ECALL + priv_lvl_q;
            csr_xcpt = 1'b1;
        end else if (insn_break & (~debug_mode_en_q)) begin
            if (((priv_lvl_o == riscv_pkg::PRIV_LVL_M) && (~dcsr_q.ebreakm)) || 
                ((priv_lvl_o == riscv_pkg::PRIV_LVL_S) && (~dcsr_q.ebreaks)) ||
                ((priv_lvl_o == riscv_pkg::PRIV_LVL_U) && (~dcsr_q.ebreaku))) begin
                csr_xcpt_cause = riscv_pkg::BREAKPOINT;
                csr_xcpt = 1'b1;
            end
        end else if (insn_wfi && mstatus_q.tw) begin
            csr_xcpt_cause = riscv_pkg::ILLEGAL_INSTR;
            csr_xcpt = 1'b1;
        end else if (def_pkg::RVH && insn_wfi && hstatus_q.vtw && v_mode_q && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) begin
          csr_xcpt_cause = riscv_pkg::VIRTUAL_INSTRUCTION;
          csr_xcpt = 1'b1;
      end
        
        if (def_pkg::RVH && (virtual_update_access_exception || update_access_exception_vs || virtual_read_access_exception || virtual_privilege_violation)) begin
          csr_xcpt_cause = riscv_pkg::VIRTUAL_INSTRUCTION;
          csr_xcpt = 1'b1;
        end
    end

    // -------------------
    // Wait for Interrupt
    // -------------------
    always_comb begin : wfi_ctrl
        // wait for interrupt register
        wfi_d = wfi_q;
        // if there is any interrupt pending and it is individually enabled un-stall the core
        if ((((|mip_q) || irq_q[0] || irq_q[1]) && interrupt_cause[63]) || debug_halt_req_i) begin
            wfi_d = 1'b0;
        // or alternatively if there is no exception pending and we are not in debug mode wait here
        // for the interrupt
        end else if (insn_wfi && !ex_i && !csr_xcpt) begin
            wfi_d = 1'b1;
        end
    end

    // -------------------
    // PCR contol logic
    // -------------------

`ifdef CONF_SARGANTANA_ENABLE_PCR
    always_comb begin : pcr_ctrl
        //whait until a response from the pcs
        cpu_ren = 1'b0;
        pcr_wait_resp_d = pcr_wait_resp_q;

        // determine if the cpu requests a read of a csr
        if (rw_cmd_i inside {4'b0001, 4'b0010, 4'b0011, 4'b0101}) begin //rw, set, clear, read
            cpu_ren = 1'b1;
        end

        // requests to pcr are valid when the pcr is ready, there aren't any exceptions and the 
        pcr_req_valid = cpu_ren & pcr_addr_valid & priv_sufficient & ~csr_xcpt & ~pcr_wait_resp_d;
        

        if (pcr_req_valid && (!pcr_resp_valid_i || (pcr_resp_core_id_i != core_id_i))) pcr_wait_resp_d = 1'b1;
        else if (pcr_resp_valid_i && (pcr_resp_core_id_i == core_id_i)) pcr_wait_resp_d = 1'b0;

        //pcr requests outputs connections
        pcr_req_addr_o = csr_addr;
        pcr_req_we_o = rw_cmd_i[2:0];
        pcr_req_core_id_o = core_id_i;
        pcr_req_valid_o = pcr_req_valid;
    end
`endif // CONF_SARGANTANA_ENABLE_PCR

    // -------------------
    // CPU actions induced by the csr
    // -------------------
`ifdef CONF_SARGANTANA_ENABLE_PCR
    assign csr_replay_o = pcr_req_valid & !pcr_req_ready_i; // pcr write but not ready
    assign csr_stall_o = wfi_q || // or waiting pcr response 
                  (pcr_wait_resp_d && (!pcr_resp_valid_i || (pcr_resp_core_id_i != core_id_i)));
`else
    assign csr_replay_o = 1'b0;
    assign csr_stall_o = wfi_q;
`endif // CONF_SARGANTANA_ENABLE_PCR

`ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
    assign dyn_fpga_mem_latency_o = dyn_fpga_mem_latency_q;
`endif // CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY

    // output assignments dependent on privilege mode
    always_comb begin : priv_output
        // vectorized trap addres
        trap_vector_base[63:8] = mtvec_q[63:8];
        trap_vector_base[7:2] = ((mtvec_q[1:0] == 2'b0) || csr_xcpt || !ex_cause_i[63]) ? mtvec_q[7:2] : trunc_sum_6bits(mtvec_q[7:2] + ex_cause_i[5:0]);
        trap_vector_base[1:0] = 2'b0;
        // output user mode stvec
        if (trap_to_priv_lvl == riscv_pkg::PRIV_LVL_S) begin
            // vectorized trap addres
            trap_vector_base[63:8] = (def_pkg::RVH && trap_to_v_mode) ? vstvec_q[63:8] : stvec_q[63:8];
            trap_vector_base[7:2] = (def_pkg::RVH && trap_to_v_mode) ? (((vstvec_q[1:0] == 2'b0) || csr_xcpt || !ex_cause_i[63]) ? vstvec_q[7:2] : trunc_sum_6bits(vstvec_q[7:2] + ex_cause_i[5:0]))
                                                                     : (((stvec_q[1:0] == 2'b0) || csr_xcpt || !ex_cause_i[63]) ? stvec_q[7:2] : trunc_sum_6bits(stvec_q[7:2] + ex_cause_i[5:0]));
            trap_vector_base[1:0] = 2'b0;
        end

        evec_o = mepc_q; // we are returning from machine mode, so take the mepc register
        if ((ex_i || csr_xcpt_o) & ~debug_mode_en_q) begin // an exception is detected in the core and it is send the trap address
            if (dcsr_q.step) begin
                evec_o = PROGRAM_BUFFER_ADDR;
            end else begin
                evec_o = trap_vector_base;
            end
        end else if (sret) begin // we are returning from supervisor mode, so take the sepc register
            if (dcsr_q.step) begin
                evec_o = PROGRAM_BUFFER_ADDR;
            end else begin
                evec_o = (def_pkg::RVH && v_mode_q) ? vsepc_q : sepc_q;
            end
        end else if (mret) begin // we are returning from machine mode, so take the sepc register
            if (dcsr_q.step) begin
                evec_o = PROGRAM_BUFFER_ADDR;
            end else begin
                evec_o = mepc_q;
            end
        end else if (debug_halt_ack_i) begin // entering debug mode, jump to debug program buffer
            evec_o = PROGRAM_BUFFER_ADDR; 
        end else if (debug_resume_ack_i) begin // returning from debug mode, take dpc register
            evec_o = dpc_q;
        end else if (debug_mode_en_q) begin // if inside debug mode, jump to debug program buffer
            evec_o = PROGRAM_BUFFER_ADDR; 
        end else if (debug_ebreak_d) begin // if inside debug mode, jump to debug program buffer
            evec_o = PROGRAM_BUFFER_ADDR; 
        end
    end

    // -------------------
    // Output Assignments
    // -------------------
    always_comb begin
        // When the SEIP bit is read with a CSRRW, CSRRS, or CSRRC instruction, the value
        // returned in the rd destination register contains the logical-OR of the software-writable
        // bit and the interrupt signal from the interrupt controller.
	if (vsetvl_insn) begin
        	r_data_core_o = vl_d;
	end else begin
		r_data_core_o = csr_rdata;
        	unique case (conv_csr_addr.address)
        	    riscv_pkg::CSR_MIP: r_data_core_o = csr_rdata | ({63'b0, irq_q[1]} << riscv_pkg::IRQ_S_EXT);
        	    // in supervisor mode we also need to check whether we delegated this bit
        	    riscv_pkg::CSR_SIP: begin
        	        r_data_core_o = csr_rdata
        	                    | ({63'b0, (irq_q[1] & mideleg_q[riscv_pkg::IRQ_S_EXT])} << riscv_pkg::IRQ_S_EXT);
        	    end
                default:;
                endcase
	end
    end
    // fcrs assigments
    assign mstatus_o  = mstatus_q;
    assign vsstatus_o = vsstatus_q;
    // in debug mode we execute with privilege level M
    assign priv_lvl_o       = (debug_resume_ack_i) ? dcsr_q.prv : priv_lvl_q;
    assign v_mode_o = def_pkg::RVH ? v_mode_q : 1'b0;
    // FPU outputs

    assign fcsr_rm_o        = fcsr_q.frm;
    assign fcsr_fs_o        = ((v_mode_q && (vsstatus_q.fs == 2'b00)) || (mstatus_q.fs == 2'b00)) ? 2'b00 : 2'b01;

    // VPU outputs
    assign vcsr_vs_o        = ((v_mode_q && (vsstatus_q.vs == 2'b00)) || (mstatus_q.vs == 2'b00)) ? 2'b00 : 2'b01;

    // CMO configuration outputs
    assign csr_m_cmo_cfg_o  = menvcfg_q[7:4];
    assign csr_s_cmo_cfg_o  = senvcfg_q[7:4];
    assign csr_h_cmo_cfg_o  = henvcfg_q[7:4];

    // MMU outputs 
    assign satp_ppn_o       = satp_q.ppn[PPN_WIDTH-1:0];
    assign vsatp_ppn_o      = def_pkg::RVH ? vsatp_q.ppn[PPN_WIDTH-1:0] : '0;
    assign hgatp_ppn_o      = def_pkg::RVH ? hgatp_q.ppn[PPN_WIDTH-1:0] : '0;

    // we support bare memory addressing and SV39
    if (def_pkg::RVH) begin
      assign en_translation_o = ((((satp_q.mode == def_pkg::MODE_SV39) && !(v_mode_q)) || ((vsatp_q.mode == def_pkg::MODE_SV39) && v_mode_q)) &&
                                (priv_lvl_o != riscv_pkg::PRIV_LVL_M))
                                ? 1'b1
                                : 1'b0;
      assign en_g_translation_o = ((hgatp_q.mode == def_pkg::MODE_SV39) &&
                                (priv_lvl_o != riscv_pkg::PRIV_LVL_M) && v_mode_q)
                                ? 1'b1
                                : 1'b0;
      assign csr_hu_o = hstatus_q.hu;
    end else begin
      assign en_translation_o = ((satp_q.mode == def_pkg::MODE_SV39) && (priv_lvl_o != riscv_pkg::PRIV_LVL_M))
                              ? 1'b1
                              : 1'b0;
      assign en_g_translation_o = 1'b0;
      assign csr_hu_o = 1'b0;
    end

    // mprv assignation
    assign mprv             = mstatus_q.mprv;

    // timer output assign
    assign reg_time_d = time_i;
    assign debug_ebreak_o = debug_ebreak_q;


    // sequential process
    always_ff @(posedge clk_i, negedge rstn_i) begin
        if (!rstn_i) begin
            priv_lvl_q             <= riscv_pkg::PRIV_LVL_M;
            // floating-point registers
            fcsr_q                 <= 64'b0;
            if(def_pkg::RVH) begin
              v_mode_q               <= '0;
              mtval2_q               <= 64'b0;
              mtinst_q               <= 64'b0;
              // hypervisor mode registers
              hstatus_q              <= 64'b0;
              hedeleg_q              <= 64'b0;
              hideleg_q              <= 64'b0;
              henvcfg_q              <= 64'b0;
              hcounteren_q           <= 32'b0;
              htval_q                <= 64'b0;
              hgatp_q                <= 64'b0;
              htinst_q               <= 64'b0;
              htimedelta_q           <= 64'b0;
              hstateen0_q            <= 64'b0;
              hstateen1_q            <= 64'b0;
              hstateen2_q            <= 64'b0;
              hstateen3_q            <= 64'b0;
              // virtual supervisor mode registers
              vsstatus_q             <= 64'b0;
              vstvec_q               <= 64'b0;
              vsscratch_q            <= 64'b0;
              vsepc_q                <= 64'b0;
              vscause_q              <= 64'b0;
              vstval_q               <= 64'b0;
              vsatp_q                <= 64'b0;
              en_ld_st_g_translation_q <= 1'b0;
            end
            // machine mode registers
            mstatus_q              <= 64'b0; // mstatus.VS set to OFF on reset
            // set to boot address + direct mode + 4 byte offset which is the initial trap
            mtvec_rst_load_q       <= 1'b1;
            mtvec_q                <= 64'b0;
            medeleg_q              <= 64'b0;
            mideleg_q              <= 64'b0;
            mip_q                  <= 64'b0;
            mie_q                  <= 64'b0;
            mepc_q                 <= 64'b0;
            mcause_q               <= 64'b0;
            mcounteren_q           <= 32'b0;
            mcountinhibit_q        <= 32'b0;
            mcyclecfg_q            <= 64'b0;
            minstretcfg_q          <= 64'b0;
            mscratch_q             <= 64'b0;
            mtval_q                <= 64'b0;
            menvcfg_q              <= 64'b0;
            mstateen0_q            <= 64'b0;
            mstateen1_q            <= 64'b0;
            mstateen2_q            <= 64'b0;
            mstateen3_q            <= 64'b0;
            // supervisor mode registers
            sepc_q                 <= 64'b0;
            scause_q               <= 64'b0;
            stvec_q                <= 64'b0;
            scounteren_q           <= 32'b0;
            senvcfg_q              <= 64'b0;
            sscratch_q             <= 64'b0;
            stval_q                <= 64'b0;
            satp_q                 <= 64'b0;
            sstateen0_q            <= 32'b0;
            sstateen1_q            <= 32'b0;
            sstateen2_q            <= 32'b0;
            sstateen3_q            <= 32'b0;
            // timer and counters
            cycle_q                <= 64'b0;
            instret_q              <= 64'b0;
            scountovf_q            <= 32'b0;
            // aux registers
            en_ld_st_translation_q <= 1'b0;
            // wait for interrupt
            wfi_q                  <= 1'b0;
            // register external interrupt for timing
            irq_q                  <= 2'b0;

            `ifdef CONF_SARGANTANA_ENABLE_PCR
                //PCR assigments
                pcr_wait_resp_q <= 1'b0;
            `endif // CONF_SARGANTANA_ENABLE_PCR

            `ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
                dyn_fpga_mem_latency_q <= '0;
            `endif // CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY

            reg_time_q <= 64'b0;

            //Interrupt assigments
            interrupt_q <= 1'b0;
            interrupt_cause_q <= 64'b0;
            // Vector extension
            vl_q              <= 64'b0;
            vtype_q           <= {1'b1, 63'b0};
            vnarrow_wide_en_q <= 1'b0;
            vcsr_q            <= 'h0;
            // Debug mode
            dcsr_q <= 32'h40000003;
            dpc_q <= 64'b0;
            dscratch0_q <= 64'b0;
            dscratch1_q <= 64'b0;
            debug_mode_en_q <= 1'b0;
            debug_ebreak_q <= 1'b0;
        end else begin
            priv_lvl_q             <= priv_lvl_d;
            // floating-point registers
            fcsr_q                 <= fcsr_d;
            if(def_pkg::RVH) begin
              v_mode_q               <= v_mode_d;
              mtval2_q               <= mtval2_d;
              mtinst_q               <= mtinst_d;
              // hypervisor mode registers
              hstatus_q              <= hstatus_d;
              hedeleg_q              <= hedeleg_d;
              hideleg_q              <= hideleg_d;
              henvcfg_q              <= henvcfg_d;
              hcounteren_q           <= hcounteren_d;
              htval_q                <= htval_d;
              hgatp_q                <= hgatp_d;
              htinst_q               <= htinst_d;
              htimedelta_q           <= htimedelta_d;
              hstateen0_q            <= hstateen0_d;
              hstateen1_q            <= hstateen1_d;
              hstateen2_q            <= hstateen2_d;
              hstateen3_q            <= hstateen3_d;
              // virtual supervisor mode registers
              vsstatus_q             <= vsstatus_d;
              vstvec_q               <= vstvec_d;
              vsscratch_q            <= vsscratch_d;
              vscause_q              <= vscause_d;
              vstval_q               <= vstval_d;
              vsatp_q                <= vsatp_d;
              vsepc_q                <= vsepc_d;
              en_ld_st_g_translation_q <= en_ld_st_g_translation_d;
            end
            // machine mode registers
            mstatus_q              <= mstatus_d;
            mtvec_rst_load_q       <= 1'b0;
            mtvec_q                <= mtvec_d;
            medeleg_q              <= medeleg_d;
            mideleg_q              <= mideleg_d;
            mip_q                  <= mip_d;
            mie_q                  <= mie_d;
            mepc_q                 <= mepc_d;
            mcause_q               <= mcause_d;
            mcounteren_q           <= mcounteren_d;
            mcountinhibit_q        <= mcountinhibit_d;
            mcyclecfg_q            <= mcyclecfg_d;
            minstretcfg_q          <= minstretcfg_d;
            mscratch_q             <= mscratch_d;
            mtval_q                <= mtval_d;
            menvcfg_q              <= menvcfg_d;
            mstateen0_q            <= mstateen0_d;
            mstateen1_q            <= mstateen1_d;
            mstateen2_q            <= mstateen2_d;
            mstateen3_q            <= mstateen3_d;
            // supervisor mode registers
            sepc_q                 <= sepc_d;
            scause_q               <= scause_d;
            stvec_q                <= stvec_d;
            scounteren_q           <= scounteren_d;
            senvcfg_q              <= senvcfg_d;
            sscratch_q             <= sscratch_d;
            stval_q                <= stval_d;
            satp_q                 <= satp_d;
            sstateen0_q            <= sstateen0_d;
            sstateen1_q            <= sstateen1_d;
            sstateen2_q            <= sstateen2_d;
            sstateen3_q            <= sstateen3_d;
            // timer and counters
            cycle_q                <= cycle_d;
            instret_q              <= instret_d;
            scountovf_q            <= scountovf_d;
            // aux registers
            en_ld_st_translation_q <= en_ld_st_translation_d;
            // wait for interrupt
            wfi_q                  <= wfi_d;
            // register external interrupt for timing
            irq_q                  <= irq_i;

            `ifdef CONF_SARGANTANA_ENABLE_PCR
                // PCR assigments
                pcr_wait_resp_q <= pcr_wait_resp_d;
            `endif // CONF_SARGANTANA_ENABLE_PCR

            `ifdef CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY
                dyn_fpga_mem_latency_q <= dyn_fpga_mem_latency_d;
            `endif // CONF_SARGANTANA_ENABLE_DYN_FPGA_MEM_LATENCY

            reg_time_q <= reg_time_d; 

            //Interrupt assigments
            interrupt_q <= interrupt_d;
            interrupt_cause_q <= interrupt_cause_d;
            // Vector extension
            vl_q                   <= vl_d;
            vtype_q                <= vtype_d;
            vnarrow_wide_en_q      <= vnarrow_wide_en_d;
            vcsr_q                 <= vcsr_d;
            // Debug mode
            dcsr_q                 <= dcsr_d;
            dpc_q                  <= dpc_d;
            dscratch0_q            <= dscratch0_d;
            dscratch1_q            <= dscratch1_d;
            debug_mode_en_q        <= debug_mode_en_d;
            debug_ebreak_q <= debug_ebreak_d;

        end
    end

    `ifdef SIM_COMMIT_LOG
    `ifdef SIM_COMMIT_LOG_DPI
        import "DPI-C" function void csr_change (input longint unsigned addr, input longint unsigned value);

        // Very important!!! Must be negedge to execute it before torture_dump when an instruction commits in datapath!
        `ifdef LAGARTO_KA
        logic csr_we_q1,csr_we_q2,csr_we_q3;
        logic [1:0] retire_q1,fcsr_flags_valid_q1,fcsr_flags_valid_q2,fcsr_flags_valid_q3;
        riscv_pkg::csr_t csr_addr_q1, csr_addr_q2 ,csr_addr_q3;
        riscv_pkg::status_rv64_t  mstatus_q1,  mstatus_q2,mstatus_q3;
        logic [4:0] fcsr_flags_bits_q1,fcsr_flags_bits_q2,fcsr_flags_bits_q3,fflags_q1,fflags_q2,fflags_q3;

        mvp_dpreg  #(1)       _fcsr_flags_valid_q1_  (clk_i, rstn_i, fcsr_flags_valid_i,    fcsr_flags_valid_q1);
        mvp_dpreg  #(1)       _fcsr_flags_valid_q2_  (clk_i, rstn_i, fcsr_flags_valid_q1,   fcsr_flags_valid_q2);
        mvp_dpreg  #(1)       _fcsr_flags_valid_q3_  (clk_i, rstn_i, fcsr_flags_valid_q2,   fcsr_flags_valid_q3);

        mvp_dpreg  #(5)       _fcsr_flags_bits_q1_  (clk_i, rstn_i, fcsr_flags_bits_i,    fcsr_flags_bits_q1);
        mvp_dpreg  #(5)       _fcsr_flags_bits_q2_  (clk_i, rstn_i, fcsr_flags_bits_q1,   fcsr_flags_bits_q2);
        mvp_dpreg  #(5)       _fcsr_flags_bits_q3_  (clk_i, rstn_i, fcsr_flags_bits_q2,   fcsr_flags_bits_q3);

        mvp_dpreg  #(5)       _fcsr_flags_q1_  (clk_i, rstn_i, fcsr_d.fflags,        fflags_q1);
        mvp_dpreg  #(5)       _fcsr_flags_q2_  (clk_i, rstn_i, fflags_q1,            fflags_q2);
        mvp_dpreg  #(5)       _fcsr_flags_q3_  (clk_i, rstn_i, fflags_q2,            fflags_q3);

        mvp_dpreg  #(1)       _csr_we_q1_  (clk_i, rstn_i, csr_we,    csr_we_q1);
        mvp_dpreg  #(1)       _csr_we_q2_  (clk_i, rstn_i, csr_we_q1, csr_we_q2);
        mvp_dpreg  #(1)       _csr_we_q3_  (clk_i, rstn_i, csr_we_q2, csr_we_q3);
        
        mvp_dpreg  #(24)       _csr_addr_q1_  (clk_i, rstn_i, csr_addr,    csr_addr_q1);
        mvp_dpreg  #(24)       _csr_addr_q2_  (clk_i, rstn_i, csr_addr_q1, csr_addr_q2);
        mvp_dpreg  #(24)       _csr_addr_q3_  (clk_i, rstn_i, csr_addr_q2, csr_addr_q3);

        mvp_dpreg  #(64)       _csr_mstatus_q1_  (clk_i, rstn_i, mstatus_q,  mstatus_q1);
        mvp_dpreg  #(64)       _csr_mstatus_q2_  (clk_i, rstn_i, mstatus_q1, mstatus_q2);
        mvp_dpreg  #(64)       _csr_mstatus_q3_  (clk_i, rstn_i, mstatus_q2, mstatus_q3);

        mvp_dpreg  #(2)       _csr_retire_q1_  (clk_i, rstn_i, retire_i, retire_q1);
        always_ff @(negedge clk_i) begin
            automatic logic [63:0] mstatus_fix, mstatus_clear ,mstatus_set;
            mstatus_clear = riscv_pkg::MSTATUS_UXL | riscv_pkg::MSTATUS_SXL | riscv_pkg::MSTATUS64_SD;
            mstatus_set =   ((mstatus_d.xs == riscv_pkg::Dirty) | (mstatus_d.fs == riscv_pkg::Dirty))<<63 |
                            riscv_pkg::XLEN_64 << 32|
                            riscv_pkg::XLEN_64 << 34;
            mstatus_fix = (mstatus_d & ~mstatus_clear) | mstatus_set;

            if (rstn_i & (|retire_q1)) begin
                // CSRs which can change due to side-effects etc

                // For some reason mstatus is updated in multiple cycles, but at commit we need the value that will be set later
                // This might break in some random tests.....
                if (mstatus_q3 != mstatus_fix) csr_change(riscv_pkg::CSR_MSTATUS, mstatus_fix);

                if (fcsr_flags_valid_q1 && fcsr_flags_bits_q1) csr_change(riscv_pkg::CSR_FFLAGS, fflags_q1);

                // CSRs which only change when written to
                if (csr_we_q3) begin
                    case(csr_addr_q3)
                        riscv_pkg::CSR_MSTATUS, riscv_pkg::CSR_SSTATUS:
                            ; // Covered by previous mstatus check
                        riscv_pkg::CSR_MTVEC: csr_change(csr_addr_q3, mtvec_d);
                        riscv_pkg::CSR_MEPC: csr_change(csr_addr_q3, mepc_d);
                        riscv_pkg::CSR_MCAUSE: csr_change(csr_addr_q3, mcause_d);
                        riscv_pkg::CSR_MSCRATCH: csr_change(csr_addr_q3, mscratch_d);
                        riscv_pkg::CSR_MEDELEG: csr_change(csr_addr_q3, medeleg_d);
                        riscv_pkg::CSR_MIE: csr_change(csr_addr_q3, mie_d);
                        riscv_pkg::CSR_SATP: csr_change(csr_addr_q3, satp_d);
                        riscv_pkg::CSR_STVEC: csr_change(csr_addr_q3, stvec_d);
                        riscv_pkg::CSR_SSCRATCH: csr_change(csr_addr_q3, sscratch_d);
                        riscv_pkg::CSR_SEPC: csr_change(csr_addr_q3, sepc_d);
                        riscv_pkg::CSR_MISA: csr_change(csr_addr_q3, def_pkg::ISA_CODE);
                        default: csr_change(csr_addr_q3, csr_wdata);
                    endcase
                end
            end
        end
        `else
        always_ff @(negedge clk_i) begin
            automatic logic [63:0] mstatus_fix, mstatus_clear ,mstatus_set;

            mstatus_clear = riscv_pkg::MSTATUS_UXL | riscv_pkg::MSTATUS_SXL | riscv_pkg::MSTATUS64_SD;
            mstatus_set =   ((mstatus_d.xs == riscv_pkg::Dirty) | (mstatus_d.fs == riscv_pkg::Dirty) | (mstatus_d.vs == riscv_pkg::Dirty))<<63 |
                            riscv_pkg::XLEN_64 << 32|
                            riscv_pkg::XLEN_64 << 34;
            mstatus_fix = (mstatus_d & ~mstatus_clear) | mstatus_set;
            `ifdef LOX
            if (rstn_i & (|torture_dpi_we_i)) begin
            `else
            if (rstn_i & (|retire_i)) begin
            `endif
                // CSRs which can change due to side-effects etc

                // For some reason mstatus is updated in multiple cycles, but at commit we need the value that will be set later
                // This might break in some random tests.....
                if (mstatus_q != mstatus_fix) csr_change(riscv_pkg::CSR_MSTATUS, mstatus_fix);

                if (fcsr_flags_valid_i && fcsr_flags_bits_i) csr_change(riscv_pkg::CSR_FFLAGS, fcsr_d.fflags);

                // CSRs which only change when written to
                if (csr_we) begin
                    case(csr_addr)
                        riscv_pkg::CSR_MSTATUS, riscv_pkg::CSR_SSTATUS:
                            ; // Covered by previous mstatus check
                        riscv_pkg::CSR_MTVEC: csr_change(csr_addr, mtvec_d);
                        riscv_pkg::CSR_MEPC: csr_change(csr_addr, mepc_d);
                        riscv_pkg::CSR_MCAUSE: csr_change(csr_addr, mcause_d);
                        riscv_pkg::CSR_MSCRATCH: csr_change(csr_addr, mscratch_d);
                        riscv_pkg::CSR_MEDELEG: csr_change(csr_addr, medeleg_d);
                        riscv_pkg::CSR_SIE,
                        riscv_pkg::CSR_MIE: csr_change(riscv_pkg::CSR_MIE, mie_d);
                        riscv_pkg::CSR_SATP: csr_change(csr_addr, satp_d);
                        riscv_pkg::CSR_STVEC: csr_change(csr_addr, stvec_d);
                        riscv_pkg::CSR_SSCRATCH: csr_change(csr_addr, sscratch_d);
                        riscv_pkg::CSR_SEPC: csr_change(csr_addr, sepc_d);
                        riscv_pkg::CSR_MISA: csr_change(csr_addr, def_pkg::ISA_CODE);
                        default: csr_change(csr_addr, csr_wdata);
                    endcase
                end
            end
        end
        `endif
    `endif
    `endif

    //-------------
    // Assertions
    //-------------
    //pragma translate_off
    `ifndef VERILATOR
        // check that eret and ex are never valid together
        assert property (
          @(posedge clk_i) !(eret_o && ex_i))
        else begin $error("eret and exception should never be valid at the same time"); end
    `endif
    //pragma translate_on
endmodule
