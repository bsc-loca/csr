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
    input logic [WORD_WIDTH-1:0]            w_data_core_i,              //write data from the core
    output logic [WORD_WIDTH-1:0]           r_data_core_o,              // read data to the core, address specified with the rw_addr_i

    //Exceptions 
    input logic                             ex_i,                       // exception produced in the core
    input logic [WORD_WIDTH-1:0]            ex_cause_i,                 //cause of the exception
    input logic [63:0]                      ex_origin_i,                //origin of the exception
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

    // floating point flags
    input logic                             freg_modified_i,
    input logic                             fcsr_flags_valid_i,
    input logic [4:0]                       fcsr_flags_bits_i,
    output logic [2:0]                      fcsr_rm_o,
    output logic [1:0]                      fcsr_fs_o,

    output logic [1:0]                      vcsr_vs_o,
    input logic                             vxsat_i,

    output logic                            csr_replay_o,               // replay send to the core because there are some parts that are bussy
    output logic                            csr_stall_o,                // The csr are waiting a resp and de core is stalled
    output logic                            csr_xcpt_o,                 // Exeption pproduced by the csr   
    output logic [63:0]                     csr_xcpt_cause_o,           // Exception cause
    output logic [63:0]                     csr_tval_o,                 // Value written to the tval registers
    output logic                            eret_o,

    output logic [WORD_WIDTH-1:0]           status_o,                   //actual mstatus of the core
    output logic [1:0]                      priv_lvl_o,                 // actual privialge level of the core
    output logic [1:0]                      ld_st_priv_lvl_o,
    output logic                            en_ld_st_translation_o,
    output logic                            en_translation_o,

    output logic [PPN_WIDTH-1:0]             satp_ppn_o,                 // Page table base pointer for the PTW

    output logic [63:0]                     evec_o,                      // virtual address of the PC to execute after a Interrupt or exception

    output logic                            flush_o,                    // the core is executing a sfence.vm instruction and a tlb flush is needed
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

    //////////////////////////////////////////////
    // Registers declaration
    //////////////////////////////////////////////
    
    riscv_pkg::status_rv64_t  mstatus_q,  mstatus_d;
    riscv_pkg::satp_t         satp_q, satp_d;
    riscv_pkg::csr_t  csr_addr;
    // privilege level register
    riscv_pkg::priv_lvl_t   priv_lvl_d, priv_lvl_q;

    logic        mtvec_rst_load_q;// used to determine whether we came out of reset
    logic [63:0] mtvec_q,     mtvec_d;
    logic [63:0] medeleg_q,   medeleg_d;
    logic [63:0] mideleg_q,   mideleg_d;
    logic [63:0] mip_q,       mip_d;
    logic [63:0] mie_q,       mie_d;
    logic [31:0] mcounteren_q,mcounteren_d;
    logic [31:0] mcountinhibit_q,mcountinhibit_d;
    logic [63:0] mscratch_q,  mscratch_d;
    logic [63:0] mepc_q,      mepc_d;
    logic [63:0] mcause_q,    mcause_d;
    logic [63:0] mtval_q,     mtval_d;
    logic [63:0] menvcfg_q,   menvcfg_d;

    logic [63:0] stvec_q,     stvec_d;
    logic [31:0] scounteren_q,scounteren_d;
    logic [63:0] senvcfg_q,   senvcfg_d;
    logic [63:0] sscratch_q,  sscratch_d;
    logic [63:0] sepc_q,      sepc_d;
    logic [63:0] scause_q,    scause_d;
    logic [63:0] stval_q,     stval_d;

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
    logic        csr_we, csr_read;
    logic        csr_xcpt;          // Internal csr exception bit.
    logic [63:0] csr_xcpt_cause;    // cause of the internal csr exception
    logic [63:0] ex_tval;
    logic [63:0] csr_wdata, csr_rdata;
    logic [63:0] trap_vector_base;
    riscv_pkg::priv_lvl_t   trap_to_priv_lvl;
    // register for enabling load store address translation, this is critical, hence the register
    logic        en_ld_st_translation_d, en_ld_st_translation_q;
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

    //interruption wires
    logic [63:0] interrupt_cause_q, interrupt_cause_d, interrupt_cause;
    logic interrupt_d, interrupt_q;
    logic global_enable;

    // flush caused by a sfence instruction
    logic flush_sfence;
    
    logic [11:0] perf_addr_dist;


    //////////////////////////////////////////////
    // System Instructions Decode
    //////////////////////////////////////////////
    // indicates if the request is a system instuction
    assign system_insn = (rw_cmd_i == 4'b0100) ? 1'b1 : 1'b0;
    assign priv_sufficient = priv_lvl_q >= rw_addr_i[9:8];
    // the instructions are codified using the rw_addr_i
    assign insn_call = ((10'b0000000000 == rw_addr_i[9:0]) && system_insn) ? 1'b1 : 1'b0;
    assign insn_break = ((10'b0000000001 == rw_addr_i[9:0]) && system_insn) ? 1'b1 : 1'b0;
    assign insn_mret =  ((10'b1100000010 == rw_addr_i[9:0]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_sret =  ((10'b0100000010 == rw_addr_i[9:0]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
    assign insn_sfence_vm = ((5'b01001 == rw_addr_i[9:5]) && system_insn && priv_sufficient) ? 1'b1 : 1'b0;
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

        `ifdef CONF_SARGANTANA_ENABLE_PCR
            pcr_addr_valid = 1'b0;
        `endif // CONF_SARGANTANA_ENABLE_PCR

        csr_rdata = 64'b0;
        perf_addr_dist = '0;

        if (csr_read) begin
            unique case (csr_addr.address)
                riscv_pkg::CSR_FFLAGS: begin
                    if (mstatus_q.fs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {59'b0, fcsr_q.fflags};
                    end
                end
                riscv_pkg::CSR_FRM: begin
                    if (mstatus_q.fs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {61'b0, fcsr_q.frm};
                    end
                end
                riscv_pkg::CSR_FCSR: begin
                    if (mstatus_q.fs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {56'b0, fcsr_q.frm, fcsr_q.fflags};
                    end
                end
                riscv_pkg::CSR_VCSR: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {61'b0, vcsr_q.vxrm, vcsr_q.vxsat};
                    end
                end

                riscv_pkg::CSR_VXRM: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {62'b0, vcsr_q.vxrm};

                    end
                end

                riscv_pkg::CSR_VXSAT: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {63'b0, vcsr_q.vxsat};
                    end
                end
                riscv_pkg::CSR_VSTART: begin // not supported
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = {64'b0};
                    end
                end
                riscv_pkg::CSR_VL: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = vl_q;
                    end
                end

                riscv_pkg::CSR_VTYPE: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        read_access_exception = 1'b1;
                    end else begin
                        csr_rdata = vtype_q;
                    end
                end
                
                riscv_pkg::CSR_VLENB: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
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
                riscv_pkg::CSR_SIE:                csr_rdata = mie_q & mideleg_q;
                riscv_pkg::CSR_SIP:                csr_rdata = mip_q & mideleg_q;
                riscv_pkg::CSR_STVEC:              csr_rdata = stvec_q;
                riscv_pkg::CSR_SCOUNTEREN:         csr_rdata = {{32{1'b0}}, scounteren_q};
                riscv_pkg::CSR_SENVCFG:            csr_rdata = {63'b0, senvcfg_q[0]}; // only implemented FIOM
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
                // machine mode registers
                riscv_pkg::CSR_MSTATUS:            csr_rdata = mstatus_q;
                riscv_pkg::CSR_MISA:               csr_rdata = def_pkg::ISA_CODE; 
                riscv_pkg::CSR_MEDELEG:            csr_rdata = medeleg_q;
                riscv_pkg::CSR_MIDELEG:            csr_rdata = mideleg_q;
                riscv_pkg::CSR_MIE:                csr_rdata = mie_q;
                riscv_pkg::CSR_MTVEC:              csr_rdata = mtvec_q;
                riscv_pkg::CSR_MCOUNTEREN:         csr_rdata = {{32{1'b0}}, mcounteren_q};
                riscv_pkg::CSR_MCOUNTINHIBIT:      csr_rdata = {{32{1'b0}}, mcountinhibit_q[31:2], 1'b0, mcountinhibit_q[0]};
                riscv_pkg::CSR_MSCRATCH:           csr_rdata = mscratch_q;
                riscv_pkg::CSR_MEPC:               csr_rdata = mepc_q;
                riscv_pkg::CSR_MCAUSE:             csr_rdata = mcause_q;
                riscv_pkg::CSR_MTVAL:              csr_rdata = mtval_q;
                riscv_pkg::CSR_MIP:                csr_rdata = mip_q;
                riscv_pkg::CSR_MENVCFG:            csr_rdata = {63'b0, menvcfg_q[0]}; // only FIOM bit implemented
                riscv_pkg::CSR_MVENDORID:          csr_rdata = 64'b0; // not implemented
                riscv_pkg::CSR_MARCHID:            csr_rdata = 64'b0; // not implemented
                riscv_pkg::CSR_MIMPID:             csr_rdata = 64'b0; // not implemented
                riscv_pkg::CSR_MHARTID:            csr_rdata = core_id_i; 
                riscv_pkg::CSR_MCONFIGPTR:         csr_rdata = 64'b0; // not implemented
                `ifdef PITON_CINCORANCH
                riscv_pkg::CSR_MBOOT_MAIN_ID:      csr_rdata = {62'b0, boot_main_id_i};
                `endif  // Custom for CincoRanch
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
                riscv_pkg::CSR_TIME:               csr_rdata = reg_time_q;
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
        automatic logic [63:0] instret;
        automatic logic [63:0] mstatus_int, mstatus_clear ,mstatus_set; //Used to set and clear some bits of the mstatus_d
        automatic logic flush; //temporal flush value befor the exceptions logic
        automatic logic [63:0] mcause_int; // temporal value of mcause
        automatic logic [63:0] scause_int; // temporal value of scause
        automatic logic [63:0] mtval_int; // temporal value of mtval
        automatic logic [63:0] stval_int; // temporal value of stval
        automatic logic [63:0] mepc_int; // temporal value of mepc
        automatic logic [63:0] sepc_int; // temporal value of sepc

        satp = satp_q;
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
            instret = trunc_sum_64bits(instret + {{(64-$clog2(RETIRE_BW+1)){1'b0}},retire_cnt});
        end
        instret_d = instret;
        // increment the cycle count 
        cycle_d = trunc_sum_64bits(cycle_q + {63'b0,~mcountinhibit_q[0]});
        
        scountovf_d = {perf_mhpm_ovf_bits_i, 3'b000};

        eret_o                  = 1'b0;
        flush                   = 1'b0;
        update_access_exception = 1'b0;

        perf_we_o               = 1'b0;
        perf_data_o             = 'b0;

        fcsr_d                  = fcsr_q;
        vcsr_d                  = vcsr_q;

        priv_lvl_d              = priv_lvl_q;

        mstatus_clear = riscv_pkg::MSTATUS_UXL | riscv_pkg::MSTATUS_SXL | riscv_pkg::MSTATUS64_SD;
        mstatus_set =   (((mstatus_q.xs == riscv_pkg::Dirty) || (mstatus_q.fs == riscv_pkg::Dirty) || (mstatus_q.vs == riscv_pkg::Dirty))<<63) |
                        {30'b0,riscv_pkg::XLEN_64,32'b0} |
                        {28'b0,riscv_pkg::XLEN_64,34'b0};
        mstatus_int   = (mstatus_q & ~mstatus_clear) | mstatus_set;


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
        if (vsetvl_insn && (mstatus_q.vs != riscv_pkg::Off)) begin
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



        medeleg_d               = medeleg_q;
        mideleg_d               = mideleg_q;
        
        mie_d                   = mie_q;
        mepc_int                = mepc_q;
        mcause_int              = mcause_q;
        mcounteren_d            = mcounteren_q;
        mcountinhibit_d         = mcountinhibit_q;
        mscratch_d              = mscratch_q;
        mtval_int               = mtval_q;
        menvcfg_d               = menvcfg_q;

        sepc_int                = sepc_q;
        scause_int              = scause_q;
        stvec_d                 = stvec_q;
        scounteren_d            = scounteren_q;
        senvcfg_d               = senvcfg_q;
        sscratch_d              = sscratch_q;
        stval_int               = stval_q;
        satp_d                  = satp_q;

        en_ld_st_translation_d  = en_ld_st_translation_q;
        dirty_fp_state_csr      = 1'b0;
        dirty_v_state_csr       = 1'b0;

        dcsr_d = dcsr_q;
        dpc_d = dpc_q;
        dscratch0_d = dscratch0_q;
        dscratch1_d = dscratch1_q;

        `ifdef CONF_SARGANTANA_ENABLE_PCR
            pcr_req_data_o          = 'b0;
        `endif // CONF_SARGANTANA_ENABLE_PCR

        mask                    = 64'h0;
        satp_temp='0;

        // check for correct access rights and that we are writing
        if (csr_we) begin
            unique case (csr_addr.address)
                // Floating-Point
                riscv_pkg::CSR_FFLAGS: begin
                    if (mstatus_q.fs == riscv_pkg::Off) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_fp_state_csr = 1'b1;
                        fcsr_d.fflags = csr_wdata[4:0];
                        // this instruction has side-effects
                        flush = 1'b1;
                    end
                end
                riscv_pkg::CSR_FRM: begin
                    if (mstatus_q.fs == riscv_pkg::Off) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_fp_state_csr = 1'b1;
                        fcsr_d.frm    = csr_wdata[2:0];
                        // this instruction has side-effects
                        flush = 1'b1;
                    end
                end
                riscv_pkg::CSR_FCSR: begin
                    if (mstatus_q.fs == riscv_pkg::Off) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_fp_state_csr = 1'b1;
                        fcsr_d[7:0] = csr_wdata[7:0]; // ignore writes to reserved space
                        // this instruction has side-effects
                        flush = 1'b1;
                    end
                end
                riscv_pkg::CSR_VXSAT: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_v_state_csr  = 1'b1;
                        vcsr_d.vxsat    = csr_wdata[0];
                        // this instruction has side-effects
                        flush = 1'b1;
                    end
                    
                end
                riscv_pkg::CSR_VXRM: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_v_state_csr  = 1'b1;
                        vcsr_d.vxrm    = csr_wdata[1:0];

                        // this instruction has side-effects
                        flush = 1'b1;
                    end
                end
                riscv_pkg::CSR_VCSR: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
                        update_access_exception = 1'b1;
                    end else begin
                        dirty_v_state_csr = 1'b1;
                        vcsr_d.vxsat = csr_wdata[0];
                        vcsr_d.vxrm = csr_wdata[2:1];
                        // this instruction has side-effects
                        flush = 1'b1;
                    end
                end
                riscv_pkg::CSR_VSTART: begin
                    if (mstatus_q.vs == riscv_pkg::Off) begin
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
                    // this instruction has side-effects
                    flush = 1'b1;
                end
                // even machine mode interrupts can be visible and set-able to supervisor
                // if the corresponding bit in mideleg is set
                riscv_pkg::CSR_SIE: begin
                    // the mideleg makes sure only delegate-able register (and therefore also only implemented registers) are written
                    mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_LCOFIP;
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
                    flush = 1'b1;
                end

                riscv_pkg::CSR_MSTATUS: begin
                    // mask of the bits that are set to zero
                    mask = riscv_pkg::MSTATUS_UIE | riscv_pkg::MSTATUS_UPIE | riscv_pkg::MSTATUS_XS | riscv_pkg::MSTATUS64_WPRI;
                    mstatus_int      = csr_wdata & ~mask;
                    
                    // this register has side-effects on other registers, flush the pipeline
                    flush        = 1'b1;
                end
                // MISA is WARL (Write Any Value, Reads Legal Value)
                riscv_pkg::CSR_MISA:;
                // machine exception delegation register
                // 0 - 15 exceptions supported
                riscv_pkg::CSR_MEDELEG: begin
                    mask = (1 << riscv_pkg::INSTR_ADDR_MISALIGNED) |
                           (1 << riscv_pkg::BREAKPOINT) |
                           (1 << riscv_pkg::USER_ECALL) |
                           (1 << riscv_pkg::INSTR_PAGE_FAULT) |
                           (1 << riscv_pkg::LD_PAGE_FAULT) |
                           (1 << riscv_pkg::ST_AMO_PAGE_FAULT);
                    medeleg_d = (medeleg_q & ~mask) | (csr_wdata & mask);
                end
                // machine interrupt delegation register
                // we do not support user interrupt delegation
                riscv_pkg::CSR_MIDELEG: begin
                    mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_LCOFIP;
                    mideleg_d = (mideleg_q & ~mask) | (csr_wdata & mask);
                end
                // mask the register so that unsupported interrupts can never be set
                riscv_pkg::CSR_MIE: begin
                    mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_MSIP | riscv_pkg::MIP_MTIP | riscv_pkg::MIP_MEIP | riscv_pkg::MIP_LCOFIP;
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
                riscv_pkg::CSR_MSCRATCH:           mscratch_d  = csr_wdata;
                riscv_pkg::CSR_MEPC:               mepc_int    = {csr_wdata[63:1], 1'b0};
                riscv_pkg::CSR_MCAUSE:             mcause_int  = csr_wdata;
                riscv_pkg::CSR_MTVAL:              mtval_int   = csr_wdata;
                riscv_pkg::CSR_MENVCFG:            menvcfg_d   = csr_wdata;
                riscv_pkg::CSR_MIP: begin
                    mask = riscv_pkg::MIP_SSIP | riscv_pkg::MIP_STIP | riscv_pkg::MIP_SEIP | riscv_pkg::MIP_LCOFIP;
                    mip_d = (mip_q & ~mask) | (csr_wdata & mask);
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

        // mark the floating point extension register as dirty 
        if (def_pkg::FP_PRESENT && (dirty_fp_state_csr)) begin
            mstatus_d.fs = riscv_pkg::Dirty;
        end
        // hardwire to zero if floating point extension is not present
        else if (!def_pkg::FP_PRESENT) begin
            mstatus_d.fs = riscv_pkg::Off;
        end

        // mark the vector extension register as dirty 
        if (def_pkg::V_PRESENT && (dirty_v_state_csr)) begin
            mstatus_d.vs = riscv_pkg::Dirty;
        end
        // hardwire to zero if vector extension is not present
        else if (!def_pkg::V_PRESENT) begin
            mstatus_d.vs = riscv_pkg::Off;
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
        
        // if the priv is different of M or the mie is 1, the interrups are enable
        global_enable = ((mstatus_q.mie && (priv_lvl_o == riscv_pkg::PRIV_LVL_M))
                                        || (priv_lvl_o != riscv_pkg::PRIV_LVL_M)) && (~debug_mode_en_q) && (~dcsr_q.step);

        if (interrupt_cause[63] && global_enable) begin
            // However, if bit i in mideleg is set, interrupts are considered to be globally enabled if the hart’s current privilege
            // mode equals the delegated privilege mode (S or U) and that mode’s interrupt enable bit
            // (SIE or UIE in mstatus) is set, or if the current privilege mode is less than the delegated privilege mode.
            if (mideleg_q[interrupt_cause[5:0]]) begin
                if ((mstatus_q.sie && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) || (priv_lvl_q == riscv_pkg::PRIV_LVL_U)) begin
                    interrupt_d = 1'b1;
                    interrupt_cause_d = interrupt_cause;
                end
            end else begin
                interrupt_d = 1'b1;
                interrupt_cause_d = interrupt_cause;
            end
        end
        
        // a sfence is executed and a flush is needed
        if (flush_sfence) begin
            flush = 1'b1;
        end
        flush_o = flush;

        //Output connection
        interrupt_o = interrupt_q;
        interrupt_cause_o = interrupt_cause_q;
        // -----------------------
        // Manage Exception Stack
        // -----------------------
        // update exception CSRs
        // we got an exception update cause, pc and stval register
        trap_to_priv_lvl = riscv_pkg::PRIV_LVL_M;
        // Exception is taken and we are not in debug mode
        // exceptions in debug mode don't update any fields
        
        if ((((ex_cause_i != riscv_pkg::DEBUG_REQUEST) && ex_i) || csr_xcpt) && (~debug_mode_en_q)) begin
            // do not flush, flush is reserved for CSR writes with side effects
            flush_o   = 1'b0;
            ex_tval = pc_i;
            //tval is the actual pc except for the data access exeptions
            if (ex_i && ex_cause_i inside {riscv_pkg::LD_ADDR_MISALIGNED, riscv_pkg::LD_ACCESS_FAULT, 
                                    riscv_pkg::ST_AMO_ADDR_MISALIGNED, riscv_pkg::ST_AMO_ACCESS_FAULT,
                                    riscv_pkg::LD_PAGE_FAULT, riscv_pkg::ST_AMO_PAGE_FAULT,
                                    riscv_pkg::INSTR_PAGE_FAULT, riscv_pkg::INSTR_ADDR_MISALIGNED}) begin
                ex_tval = ex_origin_i;
            end else if ((ex_i && (ex_cause_i == riscv_pkg::ILLEGAL_INSTR)) || (csr_xcpt && (csr_xcpt_cause == riscv_pkg::ILLEGAL_INSTR))) begin
                ex_tval = 64'b0;
	        end else if (csr_xcpt && (csr_xcpt_cause == riscv_pkg::BREAKPOINT)) begin
                ex_tval = pc_i;
            end else begin
                ex_tval = 64'b0;
            end
            // figure out where to trap to
            // a m-mode trap might be delegated if we are taking it in S mode
            // first figure out if this was an exception or an interrupt e.g.: look at bit 63
            // the cause register can only be 6 bits long (as we only support 64 exceptions)
            if ((ex_i &&((ex_cause_i[63] && mideleg_q[ex_cause_i[5:0]]) ||
                (~ex_cause_i[63] && medeleg_q[ex_cause_i[5:0]]))) ||
                (csr_xcpt && ((csr_xcpt_cause[63] && mideleg_q[csr_xcpt_cause[5:0]]) ||
                (~csr_xcpt_cause[63] && medeleg_q[csr_xcpt_cause[5:0]])))) begin
                // traps never transition from a more-privileged mode to a less privileged mode
                // so if we are already in M mode, stay there
                trap_to_priv_lvl = (priv_lvl_o == riscv_pkg::PRIV_LVL_M) ? riscv_pkg::PRIV_LVL_M : riscv_pkg::PRIV_LVL_S;
            end

            // trap to supervisor mode
            if (trap_to_priv_lvl == riscv_pkg::PRIV_LVL_S) begin
                // update sstatus
                mstatus_d.sie  = 1'b0;
                mstatus_d.spie = mstatus_q.sie;
                // this can either be user or supervisor mode
                mstatus_d.spp  = priv_lvl_q[0];
                // set cause
                scause_d       = csr_xcpt ? csr_xcpt_cause : ex_cause_i;
                // set epc
                sepc_d         = pc_i;
                // set mtval or stval
                // stval_d have a special case for a mecanisem of ariane. In DRAC stval_d = ex_i.tval.
                stval_d        = ex_tval;
            // trap to machine mode
            end else begin
                // update mstatus
                mstatus_d.mie  = 1'b0;
                mstatus_d.mpie = mstatus_q.mie;
                // save the previous privilege mode
                mstatus_d.mpp  = priv_lvl_q;
                mcause_d       = csr_xcpt ? csr_xcpt_cause : ex_cause_i;
                // set epc
                mepc_d         = pc_i;
                // set mtval or stval
                // stval_d have a special case for a mecanisem of ariane. In DRAC stval_d = ex_i.tval.
                mtval_d        = ex_tval;
            end
            
            priv_lvl_d = trap_to_priv_lvl;
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
            // clear mprv if returning from machine mode to any other mode
            if ((priv_lvl_d != riscv_pkg::PRIV_LVL_M) && (priv_lvl_d != priv_lvl_q)) begin
                mstatus_d.mprv = 1'b0;
            end
        end else if (sret && !((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && (mstatus_q.tsr == 1'b1))) begin
            // return from exception, IF doesn't care from where we are returning
            eret_o = 1'b1;
            // return the previous supervisor interrupt enable flag
            mstatus_d.sie  = mstatus_q.spie;
            // restore the previous privilege level
            priv_lvl_d     = riscv_pkg::priv_lvl_t'({1'b0, mstatus_q.spp});
            // set spp to user mode
            mstatus_d.spp  = 1'b0;
            // set spie to 1
            mstatus_d.spie = 1'b1;
            // clear mprv if returning from machine mode to any other mode
            if ((priv_lvl_d != riscv_pkg::PRIV_LVL_M) && (priv_lvl_d != priv_lvl_q)) begin
                mstatus_d.mprv = 1'b0;
            end
        end

        // ------------------------------
        // MPRV - Modify Privilege Level
        // ------------------------------
        // Set the address translation at which the load and stores should occur
        // we can use the previous values since changing the address translation will always involve a pipeline flush
        if (mprv && (satp_q.mode == def_pkg::MODE_SV39) && (mstatus_q.mpp != riscv_pkg::PRIV_LVL_M) && ((~debug_mode_en_q) || dcsr_q.mprven)) begin
            en_ld_st_translation_d = 1'b1;
        end else begin // otherwise we go with the regular settings
            en_ld_st_translation_d = en_translation_o;
            //ld_st_priv_lvl_o = (mprv) ? mstatus_q.mpp : priv_lvl_o;
            //en_ld_st_translation_o = en_ld_st_translation_q;
        end
	
        ld_st_priv_lvl_o = (mprv &&  ((~debug_mode_en_q) || dcsr_q.mprven)) ? mstatus_q.mpp : priv_lvl_o;
        en_ld_st_translation_o = en_ld_st_translation_q;

        debug_mode_en_d = debug_mode_en_q;
        debug_ebreak_d = 1'b0;

        if (insn_break & (~debug_mode_en_q)) begin
            if (((priv_lvl_q == riscv_pkg::PRIV_LVL_M) && (dcsr_q.ebreakm)) || 
                ((priv_lvl_q == riscv_pkg::PRIV_LVL_S) && (dcsr_q.ebreaks)) ||
                ((priv_lvl_q == riscv_pkg::PRIV_LVL_U) && (dcsr_q.ebreaku))) begin
                dcsr_d.cause = 3'h1;
                dcsr_d.prv = priv_lvl_q;
                dpc_d = pc_i; // pc of the ebreak_instruction
                debug_mode_en_d = 1'b1;
                priv_lvl_d = riscv_pkg::PRIV_LVL_M;
                debug_ebreak_d = 1'b1;
            end
        end else if (debug_halt_ack_i) begin
            dcsr_d.cause = 3'h3;
            dcsr_d.prv = priv_lvl_q;
            dpc_d = pc_i; // pc of the next instruction to be executed
            debug_mode_en_d = 1'b1;
            priv_lvl_d = riscv_pkg::PRIV_LVL_M;
        end else if ((~debug_mode_en_q) & dcsr_q.step & ((|retire_i)| ex_i)) begin
            if ( ex_i | csr_xcpt) begin
                dpc_d = trap_vector_base;
                dcsr_d.prv = priv_lvl_d;
            end else if( sret ) begin
                dpc_d = sepc_q;
                dcsr_d.prv = priv_lvl_d;
            end else if( mret) begin
                dpc_d = mepc_q;
                dcsr_d.prv = priv_lvl_d;
            end else begin
                dcsr_d.prv = priv_lvl_q;
                dpc_d = pc_i; // pc of the next instruction to be executed
            end
            dcsr_d.cause = 3'h4;
            debug_mode_en_d = 1'b1;
            priv_lvl_d = riscv_pkg::PRIV_LVL_M;
            debug_ebreak_d = 1'b1;
        end else if (debug_resume_ack_i & debug_mode_en_q) begin
            eret_o = 1'b1;
            priv_lvl_d = dcsr_q.prv;
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
        end
        // if we are violating our privilges do not update the architectural state
        if (privilege_violation) begin
            csr_we = 1'b0;
            csr_read = 1'b0;
        end
    end

    // -----------------
    // Privilege Check
    // -----------------
    always_comb begin : privilege_check
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
        end
        //checks the level of the system instruction or sfence with tvm = 1 or sret and tsr = 1
        if ((system_insn && !priv_sufficient) || 
            ((insn_sfence_vm && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) && (mstatus_q.tvm == 1'b1)) || 
            ((insn_sret && (priv_lvl_q == riscv_pkg::PRIV_LVL_S)) && (mstatus_q.tsr == 1'b1))) begin
            privilege_violation = 1'b1;
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

            if ((mstatus_q.vs == riscv_pkg::Off)) begin
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
                        vtype_d = {'0,vtype_new};
                    end
                end else begin
                // vtype assignation
                    if ((vtype_new[10:8] != 3'b0) || (vtype_new[6] == 1'b0) || (vtype_new[5] == 1'b1) || 
                        ((vtype_new[2:0] > 3'b0) && ((vtype_new[2:0] < 3'b101) || (vtype_new[1:0] <= vtype_new[4:3])))) begin // unsupported tail, or SEW/LMUL configuration (rvv1.0 page 11)
                        vtype_d = {1'b1,63'b0};
                        vl_d = 'h0;
                    end else begin
                        vtype_d = {'0,vtype_new};
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
            csr_xcpt_cause = riscv_pkg::USER_ECALL + priv_lvl_q;
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
        end
    end

    // -------------------
    // Wait for Interrupt
    // -------------------
    always_comb begin : wfi_ctrl
        // wait for interrupt register
        wfi_d = wfi_q;
        // if there is any interrupt pending un-stall the core
        if ((|mip_q) || irq_q[0] || irq_q[1] || debug_halt_req_i) begin
            wfi_d = 1'b0;
        // or alternatively if there is no exception pending and we are not in debug mode wait here
        // for the interrupt
        end else if (insn_wfi && !ex_i) begin
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


    // output assignments dependent on privilege mode
    always_comb begin : priv_output
        // vectorized trap addres
        trap_vector_base[63:8] = mtvec_q[63:8];
        trap_vector_base[7:2] = ((mtvec_q[1:0] == 2'b0) || csr_xcpt || !ex_cause_i[63]) ? mtvec_q[7:2] : csr_xcpt ? trunc_sum_6bits(mtvec_q[7:2] + csr_xcpt_cause[5:0]) : trunc_sum_6bits(mtvec_q[7:2] + ex_cause_i[5:0]);
        trap_vector_base[1:0] = 2'b0;
        // output user mode stvec
        if (trap_to_priv_lvl == riscv_pkg::PRIV_LVL_S) begin
            // vectorized trap addres
            trap_vector_base[63:8] = stvec_q[63:8];
            trap_vector_base[7:2] = ((stvec_q[1:0] == 2'b0) || csr_xcpt || !ex_cause_i[63]) ? stvec_q[7:2] : csr_xcpt ? trunc_sum_6bits(mtvec_q[7:2] + csr_xcpt_cause[5:0]) : trunc_sum_6bits(mtvec_q[7:2] + ex_cause_i[5:0]);
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
                evec_o = sepc_q;
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
        	unique case (csr_addr.address)
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
    assign status_o = mstatus_q;
    // in debug mode we execute with privilege level M
    assign priv_lvl_o       = (debug_resume_ack_i) ? dcsr_q.prv : priv_lvl_q;
    // FPU outputs

    assign fcsr_rm_o        = fcsr_q.frm;
    assign fcsr_fs_o        = mstatus_q.fs;

    // VPU outputs
    assign vcsr_vs_o        = mstatus_q.vs;


    // MMU outputs 
    assign satp_ppn_o       = satp_q.ppn[PPN_WIDTH-1:0];

    // we support bare memory addressing and SV39
    assign en_translation_o = ((satp_q.mode == 4'h8) && (priv_lvl_o != riscv_pkg::PRIV_LVL_M))
                              ? 1'b1
                              : 1'b0;

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
            // machine mode registers
            mstatus_q              <= 64'b011000000000;
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
            mscratch_q             <= 64'b0;
            mtval_q                <= 64'b0;
            menvcfg_q              <= 64'b0;
            // supervisor mode registers
            sepc_q                 <= 64'b0;
            scause_q               <= 64'b0;
            stvec_q                <= 64'b0;
            scounteren_q           <= 32'b0;
            senvcfg_q              <= 64'b0;
            sscratch_q             <= 64'b0;
            stval_q                <= 64'b0;
            satp_q                 <= 64'b0;
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
            mscratch_q             <= mscratch_d;
            mtval_q                <= mtval_d;
            menvcfg_q              <= menvcfg_d;
            // supervisor mode registers
            sepc_q                 <= sepc_d;
            scause_q               <= scause_d;
            stvec_q                <= stvec_d;
            scounteren_q           <= scounteren_d;
            senvcfg_q              <= senvcfg_d;
            sscratch_q             <= sscratch_d;
            stval_q                <= stval_d;
            satp_q                 <= satp_d;
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
