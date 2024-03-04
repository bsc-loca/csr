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

// This module implements the Zihpm (v2.0) (previously known as "Counters") and Sscofpmf (v0.5.2) extensions
module hpm_counters
    import riscv_pkg::*;
#(
    parameter CSR_ADDR_WIDTH = 12,
    parameter XLEN = 64,
    parameter HPM_NUM_EVENTS = 28,
    parameter HPM_NUM_COUNTERS = 29
) (
    input   logic           clk_i,
    input   logic           rstn_i,

    // Access interface
    input   logic [CSR_ADDR_WIDTH-1:0]  addr_i,
    input   logic                       we_i,
    input   logic [XLEN-1:0]            data_i,
    output  logic [XLEN-1:0]            data_o,

    // Inhibition mask
    input   logic [31:0]    mcountinhibit_i,
    
    // Current privilege mode of the core
    input   logic [1:0]     priv_lvl_i,

    // Events
    input logic [HPM_NUM_EVENTS:1] events_i,
    
    output  logic                          count_ovf_int_req_o,
    output  logic [HPM_NUM_COUNTERS+3-1:3] mhpm_ovf_bits_o 
);

    localparam HPM_NUM_EVENTS_BITS   = $clog2(HPM_NUM_EVENTS);
    localparam HPM_NUM_COUNTERS_BITS = $clog2(HPM_NUM_COUNTERS+3);

    function [63:0] trunc_sum_64bits(input [64:0] val_in);
        trunc_sum_64bits = val_in[63:0];
    endfunction

    function [HPM_NUM_COUNTERS_BITS-1:0] trunc_counter_idx(input [CSR_ADDR_WIDTH:0] val_in);
        trunc_counter_idx = val_in[HPM_NUM_COUNTERS_BITS-1:0];
    endfunction

    function [HPM_NUM_COUNTERS_BITS-1:0] trunc_event_idx(input [CSR_ADDR_WIDTH:0] val_in);
        trunc_event_idx = val_in[HPM_NUM_COUNTERS_BITS-1:0];
    endfunction

    if (XLEN != 64) begin
        $error("Only supported value for XLEN is 64");
    end
    
    // HPM Counters
    logic [63:0] mhpmcounter_d[HPM_NUM_COUNTERS+3-1:3];
    logic [63:0] mhpmcounter_q[HPM_NUM_COUNTERS+3-1:3];

    // Event selector
    logic [63:0] mhpmevent_d[HPM_NUM_COUNTERS+3-1:3];
    logic [63:0] mhpmevent_q[HPM_NUM_COUNTERS+3-1:3];
    
    logic [HPM_NUM_COUNTERS_BITS-1:0] mhpmcounter_idx;
    logic [HPM_NUM_COUNTERS_BITS-1:0]   mhpmevent_idx;
    assign mhpmcounter_idx = trunc_counter_idx(addr_i - CSR_MHPM_COUNTER_3 + 12'd3);
    assign mhpmevent_idx   = trunc_event_idx  (addr_i - CSR_MHPM_EVENT_3   + 12'd3);
    
    always_comb begin
        mhpmcounter_d = mhpmcounter_q;
        data_o = 'b0;
        mhpmevent_d = mhpmevent_q;
        count_ovf_int_req_o = 'b0;
        mhpm_ovf_bits_o = 'b0;

        for(int unsigned i = 3; i < (HPM_NUM_COUNTERS + 3); i++) begin
            mhpm_ovf_bits_o[i] = mhpmevent_q[i][63];
            // The mhpmcounterX can be incremented if bit X of mcountinhibit is clear and 
            // the counting of events in the current privilege mode is not disabled (mhpmeventX bit 62/61/60 is clear)
            // Hypervisor Extension (H) not supported (mhpmeventX bits 59 and 58)
            if (!mcountinhibit_i[i] && 
               (!(((priv_lvl_i == riscv_pkg::PRIV_LVL_M) && mhpmevent_q[i][62]) ||
               ((priv_lvl_i    == riscv_pkg::PRIV_LVL_S) && mhpmevent_q[i][61]) ||
               ((priv_lvl_i    == riscv_pkg::PRIV_LVL_U) && mhpmevent_q[i][60])))) begin
                // mhpmeventX[55:0] is the position (in the input vector) of the event to be counted in mhpmcounterX (mhpmeventX[55:0] == 0 means "no event")
                if ((mhpmevent_q[i][55:0] > 0) && (mhpmevent_q[i][55:0] <= HPM_NUM_EVENTS)) begin
                    mhpmcounter_d[i] = trunc_sum_64bits(mhpmcounter_q[i] + events_i[mhpmevent_q[i][HPM_NUM_EVENTS_BITS-1:0]]);
                    // Check overflow of counter and overflow status
                    if ((mhpmcounter_d[i] < mhpmcounter_q[i]) && !mhpmevent_q[i][63]) begin
                        mhpmevent_d[i][63] = 1'b1;
                        count_ovf_int_req_o = 1'b1;
                    end
                end
            end
        end

        //Read
        unique case (addr_i)
            CSR_MHPM_COUNTER_3,
            CSR_MHPM_COUNTER_4,
            CSR_MHPM_COUNTER_5,
            CSR_MHPM_COUNTER_6,
            CSR_MHPM_COUNTER_7,
            CSR_MHPM_COUNTER_8,
            CSR_MHPM_COUNTER_9,
            CSR_MHPM_COUNTER_10,
            CSR_MHPM_COUNTER_11,
            CSR_MHPM_COUNTER_12,
            CSR_MHPM_COUNTER_13,
            CSR_MHPM_COUNTER_14,
            CSR_MHPM_COUNTER_15,
            CSR_MHPM_COUNTER_16,
            CSR_MHPM_COUNTER_17,
            CSR_MHPM_COUNTER_18,
            CSR_MHPM_COUNTER_19,
            CSR_MHPM_COUNTER_20,
            CSR_MHPM_COUNTER_21,
            CSR_MHPM_COUNTER_22,
            CSR_MHPM_COUNTER_23,
            CSR_MHPM_COUNTER_24,
            CSR_MHPM_COUNTER_25,
            CSR_MHPM_COUNTER_26,
            CSR_MHPM_COUNTER_27,
            CSR_MHPM_COUNTER_28,
            CSR_MHPM_COUNTER_29,
            CSR_MHPM_COUNTER_30,
            CSR_MHPM_COUNTER_31: begin
                if (mhpmcounter_idx < (HPM_NUM_COUNTERS + 3)) begin
                    if (we_i) begin
                        mhpmcounter_d[mhpmcounter_idx] = data_i;
                    end else begin
                        data_o = mhpmcounter_q[mhpmcounter_idx];
                    end
                end 
            end

            CSR_MHPM_EVENT_3,
            CSR_MHPM_EVENT_4,
            CSR_MHPM_EVENT_5,
            CSR_MHPM_EVENT_6,
            CSR_MHPM_EVENT_7,
            CSR_MHPM_EVENT_8,
            CSR_MHPM_EVENT_9,
            CSR_MHPM_EVENT_10,
            CSR_MHPM_EVENT_11,
            CSR_MHPM_EVENT_12,
            CSR_MHPM_EVENT_13,
            CSR_MHPM_EVENT_14,
            CSR_MHPM_EVENT_15,
            CSR_MHPM_EVENT_16,
            CSR_MHPM_EVENT_17,
            CSR_MHPM_EVENT_18,
            CSR_MHPM_EVENT_19,
            CSR_MHPM_EVENT_20,
            CSR_MHPM_EVENT_21,
            CSR_MHPM_EVENT_22,
            CSR_MHPM_EVENT_23,
            CSR_MHPM_EVENT_24,
            CSR_MHPM_EVENT_25,
            CSR_MHPM_EVENT_26,
            CSR_MHPM_EVENT_27,
            CSR_MHPM_EVENT_28,
            CSR_MHPM_EVENT_29,
            CSR_MHPM_EVENT_30,
            CSR_MHPM_EVENT_31: begin
                if (mhpmevent_idx < (HPM_NUM_COUNTERS + 3)) begin
                    if (we_i) begin
                        mhpmevent_d[mhpmevent_idx] = data_i;
                    end else begin
                        data_o = mhpmevent_q[mhpmevent_idx];
                    end
                end
            end
            default: data_o = 'h0;
        endcase
    end

    //Registers
    always_ff @(posedge clk_i or negedge rstn_i) begin
        if (!rstn_i) begin
            mhpmcounter_q   <= '{default:0};
            mhpmevent_q     <= '{default:0};
        end else begin
            mhpmcounter_q   <= mhpmcounter_d;
            mhpmevent_q     <= mhpmevent_d;
        end
    end

endmodule
