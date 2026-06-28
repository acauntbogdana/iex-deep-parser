//! iex-deep-parser v3
//! IEX DEEP 1.0 pcap.gz → single Parquet with full schema (all types, all fields).
//! Streaming gz read without loading into RAM.
//!
//! Usage: iex-deep-parser <input.pcap.gz> <output.parquet>

use std::{
    env,
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
    time::Instant,
};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;

use arrow::{
    array::{
        ArrayRef, BooleanBuilder, Float64Builder,
        Int64Builder, StringBuilder, UInt8Builder, UInt32Builder,
    },
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use parquet::{
    arrow::ArrowWriter,
    basic::{Compression, ZstdLevel},
    file::properties::WriterProperties,
};

// ── IEX-TP offsets ────────────────────────────────────────────────────────────
const ETH_IP_UDP:          usize = 42;
const IEXTP_PROTO_ID_OFF:  usize = 2;
const IEXTP_MSG_COUNT_OFF: usize = 14;
const IEXTP_HEADER:        usize = 40;
const MSG_OFFSET:          usize = ETH_IP_UDP + IEXTP_HEADER;

// ── Message types ─────────────────────────────────────────────────────────────
const T_SYSTEM_EVENT:     u8 = 0x53;
const T_SECURITY_DIR:     u8 = 0x44;
const T_TRADING_STATUS:   u8 = 0x48;
const T_RETAIL_LIQUIDITY: u8 = 0x49;
const T_OPERATIONAL_HALT: u8 = 0x4f;
const T_SHORT_SALE:       u8 = 0x50;
const T_SECURITY_EVENT:   u8 = 0x45;
const T_PLU_BUY:          u8 = 0x38;
const T_PLU_SELL:         u8 = 0x35;
const T_TRADE_REPORT:     u8 = 0x54;
const T_TRADE_BREAK:      u8 = 0x42;
const T_OFFICIAL_PRICE:   u8 = 0x58;
const T_AUCTION_INFO:     u8 = 0x41;

const PARQUET_ZSTD_LEVEL: i32 = 3;
const CHUNK_SIZE:         usize = 500_000;

// ── Reading utilities ─────────────────────────────────────────────────────────
#[inline] fn ru8(b:&[u8],o:usize)->u8   { b[o] }
#[inline] fn ru16(b:&[u8],o:usize)->u16 { u16::from_le_bytes(b[o..o+2].try_into().unwrap()) }
#[inline] fn ru32(b:&[u8],o:usize)->u32 { u32::from_le_bytes(b[o..o+4].try_into().unwrap()) }
#[inline] fn ri64(b:&[u8],o:usize)->i64 { i64::from_le_bytes(b[o..o+8].try_into().unwrap()) }
#[inline] fn pf(r:i64)->f64 { r as f64 / 10_000.0 }

#[inline]
fn sym_str<'a>(b:&'a [u8], o:usize) -> &'a str {
    if o+8 > b.len() { return ""; }
    std::str::from_utf8(&b[o..o+8]).unwrap_or("").trim_end()
}

#[inline]
fn ascii4<'a>(b:&'a [u8], o:usize) -> &'a str {
    if o+4 > b.len() { return ""; }
    std::str::from_utf8(&b[o..o+4]).unwrap_or("").trim_end()
}

fn fmt(n:usize)->String {
    let s=n.to_string();
    let mut r=String::with_capacity(s.len()+s.len()/3);
    for (i,c) in s.chars().rev().enumerate() { if i>0&&i%3==0{r.push('_');} r.push(c); }
    r.chars().rev().collect()
}

// ── Schema ────────────────────────────────────────────────────────────────────
fn make_schema() -> Arc<Schema> {
    // true = nullable
    Arc::new(Schema::new(vec![
        // ── Common fields (all types) ──────────────────────────────────────
        Field::new("msg_type",   DataType::Utf8,  false),
        Field::new("timestamp",  DataType::Int64, false),
        Field::new("symbol",     DataType::Utf8,  false),  // empty for system_event
        Field::new("flags",      DataType::UInt8, true),   // not for all types

        // ── price_level_update ─────────────────────────────────────────────
        Field::new("side",       DataType::Utf8,    true), // B/S
        Field::new("price",      DataType::Float64, true),
        Field::new("size",       DataType::UInt32,  true),

        // ── trade_report / trade_break ─────────────────────────────────────
        Field::new("trade_id",       DataType::Int64,   true),
        Field::new("is_trade_break", DataType::Boolean, true),

        // ── official_price ─────────────────────────────────────────────────
        Field::new("price_type", DataType::Utf8, true), // opening/closing

        // ── auction_information ────────────────────────────────────────────
        Field::new("auction_type",                DataType::Utf8,    true),
        Field::new("paired_shares",               DataType::UInt32,  true),
        Field::new("reference_price",             DataType::Float64, true),
        Field::new("indicative_clearing_price",   DataType::Float64, true),
        Field::new("imbalance_shares",            DataType::UInt32,  true),
        Field::new("imbalance_side",              DataType::Utf8,    true),
        Field::new("extension_number",            DataType::UInt8,   true),
        Field::new("scheduled_auction_time",      DataType::UInt32,  true),
        Field::new("auction_book_clearing_price", DataType::Float64, true),
        Field::new("collar_reference_price",      DataType::Float64, true),
        Field::new("lower_auction_collar",        DataType::Float64, true),
        Field::new("upper_auction_collar",        DataType::Float64, true),

        // ── security_directory ─────────────────────────────────────────────
        Field::new("round_lot_size", DataType::UInt32,  true),
        Field::new("adj_poc_price",  DataType::Float64, true),
        Field::new("luld_tier",      DataType::UInt8,   true),

        // ── trading_status ─────────────────────────────────────────────────
        Field::new("trading_status", DataType::Utf8, true),
        Field::new("reason",         DataType::Utf8, true),

        // ── operational_halt ───────────────────────────────────────────────
        Field::new("halt_status", DataType::Utf8, true),

        // ── short_sale_status ──────────────────────────────────────────────
        Field::new("short_sale_status", DataType::UInt8, true),
        Field::new("short_sale_detail", DataType::Utf8,  true),

        // ── retail_liquidity ───────────────────────────────────────────────
        Field::new("retail_indicator", DataType::Utf8, true),

        // ── security_event ─────────────────────────────────────────────────
        Field::new("security_event", DataType::Utf8, true),

        // ── system_event ───────────────────────────────────────────────────
        Field::new("system_event", DataType::Utf8, true),
    ]))
}

// ── Buffer (one for all types) ────────────────────────────────────────────────
struct Buf {
    // common
    msg_type:  StringBuilder,
    timestamp: Int64Builder,
    symbol:    StringBuilder,
    flags:     UInt8Builder,

    // price_level_update
    side:  StringBuilder,
    price: Float64Builder,
    size:  UInt32Builder,

    // trade
    trade_id:       Int64Builder,
    is_trade_break: BooleanBuilder,

    // official_price
    price_type: StringBuilder,

    // auction
    auction_type:                StringBuilder,
    paired_shares:               UInt32Builder,
    reference_price:             Float64Builder,
    indicative_clearing_price:   Float64Builder,
    imbalance_shares:            UInt32Builder,
    imbalance_side:              StringBuilder,
    extension_number:            UInt8Builder,
    scheduled_auction_time:      UInt32Builder,
    auction_book_clearing_price: Float64Builder,
    collar_reference_price:      Float64Builder,
    lower_auction_collar:        Float64Builder,
    upper_auction_collar:        Float64Builder,

    // security_directory
    round_lot_size: UInt32Builder,
    adj_poc_price:  Float64Builder,
    luld_tier:      UInt8Builder,

    // trading_status
    trading_status: StringBuilder,
    reason:         StringBuilder,

    // operational_halt
    halt_status: StringBuilder,

    // short_sale
    short_sale_status: UInt8Builder,
    short_sale_detail: StringBuilder,

    // retail_liquidity
    retail_indicator: StringBuilder,

    // security_event
    security_event: StringBuilder,

    // system_event
    system_event: StringBuilder,

    pub len: usize,
}

impl Buf {
    fn new() -> Self {
        let c = CHUNK_SIZE;
        Self {
            msg_type:  StringBuilder::with_capacity(c, c*20),
            timestamp: Int64Builder::with_capacity(c),
            symbol:    StringBuilder::with_capacity(c, c*6),
            flags:     UInt8Builder::with_capacity(c),
            side:      StringBuilder::with_capacity(c, c),
            price:     Float64Builder::with_capacity(c),
            size:      UInt32Builder::with_capacity(c),
            trade_id:       Int64Builder::with_capacity(c),
            is_trade_break: BooleanBuilder::with_capacity(c),
            price_type:     StringBuilder::with_capacity(c, c*8),
            auction_type:                StringBuilder::with_capacity(c, c*10),
            paired_shares:               UInt32Builder::with_capacity(c),
            reference_price:             Float64Builder::with_capacity(c),
            indicative_clearing_price:   Float64Builder::with_capacity(c),
            imbalance_shares:            UInt32Builder::with_capacity(c),
            imbalance_side:              StringBuilder::with_capacity(c, c),
            extension_number:            UInt8Builder::with_capacity(c),
            scheduled_auction_time:      UInt32Builder::with_capacity(c),
            auction_book_clearing_price: Float64Builder::with_capacity(c),
            collar_reference_price:      Float64Builder::with_capacity(c),
            lower_auction_collar:        Float64Builder::with_capacity(c),
            upper_auction_collar:        Float64Builder::with_capacity(c),
            round_lot_size: UInt32Builder::with_capacity(c),
            adj_poc_price:  Float64Builder::with_capacity(c),
            luld_tier:      UInt8Builder::with_capacity(c),
            trading_status: StringBuilder::with_capacity(c, c*8),
            reason:         StringBuilder::with_capacity(c, c*4),
            halt_status:    StringBuilder::with_capacity(c, c*10),
            short_sale_status: UInt8Builder::with_capacity(c),
            short_sale_detail: StringBuilder::with_capacity(c, c*10),
            retail_indicator:  StringBuilder::with_capacity(c, c*10),
            security_event:    StringBuilder::with_capacity(c, c*20),
            system_event:      StringBuilder::with_capacity(c, c*20),
            len: 0,
        }
    }

    // Helper methods below append_null for all nullable fields that are not
    // relevant for the given message type.

    fn push_plu(&mut self, mt:u8, p:&[u8]) {
        if p.len() < 29 { return; }
        self.msg_type.append_value(if mt==T_PLU_BUY {"price_level_update_buy"} else {"price_level_update_sell"});
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_value(ru8(p,0));
        // plu fields
        self.side.append_value(if mt==T_PLU_BUY {"B"} else {"S"});
        self.price.append_value(pf(ri64(p,21)));
        self.size.append_value(ru32(p,17));
        // nulls
        self.trade_id.append_null();
        self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction();
        self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_trade(&mut self, mt:u8, p:&[u8]) {
        if p.len() < 37 { return; }
        self.msg_type.append_value(if mt==T_TRADE_REPORT {"trade_report"} else {"trade_break"});
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_value(ru8(p,0));
        // plu fields — null (trade has no side/price_level)
        self.side.append_null();
        self.price.append_value(pf(ri64(p,21)));
        self.size.append_value(ru32(p,17));
        // trade fields
        self.trade_id.append_value(ri64(p,29));
        self.is_trade_break.append_value(mt==T_TRADE_BREAK);
        // nulls
        self.price_type.append_null();
        self.push_null_auction();
        self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_official_price(&mut self, p:&[u8]) {
        if p.len() < 25 { return; }
        self.msg_type.append_value("official_price");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null();
        self.price.append_value(pf(ri64(p,17)));
        self.size.append_null();
        self.trade_id.append_null();
        self.is_trade_break.append_null();
        self.price_type.append_value(match ru8(p,0) {0x51=>"opening",0x4d=>"closing",_=>"unknown"});
        self.push_null_auction();
        self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_auction(&mut self, p:&[u8]) {
        if p.len() < 79 { return; }
        self.msg_type.append_value("auction_information");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null();
        self.price.append_null();
        self.size.append_null();
        self.trade_id.append_null();
        self.is_trade_break.append_null();
        self.price_type.append_null();
        // auction fields
        self.auction_type.append_value(match ru8(p,0) {
            0x4f=>"opening",0x43=>"closing",0x49=>"ipo",
            0x48=>"halt",0x56=>"volatility",_=>"unknown"
        });
        self.paired_shares.append_value(ru32(p,17));
        self.reference_price.append_value(pf(ri64(p,21)));
        self.indicative_clearing_price.append_value(pf(ri64(p,29)));
        self.imbalance_shares.append_value(ru32(p,37));
        self.imbalance_side.append_value(match ru8(p,41) {0x42=>"B",0x53=>"S",_=>""});
        self.extension_number.append_value(ru8(p,42));
        self.scheduled_auction_time.append_value(ru32(p,43));
        self.auction_book_clearing_price.append_value(pf(ri64(p,47)));
        self.collar_reference_price.append_value(pf(ri64(p,55)));
        self.lower_auction_collar.append_value(pf(ri64(p,63)));
        self.upper_auction_collar.append_value(pf(ri64(p,71)));
        self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_security_dir(&mut self, p:&[u8]) {
        if p.len() < 30 { return; }
        self.msg_type.append_value("security_directory");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_value(ru8(p,0));
        self.side.append_null();
        self.price.append_null();
        self.size.append_null();
        self.trade_id.append_null();
        self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction();
        // secdir fields
        self.round_lot_size.append_value(ru32(p,17));
        self.adj_poc_price.append_value(pf(ri64(p,21)));
        self.luld_tier.append_value(ru8(p,29));
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_trading_status(&mut self, p:&[u8]) {
        if p.len() < 21 { return; }
        self.msg_type.append_value("trading_status");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null(); self.price.append_null(); self.size.append_null();
        self.trade_id.append_null(); self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction(); self.push_null_secdir();
        self.trading_status.append_value(match ru8(p,0) {
            0x48=>"halted",0x4f=>"order_acceptance_period",
            0x50=>"paused",0x54=>"trading",_=>"unknown"
        });
        self.reason.append_value(ascii4(p,17));
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_operational_halt(&mut self, p:&[u8]) {
        if p.len() < 17 { return; }
        self.msg_type.append_value("operational_halt");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null(); self.price.append_null(); self.size.append_null();
        self.trade_id.append_null(); self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction(); self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_value(match ru8(p,0) {0x4f=>"halted",0x4e=>"not_halted",_=>"unknown"});
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_short_sale(&mut self, p:&[u8]) {
        if p.len() < 17 { return; }
        self.msg_type.append_value("short_sale_status");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null(); self.price.append_null(); self.size.append_null();
        self.trade_id.append_null(); self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction(); self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_value(ru8(p,0));
        self.short_sale_detail.append_value(if p.len()>17 {
            match ru8(p,17) {0x20=>"none",0x41=>"activated",0x43=>"continued",_=>"unknown"}
        } else {"unknown"});
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_retail_liquidity(&mut self, p:&[u8]) {
        if p.len() < 17 { return; }
        self.msg_type.append_value("retail_liquidity");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null(); self.price.append_null(); self.size.append_null();
        self.trade_id.append_null(); self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction(); self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_value(match ru8(p,0) {
            0x20=>"none",0x41=>"buy",0x42=>"sell",0x43=>"buy_and_sell",_=>"unknown"
        });
        self.security_event.append_null();
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_security_event(&mut self, p:&[u8]) {
        if p.len() < 17 { return; }
        self.msg_type.append_value("security_event");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value(sym_str(p,9));
        self.flags.append_null();
        self.side.append_null(); self.price.append_null(); self.size.append_null();
        self.trade_id.append_null(); self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction(); self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_value(match ru8(p,0) {
            0x4f=>"opening_process_complete",
            0x43=>"closing_process_complete",
            _=>"unknown"
        });
        self.system_event.append_null();
        self.len += 1;
    }

    fn push_system_event(&mut self, p:&[u8]) {
        if p.len() < 9 { return; }
        self.msg_type.append_value("system_event");
        self.timestamp.append_value(ri64(p,1));
        self.symbol.append_value("");
        self.flags.append_null();
        self.side.append_null(); self.price.append_null(); self.size.append_null();
        self.trade_id.append_null(); self.is_trade_break.append_null();
        self.price_type.append_null();
        self.push_null_auction(); self.push_null_secdir();
        self.trading_status.append_null(); self.reason.append_null();
        self.halt_status.append_null();
        self.short_sale_status.append_null(); self.short_sale_detail.append_null();
        self.retail_indicator.append_null();
        self.security_event.append_null();
        self.system_event.append_value(match ru8(p,0) {
            0x4f=>"start_of_messages",   0x53=>"start_of_system_hours",
            0x52=>"start_of_regular_hours", 0x4d=>"end_of_regular_hours",
            0x45=>"end_of_system_hours", 0x43=>"end_of_messages",
            _=>"unknown"
        });
        self.len += 1;
    }

    // ── null-fillers ──────────────────────────────────────────────────────────
    fn push_null_auction(&mut self) {
        self.auction_type.append_null();
        self.paired_shares.append_null();
        self.reference_price.append_null();
        self.indicative_clearing_price.append_null();
        self.imbalance_shares.append_null();
        self.imbalance_side.append_null();
        self.extension_number.append_null();
        self.scheduled_auction_time.append_null();
        self.auction_book_clearing_price.append_null();
        self.collar_reference_price.append_null();
        self.lower_auction_collar.append_null();
        self.upper_auction_collar.append_null();
    }

    fn push_null_secdir(&mut self) {
        self.round_lot_size.append_null();
        self.adj_poc_price.append_null();
        self.luld_tier.append_null();
    }

    fn finish(&mut self, sc: &Arc<Schema>) -> RecordBatch {
        let cols: Vec<ArrayRef> = vec![
            Arc::new(self.msg_type.finish()),
            Arc::new(self.timestamp.finish()),
            Arc::new(self.symbol.finish()),
            Arc::new(self.flags.finish()),
            Arc::new(self.side.finish()),
            Arc::new(self.price.finish()),
            Arc::new(self.size.finish()),
            Arc::new(self.trade_id.finish()),
            Arc::new(self.is_trade_break.finish()),
            Arc::new(self.price_type.finish()),
            Arc::new(self.auction_type.finish()),
            Arc::new(self.paired_shares.finish()),
            Arc::new(self.reference_price.finish()),
            Arc::new(self.indicative_clearing_price.finish()),
            Arc::new(self.imbalance_shares.finish()),
            Arc::new(self.imbalance_side.finish()),
            Arc::new(self.extension_number.finish()),
            Arc::new(self.scheduled_auction_time.finish()),
            Arc::new(self.auction_book_clearing_price.finish()),
            Arc::new(self.collar_reference_price.finish()),
            Arc::new(self.lower_auction_collar.finish()),
            Arc::new(self.upper_auction_collar.finish()),
            Arc::new(self.round_lot_size.finish()),
            Arc::new(self.adj_poc_price.finish()),
            Arc::new(self.luld_tier.finish()),
            Arc::new(self.trading_status.finish()),
            Arc::new(self.reason.finish()),
            Arc::new(self.halt_status.finish()),
            Arc::new(self.short_sale_status.finish()),
            Arc::new(self.short_sale_detail.finish()),
            Arc::new(self.retail_indicator.finish()),
            Arc::new(self.security_event.finish()),
            Arc::new(self.system_event.finish()),
        ];
        self.len = 0;
        RecordBatch::try_new(Arc::clone(sc), cols).expect("RecordBatch failed")
    }
}

// ── Packet processing ─────────────────────────────────────────────────────────
fn process_pkt(data: &[u8], buf: &mut Buf) {
    if data.len() <= MSG_OFFSET+2 { return; }
    if ru16(data, ETH_IP_UDP+IEXTP_PROTO_ID_OFF) != 0x8004 { return; }
    let mc = ru16(data, ETH_IP_UDP+IEXTP_MSG_COUNT_OFF) as usize;
    if mc == 0 { return; }
    let mut pos = MSG_OFFSET;
    for _ in 0..mc {
        if pos+3 > data.len() { break; }
        let ml  = ru16(data, pos) as usize;
        if ml < 1 { break; }
        let mt  = ru8(data, pos+2);
        let end = pos+2+ml;
        if end > data.len() { break; }
        let p = &data[pos+3..end];
        match mt {
            T_PLU_BUY | T_PLU_SELL           => buf.push_plu(mt, p),
            T_TRADE_REPORT | T_TRADE_BREAK    => buf.push_trade(mt, p),
            T_OFFICIAL_PRICE                  => buf.push_official_price(p),
            T_AUCTION_INFO                    => buf.push_auction(p),
            T_SECURITY_DIR                    => buf.push_security_dir(p),
            T_TRADING_STATUS                  => buf.push_trading_status(p),
            T_OPERATIONAL_HALT                => buf.push_operational_halt(p),
            T_SHORT_SALE                      => buf.push_short_sale(p),
            T_RETAIL_LIQUIDITY                => buf.push_retail_liquidity(p),
            T_SECURITY_EVENT                  => buf.push_security_event(p),
            T_SYSTEM_EVENT                    => buf.push_system_event(p),
            _ => {}
        }
        pos = end;
    }
}

// ── main ──────────────────────────────────────────────────────────────────────
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        bail!("Usage: {} <input.pcap.gz> <output.parquet>", args[0]);
    }
    let input_path  = &args[1];
    let output_path = &args[2];

    eprintln!("[iex-deep-parser] Input:  {}", input_path);
    eprintln!("[iex-deep-parser] Output: {}", output_path);
    let t0 = Instant::now();

    // ── 1. Parquet writer ─────────────────────────────────────────────────────
    let schema = make_schema();
    let tmp_path = format!("{}.part", output_path);
    let out_file = File::create(&tmp_path)
        .with_context(|| format!("Creating {}", tmp_path))?;

    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(PARQUET_ZSTD_LEVEL)?))
        .set_max_row_group_size(CHUNK_SIZE)
        .set_dictionary_enabled(true)
        .build();

    let mut writer = ArrowWriter::try_new(out_file, Arc::clone(&schema), Some(props))
        .context("ArrowWriter::try_new")?;

    // ── 2. Streaming gz read → PCAPNG blocks ──────────────────────────────
    let gz_file = File::open(input_path)
        .with_context(|| format!("Opening {}", input_path))?;
    let gz = GzDecoder::new(BufReader::with_capacity(8*1024*1024, gz_file));
    let mut gz = BufReader::with_capacity(64*1024*1024, gz);

    let mut buf = Buf::new();
    let mut total_pkts   = 0usize;
    let mut total_rows   = 0usize;
    let mut chunks_written = 0usize;

    let mut hdr = [0u8; 8];
    loop {
        match gz.read_exact(&mut hdr) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("Reading block header"),
        }
        let btype = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let blen  = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if blen < 12 { break; }

        let body_len = blen - 8;
        let mut body = vec![0u8; body_len];
        match gz.read_exact(&mut body) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("Reading block body"),
        }

        // Enhanced Packet Block
        if btype == 0x00000006 {
            if body_len < 20 { continue; }
            let cap_len   = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
            let pkt_start = 20;
            let pkt_end   = pkt_start + cap_len;
            if pkt_end > body_len { continue; }
            total_pkts += 1;
            process_pkt(&body[pkt_start..pkt_end], &mut buf);

            if buf.len >= CHUNK_SIZE {
                total_rows += buf.len;
                chunks_written += 1;
                let batch = buf.finish(&schema);
                writer.write(&batch).context("write batch")?;
                eprintln!(
                    "[iex-deep-parser] chunk {:>3} | rows: {:>14} | packets: {:>12} | {:.1} s",
                    chunks_written, fmt(total_rows), fmt(total_pkts),
                    t0.elapsed().as_secs_f32()
                );
            }
        }
        // Simple Packet Block
        else if btype == 0x00000003 {
            if body_len < 8 { continue; }
            let orig_len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
            let cap_len  = orig_len.min(body_len - 4);
            if 4 + cap_len > body_len { continue; }
            total_pkts += 1;
            process_pkt(&body[4..4+cap_len], &mut buf);
        }
        // SHB / IDB / ISB — skip
    }

    // Last chunk
    if buf.len > 0 {
        total_rows += buf.len;
        chunks_written += 1;
        let batch = buf.finish(&schema);
        writer.write(&batch).context("write last batch")?;
        eprintln!(
            "[iex-deep-parser] chunk {:>3} (last) | rows: {:>14} | {:.1} s",
            chunks_written, fmt(total_rows), t0.elapsed().as_secs_f32()
        );
    }

    writer.close().context("Closing Parquet writer")?;
    std::fs::rename(&tmp_path, output_path)
        .with_context(|| format!("rename {} → {}", tmp_path, output_path))?;

    let out_size = std::fs::metadata(output_path)?.len();
    let elapsed  = t0.elapsed().as_secs_f32();
    eprintln!("────────────────────────────────────────────────────────────");
    eprintln!("[iex-deep-parser] ✓ Done in {:.1} s", elapsed);
    eprintln!("[iex-deep-parser]   Packets:       {}", fmt(total_pkts));
    eprintln!("[iex-deep-parser]   Rows written:  {}", fmt(total_rows));
    eprintln!("[iex-deep-parser]   Parquet size:  {:.1} MB", out_size as f32/1024.0/1024.0);
    eprintln!("[iex-deep-parser]   Throughput:    {:.0} rows/s", total_rows as f32/elapsed);
    Ok(())
}
