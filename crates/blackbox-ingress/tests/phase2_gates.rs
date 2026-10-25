//! Phase 2 verification gates as release tests. The three gates bind
//! ephemeral ports, use fresh temp dirs and serialize on a mutex so their
//! RSS budgets are measured against a quiet process.

use std::sync::Mutex;

static GATE_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn gate1_end_to_end_causal_link() {
    let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(blackbox_ingress::gates_phase2::gate1())
        .expect("Gate 1 must pass");
}

#[test]
fn gate2_stream_and_bomb_safety() {
    let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(blackbox_ingress::gates_phase2::gate2())
        .expect("Gate 2 must pass");
}

#[test]
fn gate3_throughput_and_overhead() {
    let _g = GATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(blackbox_ingress::gates_phase2::gate3(20_000, 8))
        .expect("Gate 3 must pass");
}
