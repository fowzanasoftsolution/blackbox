//! Phase 3 verification gates (serialized — each gate binds ports and runs
//! heavy traffic; parallel execution would fight for CPU).

use tokio::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_gate2_invisible_app_restart() {
    let _g = SERIAL.lock().await;
    blackbox_ingress::gates_phase3::gate2()
        .await
        .expect("Gate 2: invisible app restart / connection hold");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_gate3_replay_sandbox() {
    let _g = SERIAL.lock().await;
    blackbox_ingress::gates_phase3::gate3()
        .await
        .expect("Gate 3: deterministic replay sandbox");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p3_gate1_zero_lost_webhooks_chaos() {
    let _g = SERIAL.lock().await;
    blackbox_ingress::gates_phase3::gate1()
        .await
        .expect("Gate 1: zero-lost-webhooks chaos");
}
