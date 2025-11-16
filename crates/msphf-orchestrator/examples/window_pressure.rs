use std::time::Duration;

use msphf_orchestrator::{
    AcceptInstant,
    mhw::{FreezeError, HeadRecord, MultiHeadWindow},
};

fn main() {
    let wid = b"demo-window-id";
    let mut window = MultiHeadWindow::new(3, Duration::from_secs(3));

    println!("Config: h_max=3 ttl=3 logical seconds");

    for idx in 0..3 {
        let accept_time = AcceptInstant::from_ticks(idx as u64);
        let record = head_record(idx as usize, accept_time);
        match window.accept_head(wid, record, accept_time) {
            Ok(_) => {}
            Err(_) => unreachable!("head should fit window"),
        }
        println!("  inserted head #{idx}");
    }

    let overflow_time = AcceptInstant::from_ticks(5);
    let overflow = head_record(3, overflow_time);
    match window.accept_head(wid, overflow, overflow_time) {
        Err(err) if err == FreezeError::WINDOW_FULL => {
            println!("  fourth head rejected with {}", err.reason);
        }
        Err(err) => {
            eprintln!("  unexpected rejection: {err:?}");
        }
        Ok(_) => {
            eprintln!("  unexpected success inserting overflow head");
        }
    }

    let later = AcceptInstant::from_ticks(4);
    let pruned = head_record(4, later);
    match window.accept_head(wid, pruned, later) {
        Ok(_) => {}
        Err(_) => unreachable!("expired heads should be pruned"),
    }
    println!("  after ttl expiry the head window accepts new insertions");
}

fn head_record(id: usize, accept_ts: AcceptInstant) -> HeadRecord {
    HeadRecord::new(
        [id as u8; 32],
        [0xA1; 32],
        [0xB2; 32],
        [0xC3; 32],
        [0xD4; 32],
        [0xE5; 32],
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        id as u64,
        accept_ts,
    )
}
