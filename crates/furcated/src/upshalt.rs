//! The halt sequence's two collaborators in the daemon: the actuator it asks
//! (the privileged helper, one intent at a time, each answered by nonce) and
//! the ledger it writes (the daemon's own chain, persisted after every line so
//! the record survives the power-off that follows).

use crate::{actuate, now_ms, Agent};
use furcate_ledger::OpKind;
use furcate_power::halt::{Actuator, Ledger, StepResult, StopUnit};
use std::sync::{Arc, Mutex};

pub struct AgentLedger {
    pub agent: Arc<Mutex<Agent>>,
    pub host: String,
}

impl Ledger for AgentLedger {
    fn record(&mut self, line: String) {
        eprintln!("furcated: halt: {line}");
        if let Ok(mut a) = self.agent.lock() {
            a.chain.append(now_ms(), OpKind::Power, "halt", self.host.clone(), line);
            a.persist_chain();
        }
    }
}

pub struct Real;

fn wait_for(nonce: &str, secs: u64) -> Result<serde_json::Value, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(v) = actuate::confirm(nonce) {
            return Ok(v);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("the actuator did not answer within {secs}s"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn read_step(v: &serde_json::Value) -> StepResult {
    if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        return StepResult::Failed(v.get("why").and_then(|x| x.as_str()).unwrap_or("refused").to_string());
    }
    let secs = v.get("elapsed").and_then(|x| x.as_u64()).unwrap_or(0);
    if v.get("killed").and_then(|x| x.as_bool()) == Some(true) {
        StepResult::Killed { after_secs: secs }
    } else if v.get("timed_out").and_then(|x| x.as_bool()) == Some(true) {
        StepResult::TimedOut { secs }
    } else {
        StepResult::Stopped { secs }
    }
}

impl Actuator for Real {
    fn stop(&mut self, u: &StopUnit) -> StepResult {
        let nonce = format!("stop-{}-{}", u.name, now_ms());
        if let Err(e) = actuate::write_body(&actuate::render_stop_unit(&u.name, &nonce)) {
            return StepResult::Failed(format!("intent not written: {e}"));
        }
        match wait_for(&nonce, u.window() + 60) {
            Ok(v) => read_step(&v),
            Err(e) => StepResult::Failed(e),
        }
    }

    fn start(&mut self, u: &StopUnit) -> StepResult {
        let nonce = format!("start-{}-{}", u.name, now_ms());
        if let Err(e) = actuate::write_body(&actuate::render_restart("unit", &u.name, &nonce)) {
            return StepResult::Failed(format!("intent not written: {e}"));
        }
        match wait_for(&nonce, 120) {
            Ok(v) => read_step(&v),
            Err(e) => StepResult::Failed(e),
        }
    }

    fn finish(&mut self) -> Result<(), String> {
        let nonce = format!("poweroff-{}", now_ms());
        actuate::write_poweroff(&nonce).map_err(|e| format!("intent not written: {e}"))?;
        let v = wait_for(&nonce, 90)?;
        if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
            Ok(())
        } else {
            Err(v.get("why").and_then(|x| x.as_str()).unwrap_or("refused").to_string())
        }
    }
}
