//! Reading the uninterruptible supply.
//!
//! The supply is attached to one machine running NUT's `upsd`; every node asks
//! it over the overlay with the NUT text protocol (see
//! `furcate_power::supply::ups`). No NUT software is needed on a node.
//!
//! A machine with no `/etc/furcate/ups.json` has no supply configured and says
//! so. A file that is wrong, or a daemon that does not answer, is reported as
//! exactly that and never as "on line": the ladder holds its rung on a state it
//! cannot read, and `power::loop` keeps counting time on battery if the last
//! thing it heard was that mains had failed.

use furcate_power::ladder::{PowerState, Triggers, UpsObservation};
use furcate_power::supply::ups::{self as nut, Configured, Mains, UpsReading, UpsSource};

/// What the supply is telling us, if anything.
#[derive(Clone, Debug, PartialEq)]
pub enum Reading {
    /// No supply is configured on this machine.
    Absent,
    /// The configuration is wrong; the reason.
    Invalid(String),
    /// A supply is configured and answered.
    Measured(UpsReading),
    /// A supply is configured and did not answer; the reason.
    NotMeasured(String),
}

impl Reading {
    /// Mains as far as a measured reading goes. Unknown flags are not a state.
    pub fn state(&self) -> Option<PowerState> {
        match self {
            Reading::Measured(r) => match r.mains {
                Mains::OnLine => Some(PowerState::OnLine),
                Mains::OnBattery => Some(PowerState::OnBattery),
                Mains::Unknown => None,
            },
            _ => None,
        }
    }

    /// The reading as the debounce counts it. `None` for a machine with no
    /// supply configured, which has nothing to count.
    pub fn sample(&self) -> Option<furcate_power::confirm::Sample> {
        use furcate_power::confirm::Sample;
        match self {
            Reading::Absent => None,
            Reading::Invalid(_) | Reading::NotMeasured(_) => Some(Sample::Failed),
            Reading::Measured(r) => Some(match r.mains {
                Mains::OnLine => Sample::OnLine,
                Mains::OnBattery => Sample::OnBattery,
                Mains::Unknown => Sample::Unknown,
            }),
        }
    }

    pub fn mains(&self) -> Option<Mains> {
        match self {
            Reading::Measured(r) => Some(r.mains),
            _ => None,
        }
    }

    /// The figures the ladder uses alongside the confirmed state.
    pub fn observation(&self) -> UpsObservation {
        match self {
            Reading::Measured(r) => UpsObservation {
                state: self.state(),
                charge_pct: r.charge_pct.as_ref().map(|f| f.value),
                runtime_left: r.runtime_secs.as_ref().map(|f| f.value),
            },
            _ => UpsObservation { state: None, charge_pct: None, runtime_left: None },
        }
    }

    pub fn low_flag(&self) -> bool {
        matches!(self, Reading::Measured(r) if r.low_battery_flag)
    }

    pub fn to_json(&self, now: u64) -> serde_json::Value {
        match self {
            Reading::Absent => serde_json::json!({"present": false}),
            Reading::Invalid(why) => serde_json::json!({"present": true, "measured": false, "why": format!("configuration invalid: {why}")}),
            Reading::NotMeasured(why) => UpsSource::NotMeasured(why.clone()).to_json(now),
            Reading::Measured(r) => UpsSource::Measured(r.clone()).to_json(now),
        }
    }
}

/// One pass: the reading and the thresholds the ladder is to use with it.
pub struct Pass {
    pub reading: Reading,
    pub triggers: Triggers,
}

pub fn read(now: u64) -> Pass {
    read_with(std::path::Path::new(nut::CONFIG_PATH), now)
}

pub fn read_with(path: &std::path::Path, now: u64) -> Pass {
    let none = |reading| Pass { reading, triggers: Triggers::default() };
    match nut::load_config(path) {
        Configured::None => none(Reading::Absent),
        Configured::Invalid(why) => none(Reading::Invalid(why)),
        Configured::Some(cfg) => {
            let dir = std::env::var_os("CREDENTIALS_DIRECTORY").map(std::path::PathBuf::from);
            let reading = match nut::fetch(&cfg, dir.as_deref(), now) {
                UpsSource::Measured(r) => Reading::Measured(r),
                UpsSource::NotMeasured(why) => Reading::NotMeasured(why),
            };
            Pass { reading, triggers: cfg.triggers }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_configuration_is_no_supply_and_a_bad_one_is_not() {
        let p = std::env::temp_dir().join(format!("furcated-ups-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        assert_eq!(read_with(&p, 1).reading, Reading::Absent);
        std::fs::write(&p, "nonsense").unwrap();
        assert!(matches!(read_with(&p, 1).reading, Reading::Invalid(_)));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn an_unreachable_supply_is_not_on_line() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let p = std::env::temp_dir().join(format!("furcated-ups-dead-{}", std::process::id()));
        std::fs::write(&p, format!(r#"{{"source":{{"host":"127.0.0.1","port":{port},"ups":"u"}}}}"#)).unwrap();
        let r = read_with(&p, 1).reading;
        assert!(matches!(r, Reading::NotMeasured(_)));
        assert_eq!(r.state(), None);
        assert_eq!(r.observation().state, None, "an unreadable supply tells the ladder nothing");
        assert_eq!(r.sample(), Some(furcate_power::confirm::Sample::Failed));
        let _ = std::fs::remove_file(&p);
    }
}
