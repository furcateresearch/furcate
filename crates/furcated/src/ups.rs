//! Reading the uninterruptible supply.
//!
//! NUT is the framework, and its `genericups` driver exists precisely for
//! supplies with no smart interface — contact-closure signalling giving three
//! facts: on line, on battery, low battery. That is enough to drive the whole
//! ladder, which matters because that is exactly what this site has.
//!
//! Absence of a supply is not an error. A machine with no UPS is a machine
//! that will simply lose power without warning, and the correct behaviour is
//! to report that honestly rather than to pretend it is on line.

use furcate_power::PowerState;

/// What the supply is telling us, if anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// A supply is present and reporting.
    Present {
        state: PowerState,
        /// Estimated runtime in seconds, where the supply provides it. A
        /// contact-closure supply does not.
        runtime_left: Option<u64>,
        charge_pct: Option<u64>,
    },
    /// No supply is configured on this machine.
    Absent,
}

impl Reading {
    pub fn state(&self) -> Option<PowerState> {
        match self {
            Reading::Present { state, .. } => Some(*state),
            Reading::Absent => None,
        }
    }
}

/// Map NUT's status flags onto the ladder's three states.
///
/// Flags are checked worst-first: a supply reporting both `OB` and `LB` is
/// low, and treating it as merely on-battery would skip the halt rung.
pub fn parse_status(status: &str) -> PowerState {
    let flags: Vec<&str> = status.split_whitespace().collect();
    if flags.contains(&"LB") {
        PowerState::LowBattery
    } else if flags.contains(&"OB") {
        PowerState::OnBattery
    } else {
        PowerState::OnLine
    }
}

fn field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
}

/// Query a UPS through `upsc`.
pub fn read(ups: &str) -> Reading {
    let Ok(out) = std::process::Command::new("upsc").arg(ups).output() else {
        return Reading::Absent;
    };
    if !out.status.success() {
        return Reading::Absent;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(status) = field(&text, "ups.status") else {
        return Reading::Absent;
    };
    Reading::Present {
        state: parse_status(&status),
        runtime_left: field(&text, "battery.runtime").and_then(|v| v.parse().ok()),
        charge_pct: field(&text, "battery.charge").and_then(|v| v.parse().ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_line_is_the_normal_case() {
        assert_eq!(parse_status("OL"), PowerState::OnLine);
        assert_eq!(parse_status("OL CHRG"), PowerState::OnLine);
    }

    #[test]
    fn on_battery_is_recognised() {
        assert_eq!(parse_status("OB"), PowerState::OnBattery);
        assert_eq!(parse_status("OB DISCHRG"), PowerState::OnBattery);
    }

    #[test]
    fn low_battery_wins_over_on_battery() {
        // Treating a supply reporting both as merely on-battery would skip
        // the halt rung.
        assert_eq!(parse_status("OB LB"), PowerState::LowBattery);
        assert_eq!(parse_status("LB OB DISCHRG"), PowerState::LowBattery);
    }

    #[test]
    fn an_unknown_status_is_treated_as_on_line() {
        // Erring toward on-line avoids a spurious shutdown from a status
        // string we do not recognise.
        assert_eq!(parse_status("SOMETHING ELSE"), PowerState::OnLine);
    }

    #[test]
    fn fields_are_parsed_from_upsc_output() {
        let text = "battery.charge: 100\nbattery.runtime: 1440\nups.status: OL\n";
        assert_eq!(field(text, "ups.status").as_deref(), Some("OL"));
        assert_eq!(field(text, "battery.runtime").as_deref(), Some("1440"));
    }

    #[test]
    fn a_missing_supply_reports_absent_rather_than_on_line() {
        // A machine with no UPS will lose power without warning; saying it is
        // on line would be a false statement about its resilience.
        assert_eq!(read("definitely-not-a-ups"), Reading::Absent);
        assert_eq!(Reading::Absent.state(), None);
    }
}
