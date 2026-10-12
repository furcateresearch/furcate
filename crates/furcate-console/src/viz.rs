//! Drawing numbers, in a character grid.
//!
//! A bar is read at a glance and a number has to be compared against something
//! remembered. Both are shown: the bar answers "is this a lot" and the figure
//! answers "how much", and an operator needs the first far more often than the
//! second.
//!
//! ## Sub-cell resolution
//!
//! The eighth-blocks — `▏▎▍▌▋▊▉█` — give eight positions per column, so a
//! sixteen-column meter has 128 steps rather than 16. On an 80-column terminal
//! that is the difference between a bar that moves when the machine does and
//! one that jumps between the same four positions all day.
//!
//! ## What is deliberately absent
//!
//! No colour gradient along the bar. Colour here means what it means everywhere
//! else — measured, warning, fault — and a bar that shaded from amber to red as
//! it filled would be a fourth meaning for colour and would make a half-full
//! meter look like a fault.

use crate::style;

/// The eighth-blocks, in order. Index 0 is empty.
const EIGHTHS: [&str; 9] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];

/// A horizontal meter, filled to `frac` of `width` columns.
///
/// The unfilled part is drawn rather than left blank, so the meter has a length
/// an operator can judge against. A bar floating in space says how much without
/// saying out of what.
pub fn meter(frac: f64, width: usize) -> String {
    let frac = frac.clamp(0.0, 1.0);
    let eighths = (frac * width as f64 * 8.0).round() as usize;
    let full = eighths / 8;
    let rest = eighths % 8;

    let mut bar = "█".repeat(full.min(width));
    if full < width && rest > 0 {
        bar.push_str(EIGHTHS[rest]);
    }
    let drawn = full + usize::from(full < width && rest > 0);
    let track = "·".repeat(width.saturating_sub(drawn));

    // Past four fifths is where an operator has to think about it. The
    // threshold is on the bar rather than in a legend because that is where
    // they are looking.
    let filled = if frac > 0.8 { style::warn(&bar) } else { style::measured(&bar) };
    format!("{filled}{}", style::dim(&track))
}

/// A meter with its figure, right-aligned so a column of them lines up.
pub fn gauge(value: f64, max: f64, unit: &str, width: usize) -> String {
    if max <= 0.0 {
        // No denominator is not zero headroom — it is an undeclared rating, and
        // a full bar would be a lie about a machine nobody has measured.
        return format!("{} {}", style::dim(&"·".repeat(width)), style::dim("no rating"));
    }
    let frac = value / max;
    format!(
        "{} {}{}",
        meter(frac, width),
        style::measured(&format!("{value:.0}")),
        style::dim(&format!("/{max:.0}{unit}"))
    )
}

/// A sparkline: one column per sample.
///
/// For rails that move — draw, temperature, block height. The shape is the
/// point; the axis is deliberately absent, because a sparkline that needed a
/// scale would be a chart and a chart does not belong on a status pane.
pub fn spark(values: &[f64], width: usize) -> String {
    const BARS: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    if values.is_empty() {
        return style::dim(&"·".repeat(width));
    }
    // The most recent `width` samples: a sparkline showing the oldest data it
    // has is a sparkline that stops reacting to the machine.
    let start = values.len().saturating_sub(width);
    let v = &values[start..];

    let lo = v.iter().cloned().fold(f64::INFINITY, f64::min);
    let hi = v.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let span = hi - lo;

    let line: String = v
        .iter()
        .map(|x| {
            // A flat series sits in the middle rather than at the bottom: a row
            // of empty bars reads as "nothing is happening" when what is
            // happening is that nothing is changing.
            let i = if span <= f64::EPSILON {
                3
            } else {
                (((x - lo) / span) * 7.0).round() as usize
            };
            BARS[i.min(7)]
        })
        .collect();

    let pad = width.saturating_sub(v.len());
    format!("{}{}", style::dim(&"·".repeat(pad)), style::measured(&line))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut c = s.chars();
        while let Some(ch) = c.next() {
            if ch == '\x1b' {
                for ch in c.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn a_meter_is_always_exactly_its_width() {
        // A bar that changes length as the value changes makes the column next
        // to it move, and a layout that moves is one an operator re-reads.
        for f in [0.0, 0.01, 0.33, 0.5, 0.999, 1.0, 2.0, -1.0] {
            let w = plain(&meter(f, 20)).chars().count();
            assert_eq!(w, 20, "frac {f} gave {w} columns");
        }
    }

    #[test]
    fn sub_cell_resolution_actually_moves() {
        // Eight positions per column. Without it a sixteen-column meter has
        // sixteen states and sits in the same one all day.
        let a = plain(&meter(0.500, 16));
        let b = plain(&meter(0.508, 16));
        assert_ne!(a, b, "an eighth of a column should be visible");
    }

    #[test]
    fn an_empty_meter_still_shows_its_length() {
        // A bar floating in space says how much without saying out of what.
        let m = plain(&meter(0.0, 10));
        assert_eq!(m.chars().count(), 10);
        assert!(m.chars().all(|c| c == '·'));
    }

    #[test]
    fn an_undeclared_rating_is_not_drawn_as_headroom() {
        // No denominator is not zero usage, and a full or empty bar would both
        // be claims about a machine nobody has measured.
        let g = plain(&gauge(120.0, 0.0, " W", 10));
        assert!(g.contains("no rating"), "{g}");
        assert!(!g.contains('█'), "an unrated domain must not draw a bar: {g}");
    }

    #[test]
    fn a_flat_series_sits_in_the_middle_not_the_floor() {
        // A row of empty bars reads as "nothing is happening" when what is
        // happening is that nothing is changing.
        let s = plain(&spark(&[5.0; 8], 8));
        assert!(!s.contains('▁'), "a flat line should not read as zero: {s}");
    }

    #[test]
    fn a_sparkline_shows_the_newest_samples() {
        // Showing the oldest data it has is a sparkline that has stopped
        // reacting to the machine.
        let mut v: Vec<f64> = (0..40).map(|i| i as f64).collect();
        let a = plain(&spark(&v, 8));
        v.push(1000.0);
        let b = plain(&spark(&v, 8));
        assert_ne!(a, b, "a new sample must change the line");
    }

    #[test]
    fn a_short_series_is_padded_rather_than_stretched() {
        let s = plain(&spark(&[1.0, 2.0, 3.0], 10));
        assert_eq!(s.chars().count(), 10);
        assert!(s.starts_with('·'), "missing history reads as absent, not as zero: {s}");
    }

    #[test]
    fn nothing_here_panics_on_the_values_a_machine_actually_produces() {
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -0.0] {
            let _ = meter(v, 8);
            let _ = gauge(v, 100.0, " W", 8);
            let _ = spark(&[v, 1.0, v], 8);
        }
    }
}
