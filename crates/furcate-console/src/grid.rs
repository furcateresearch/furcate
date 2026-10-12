//! The whole machine at once.
//!
//! The first version put a rail of seven sections down the left and showed one
//! of them at a time. That is a good shape for a thing with deep sections and a
//! bad one for a machine: an operator asking "is this all right" had to visit
//! seven screens to find out, and the fault they were looking for was on
//! whichever one they checked last. Most of the display was empty while they
//! did it.
//!
//! So the home screen is every section at once, in as many columns as the
//! terminal has room for, and the sections keep their own screens for when
//! somebody wants the detail. Nothing is hidden behind a keystroke that a
//! glance should have answered.
//!
//! ## Panels are laid out, not positioned
//!
//! Column count comes from the width. A panel is a fixed number of columns
//! wide, so on a narrow terminal there are fewer per row rather than narrower
//! ones — a table that reflows its columns is a table an operator has to re-read
//! from the start every time the window changes.

use crate::style::{self, State};

/// One panel: a heading, a state, and a few lines.
pub struct Panel {
    pub title: String,
    pub state: State,
    pub rows: Vec<(String, String)>,
}

/// How wide one panel is, including the gap after it.
const PANEL: usize = 26;
const GAP: usize = 2;

/// How many fit, given the terminal.
///
/// At least one, so a very narrow terminal still shows the machine rather than
/// nothing. Capped at four because past that the eye stops reading it as a set
/// of panels and starts reading it as a wall.
/// How wide the laid-out block actually is.
///
/// Panels are a fixed width on purpose, so the number that fits changes with
/// the terminal and the panels themselves do not. That leaves a remainder: at
/// 120 columns four panels occupy 110 and ten are left over. The chrome above
/// and below has to know that, or it draws a rule the width of the terminal
/// under a block the width of the grid, and the overhang reads as drift.
/// Never wider than the terminal. `columns` keeps at least one panel so a very
/// narrow terminal still shows the machine rather than nothing, and one panel
/// is 26 columns — wider than a 24-column terminal. The panel overflowing is a
/// deliberate choice about content; the chrome following it over the edge would
/// just be a rule that wraps.
pub fn content_width(width: usize) -> usize {
    let c = columns(width);
    (c * PANEL + c.saturating_sub(1) * GAP).min(width)
}

pub fn columns(width: usize) -> usize {
    ((width + GAP) / (PANEL + GAP)).clamp(1, 4)
}

/// Lay panels out into rows of columns.
pub fn render(panels: &[Panel], width: usize) -> Vec<String> {
    let cols = columns(width);
    let mut out = Vec::new();

    for chunk in panels.chunks(cols) {
        // The heading row: a filled bar per panel, so a section reads as a
        // surface rather than as a line of text that happens to be bold.
        let mut heads = Vec::new();
        for p in chunk {
            let label = format!(" {} {} ", style::mark_plain(p.state), p.title.to_uppercase());
            let pad = PANEL.saturating_sub(label.chars().count());
            heads.push(format!(
                "{}{}",
                style::bar(&label, p.state),
                " ".repeat(pad)
            ));
        }
        out.push(heads.join(&" ".repeat(GAP)));
        // A heading sitting directly on its first value reads as one block of
        // text, and the eye has to find where the panel starts. One line of air
        // is what makes a heading a heading rather than a coloured first row.
        out.push(String::new());

        // The tallest panel decides the block height; shorter ones are padded
        // so the next row of headings lines up. A ragged grid reads as a
        // rendering fault.
        let tall = chunk.iter().map(|p| p.rows.len()).max().unwrap_or(0);
        for i in 0..tall {
            let mut cells = Vec::new();
            for p in chunk {
                cells.push(match p.rows.get(i) {
                    Some((k, v)) => cell(k, v),
                    None => " ".repeat(PANEL),
                });
            }
            out.push(cells.join(&" ".repeat(GAP)));
        }
        out.push(String::new());
    }
    // The trailing blank belongs between panels, not at the end of the screen.
    out.pop();
    out
}

/// One key/value line inside a panel, padded to the panel's width.
///
/// The label is left, the value is right, and the space between them is what
/// makes a column of values scannable — the eye follows the right edge rather
/// than hunting along each line.
fn cell(k: &str, v: &str) -> String {
    let kw = style::visible_len(k);
    let vw = style::visible_len(v);
    let inner = PANEL.saturating_sub(1);
    if kw + vw + 1 > inner {
        // No room for both: the value wins, because the label is already known
        // from the panel it is in.
        let cut = style::truncate(v, inner.saturating_sub(1));
        return format!(" {}{}", " ".repeat(inner.saturating_sub(style::visible_len(&cut) + 1)), cut);
    }
    format!(" {}{}{}", style::dim(k), " ".repeat(inner - kw - vw), v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(title: &str, n: usize) -> Panel {
        Panel {
            title: title.into(),
            state: State::Ok,
            rows: (0..n).map(|i| (format!("k{i}"), format!("v{i}"))).collect(),
        }
    }

    #[test]
    fn the_chrome_can_be_drawn_to_the_block_and_not_the_terminal() {
        // The overhang this exists to prevent: at 120 columns four panels
        // occupy 110, and a rule drawn to 120 hangs ten columns past them.
        assert_eq!(columns(120), 4);
        assert_eq!(content_width(120), 110);
        assert_eq!(content_width(80), 54);
        // Never wider than the terminal it is drawn in.
        for w in [24usize, 40, 54, 80, 100, 120] {
            assert!(content_width(w) <= w, "content_width({w}) exceeded the terminal");
        }
    }

    #[test]
    fn a_narrow_terminal_gets_fewer_panels_not_narrower_ones() {
        // A table that reflows its columns is one an operator has to re-read
        // from the start every time the window changes.
        assert_eq!(columns(80), 2);
        assert_eq!(columns(120), 4);
        assert_eq!(columns(40), 1);
        assert_eq!(columns(10), 1, "never zero: a narrow screen still shows the machine");
    }

    #[test]
    fn every_line_of_a_row_is_the_same_width() {
        // A ragged grid reads as a rendering fault rather than as data.
        let panels = vec![p("power", 3), p("thermal", 5)];
        let out = render(&panels, 80);
        let widths: Vec<usize> = out
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| style::visible_len(l))
            .collect();
        let first = widths[0];
        assert!(widths.iter().all(|w| *w == first), "widths differ: {widths:?}");
    }

    #[test]
    fn a_short_panel_is_padded_so_the_next_heading_lines_up() {
        let panels = vec![p("a", 1), p("b", 4)];
        let out = render(&panels, 80);
        // heading + the blank under it + 4 rows for the tallest
        assert_eq!(out.len(), 6, "{out:#?}");
    }

    #[test]
    fn panels_wrap_onto_further_rows_rather_than_being_dropped() {
        // Every section must appear. A machine's fault is on whichever panel
        // did not fit.
        let panels: Vec<Panel> = (0..7).map(|i| p(&format!("p{i}"), 2)).collect();
        let out = render(&panels, 80); // two columns
        let headings = out.iter().filter(|l| l.contains("P0") || l.contains("P6")).count();
        assert!(headings >= 2, "first and last panel must both be drawn");
    }

    #[test]
    fn a_heading_is_never_flush_against_its_first_value() {
        // Without the blank the heading reads as a coloured first row and the
        // eye has to find where the panel starts.
        let out = render(&[p("a", 3)], 80);
        assert!(out[0].contains('A'), "row 0 is the heading: {:?}", out[0]);
        assert!(out[1].trim().is_empty(), "row 1 must be air: {:?}", out[1]);
        assert!(!out[2].trim().is_empty(), "row 2 is the first value: {:?}", out[2]);
    }

    #[test]
    fn a_value_too_long_for_its_panel_keeps_the_value() {
        // The label is already known from the panel it sits in; the value is
        // the thing being read.
        let panels = vec![Panel {
            title: "x".into(),
            state: State::Ok,
            rows: vec![("label".into(), "a-very-long-value-that-will-not-fit-at-all".into())],
        }];
        let out = render(&panels, 40);
        assert!(out[2].contains('…'), "a cut value should look cut: {:?}", out[2]);
    }
}
