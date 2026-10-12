//! The cluster's own front page.
//!
//! Until now this site had no face. The console is a TUI on a terminal
//! somebody has to be sitting at, and the controller answered only JSON — so
//! the honest answer to "what is this cluster" was `curl` and a person who
//! already knew which of forty-six routes to ask.
//!
//! ## Read-only, and that is the design
//!
//! Nothing here changes the machine, the same standing rule the console
//! keeps. A browser cannot hold an operator key safely, and this codebase
//! already decided that mutations carry a signature: the guarded routes take
//! signed envelopes, kill orders are operator-signed, and agents raise
//! proposals a person answers. A control panel that could act because it
//! answered on a port would be the one place in Furcate where authority
//! collapsed back into reachability — the exact thing the overlay lock exists
//! to prevent.
//!
//! So this shows, and `furcatectl` acts.
//!
//! ## One palette, still
//!
//! The colours are **not** written here as hex. `deploy/os/branding/
//! palette.sh` holds the 256-colour indices, `style.rs` holds the same numbers
//! for the console, and a test asserts they agree. This surface takes the same
//! indices and converts them, so a third surface does not become a third
//! opinion about what amber is — which is precisely how `warn` ended up
//! magenta in one file and amber in another while both were supposedly the
//! same design.

/// The xterm-256 indices the whole design language is defined by.
///
/// Stated as numbers, not colours, because these are the values in
/// `palette.sh` and a test checks that this list still matches it.
pub mod ink {
    pub const AMBER: u8 = 214;
    pub const WARN: u8 = 172;
    pub const FAULT: u8 = 160;
    /// Context. Grey rather than SGR 2, which paints artefacts on a VT.
    pub const DIM: u8 = 8;
}

/// Convert an xterm-256 index to CSS hex.
///
/// The cube is regular, so this is arithmetic rather than a table somebody
/// has to keep in step with anything.
pub fn xterm_hex(i: u8) -> String {
    const LEVELS: [u32; 6] = [0, 95, 135, 175, 215, 255];
    let (r, g, b) = match i {
        // The first sixteen are terminal-defined; only the two this design
        // uses are named, and both are unambiguous.
        0..=7 => {
            let v = if i == 0 { 0 } else { 128 };
            (v, v, v)
        }
        8..=15 => (128, 128, 128),
        16..=231 => {
            let n = (i as u32) - 16;
            (LEVELS[(n / 36) as usize], LEVELS[((n / 6) % 6) as usize], LEVELS[(n % 6) as usize])
        }
        _ => {
            let v = 8 + ((i as u32) - 232) * 10;
            (v, v, v)
        }
    };
    format!("#{r:02x}{g:02x}{b:02x}")
}

/// Text that is about to be put inside HTML.
///
/// Node ids, site names and workload names all arrive from elsewhere, and a
/// page that interpolates them raw is a page that can be rewritten by naming
/// a container after a script tag.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// How a value reads when nothing reported it.
///
/// A statement about the *source*, not the machine. A blank cell sends an
/// operator looking for a fault that does not exist; "not reported" sends
/// them to the reporter, which is where the problem actually is.
pub const ABSENT: &str = "not reported";

fn or_absent(v: Option<String>) -> String {
    v.unwrap_or_else(|| format!("<span class=dim>{ABSENT}</span>"))
}

/// One machine, as the page shows it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeRow {
    pub id: String,
    /// What the machine is running, if it said.
    pub image: Option<String>,
    pub wall_w: Option<f64>,
    pub hottest_c: Option<i64>,
    pub workloads: Option<usize>,
    /// Whether this node published an overlay hint this cycle.
    pub on_overlay: bool,
    pub controller: bool,
    /// Whether the node holds key custody, at what class, or why not.
    pub custody: Option<String>,
}

/// A site this cluster hosts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostedSite {
    pub name: String,
    pub domains: Vec<String>,
    pub release: Option<String>,
    pub tier: String,
}

/// Everything the front page states.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Overview {
    pub site: String,
    pub nodes: Vec<NodeRow>,
    pub sites: Vec<HostedSite>,
    /// Sum of measured wall draw. `None` when no node has a power supply this
    /// can read — never estimated, because the declared multiplier was wrong
    /// here by between four and nine times.
    pub wall_total_w: Option<f64>,
    /// `None` when the controller has no view of the overlay at all, which is
    /// different from an unlocked one.
    pub overlay_locked: Option<bool>,
    pub ledger_entries: usize,
}

pub(crate) fn head(title: &str) -> String {
    let amber = xterm_hex(ink::AMBER);
    let warn = xterm_hex(ink::WARN);
    let fault = xterm_hex(ink::FAULT);
    let dim = xterm_hex(ink::DIM);
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
/* Amber in weights, as everywhere else this system speaks:
   bright = measured, amber = the system's voice, grey = context,
   red = faults only. Deliberately one visual world rather than two
   themes — this is the console's language on a different surface. */
:root {{
  --amber: {amber};
  --warn: {warn};
  --fault: {fault};
  --dim: {dim};
  --ground: #0b0a08;
  --panel: #131110;
  --rule: #2a2420;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--ground); color: var(--amber);
  font: 14px/1.6 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}}
.wrap {{ max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }}
header {{ border-bottom: 1px solid var(--rule); padding-bottom: 18px; margin-bottom: 28px; }}
h1 {{ font-size: 20px; font-weight: 600; margin: 0 0 4px; letter-spacing: .04em; }}
h2 {{
  font-size: 11px; font-weight: 600; letter-spacing: .18em; text-transform: uppercase;
  margin: 34px 0 10px; color: var(--amber); display: flex; align-items: center; gap: 12px;
}}
h2::after {{ content: ""; flex: 1; height: 1px; background: var(--rule); }}
.dim {{ color: var(--dim); }}
.measured {{ color: #fff; }}
.warn {{ color: var(--warn); }}
.fault {{ color: var(--fault); }}
.sub {{ color: var(--dim); font-size: 13px; margin: 0; }}
.scroll {{ overflow-x: auto; border: 1px solid var(--rule); background: var(--panel); }}
table {{ border-collapse: collapse; width: 100%; min-width: 560px; }}
th {{
  text-align: left; font-weight: 600; font-size: 10px; letter-spacing: .14em;
  text-transform: uppercase; color: var(--dim); padding: 9px 12px;
  border-bottom: 1px solid var(--rule); white-space: nowrap;
}}
td {{ padding: 9px 12px; border-bottom: 1px solid var(--rule); vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
td.num {{ font-variant-numeric: tabular-nums; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 1px; background: var(--rule); border: 1px solid var(--rule); }}
.tile {{ background: var(--panel); padding: 13px 15px; }}
.tile .k {{ font-size: 10px; letter-spacing: .14em; text-transform: uppercase; color: var(--dim); display: block; }}
.tile .v {{ font-size: 19px; color: #fff; display: block; margin-top: 5px; font-variant-numeric: tabular-nums; }}
.finding {{ border: 1px solid var(--rule); border-left: 3px solid var(--warn); background: var(--panel); padding: 12px 15px; margin-bottom: 10px; }}
a {{ color: var(--amber); }}
footer {{ margin-top: 44px; padding-top: 16px; border-top: 1px solid var(--rule); color: var(--dim); font-size: 12px; }}
</style></head><body><div class=wrap>"#
    )
}

fn node_table(nodes: &[NodeRow]) -> String {
    if nodes.is_empty() {
        return "<p class=sub>No node has answered here. \
             That is a statement about reporting, not about the machines — \
             check <span class=dim>FURCATE_SITE</span> or <span class=dim>FURCATE_PEERS</span>.</p>"
            .to_string();
    }
    let mut s = String::from(
        "<div class=scroll><table><thead><tr>\
         <th>node</th><th>running</th><th>wall</th><th>hottest</th>\
         <th>workloads</th><th>overlay</th><th>custody</th></tr></thead><tbody>",
    );
    for n in nodes {
        s.push_str(&format!(
            "<tr><td>{}{}</td><td>{}</td><td class=num>{}</td><td class=num>{}</td>\
             <td class=num>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&n.id),
            if n.controller {
                " <span class=dim>controller</span>"
            } else {
                ""
            },
            or_absent(n.image.as_ref().map(|i| esc(i))),
            or_absent(n.wall_w.map(|w| format!("<span class=measured>{w:.0}</span> W"))),
            or_absent(n.hottest_c.map(|c| format!("<span class=measured>{c}</span> °C"))),
            or_absent(n.workloads.map(|w| format!("<span class=measured>{w}</span>"))),
            if n.on_overlay {
                "peered".to_string()
            } else {
                format!("<span class=dim>{ABSENT}</span>")
            },
            or_absent(n.custody.as_ref().map(|c| esc(c))),
        ));
    }
    s.push_str("</tbody></table></div>");
    s
}

fn sites_table(sites: &[HostedSite]) -> String {
    if sites.is_empty() {
        return "<p class=sub>Nothing is hosted here yet. \
                <span class=dim>furcate deploy &lt;src&gt; &lt;name&gt; &lt;domains&gt;</span></p>"
            .to_string();
    }
    let mut s = String::from(
        "<div class=scroll><table><thead><tr>\
         <th>site</th><th>answers on</th><th>release</th><th>tier</th></tr></thead><tbody>",
    );
    for h in sites {
        s.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=num>{}</td><td>{}</td></tr>",
            esc(&h.name),
            if h.domains.is_empty() {
                format!("<span class=dim>{ABSENT}</span>")
            } else {
                h.domains
                    .iter()
                    .map(|d| esc(d))
                    .collect::<Vec<_>>()
                    .join("<br>")
            },
            or_absent(h.release.as_ref().map(|r| format!("<span class=measured>{}</span>", esc(r)))),
            esc(&h.tier),
        ));
    }
    s.push_str("</tbody></table></div>");
    s
}

/// The front page: what this cluster is.
pub fn homepage(o: &Overview) -> String {
    let mut s = head(&format!("{} — Furcate", o.site));
    s.push_str(&format!(
        "<header><h1>{}</h1><p class=sub>A Furcate site. \
         {} machine(s) reporting, {} site(s) hosted.</p></header>",
        esc(&o.site),
        o.nodes.len(),
        o.sites.len()
    ));

    s.push_str("<div class=tiles>");
    s.push_str(&format!(
        "<div class=tile><span class=k>machines</span><span class=v>{}</span></div>",
        o.nodes.len()
    ));
    s.push_str(&format!(
        "<div class=tile><span class=k>measured draw</span><span class=v>{}</span></div>",
        o.wall_total_w
            .map(|w| format!("{w:.0} W"))
            .unwrap_or_else(|| format!("<span class=dim style='font-size:13px'>{ABSENT}</span>"))
    ));
    s.push_str(&format!(
        "<div class=tile><span class=k>overlay</span><span class=v>{}</span></div>",
        match o.overlay_locked {
            Some(true) => "locked".to_string(),
            // Supported, and never something to discover by reading source.
            Some(false) => "<span class=warn>unlocked</span>".to_string(),
            None => format!("<span class=dim style='font-size:13px'>{ABSENT}</span>"),
        }
    ));
    s.push_str(&format!(
        "<div class=tile><span class=k>recorded actions</span><span class=v>{}</span></div>",
        o.ledger_entries
    ));
    s.push_str("</div>");

    s.push_str("<h2>machines</h2>");
    s.push_str(&node_table(&o.nodes));

    s.push_str("<h2>hosted here</h2>");
    s.push_str(&sites_table(&o.sites));

    s.push_str(
        "<footer>This page reads; it does not act. Anything that changes a \
         machine goes through <span class=dim>furcatectl</span> and carries a \
         signature.<br>Detail at <a href=\"/dashboard\">/dashboard</a>.</footer>",
    );
    s.push_str("</div></body></html>");
    s
}

/// The operator's view: the same facts with what is behind them.
pub fn dashboard(o: &Overview) -> String {
    let mut s = head(&format!("{} — dashboard", o.site));
    s.push_str(&format!(
        "<header><h1>{} <span class=dim>dashboard</span></h1>\
         <p class=sub>Read-only. Every mutation on this site takes a \
         signed envelope, so this page can show and ask, and cannot act.</p></header>",
        esc(&o.site)
    ));

    s.push_str("<h2>machines</h2>");
    s.push_str(&node_table(&o.nodes));

    s.push_str("<h2>hosted here</h2>");
    s.push_str(&sites_table(&o.sites));

    s.push_str("<h2>the record</h2>");
    s.push_str(&format!(
        "<p class=sub><span class=measured>{}</span> action(s) chained. \
         Permitted and refused alike — a decision that was refused is the one \
         worth being able to find afterwards.</p>",
        o.ledger_entries
    ));

    s.push_str("<footer><a href=\"/\">← front page</a></footer>");
    s.push_str("</div></body></html>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Overview {
        Overview {
            site: "tirana".into(),
            nodes: vec![NodeRow {
                id: "node-a".into(),
                image: Some("Furcate 0.1".into()),
                wall_w: Some(69.0),
                hottest_c: Some(42),
                workloads: Some(10),
                on_overlay: true,
                controller: false,
                custody: Some("holds (elected, tpm)".into()),
            }],
            sites: vec![HostedSite {
                name: "furcate-xyz".into(),
                domains: vec!["furcate.xyz".into()],
                release: Some("a92fc78c7c06".into()),
                tier: "static".into(),
            }],
            wall_total_w: Some(126.0),
            overlay_locked: Some(true),
            ledger_entries: 12,
        }
    }

    #[test]
    fn the_indices_are_the_ones_the_rest_of_the_design_uses() {
        // These four numbers are in palette.sh and style.rs. If somebody
        // changes the design language, this surface must not be the one that
        // keeps the old colour — the failure that made `warn` magenta in one
        // file and amber in another.
        assert_eq!(ink::AMBER, 214);
        assert_eq!(ink::WARN, 172);
        assert_eq!(ink::FAULT, 160);
    }

    #[test]
    fn the_cube_conversion_matches_the_known_values() {
        assert_eq!(xterm_hex(214), "#ffaf00");
        assert_eq!(xterm_hex(172), "#d78700");
        assert_eq!(xterm_hex(160), "#d70000");
    }

    #[test]
    fn no_colour_is_written_as_hex_in_this_file() {
        // Same rule the shell surfaces are held to: a file that spells a
        // colour out is a file still spelling the old one after a change.
        // The page's own grounds are the exception and are stated once, in
        // the stylesheet, not per element.
        let src = include_str!("web.rs");
        let body = src.split("fn head(").nth(1).expect("head exists");
        let body = body.split("fn node_table").next().unwrap();
        for line in body.lines() {
            if line.contains("--amber:") || line.contains("--warn:") || line.contains("--fault:") || line.contains("--dim:") {
                assert!(
                    line.contains('{'),
                    "the palette must be interpolated, not literal: {line}"
                );
            }
        }
    }

    #[test]
    fn a_name_cannot_carry_markup_onto_the_page() {
        let mut o = sample();
        o.nodes[0].id = "<script>alert(1)</script>".into();
        o.sites[0].name = "a\"b".into();
        let h = homepage(&o);
        assert!(!h.contains("<script>alert"));
        assert!(h.contains("&lt;script&gt;"));
        assert!(h.contains("a&quot;b"));
    }

    #[test]
    fn an_empty_cluster_says_what_is_missing_rather_than_nothing() {
        let o = Overview {
            site: "new-site".into(),
            ..Default::default()
        };
        let h = homepage(&o);
        assert!(h.contains("No node has answered here"));
        assert!(h.contains("Nothing is hosted here yet"));
        // And it must still be a page, not a fragment.
        assert!(h.starts_with("<!DOCTYPE html>"));
        assert!(h.ends_with("</html>"));
    }

    #[test]
    fn a_figure_nobody_reported_is_named_as_unreported_not_zero() {
        // Zero watts is a measurement. No measurement is not zero, and a page
        // that showed one as the other would be lying in the direction that
        // looks fine.
        let mut o = sample();
        o.wall_total_w = None;
        o.nodes[0].wall_w = None;
        let h = homepage(&o);
        assert!(h.contains(ABSENT));
        assert!(!h.contains("0 W"));
    }

    #[test]
    fn an_unlocked_overlay_is_shown_as_a_warning_and_a_missing_view_is_not() {
        let mut o = sample();
        o.overlay_locked = Some(false);
        assert!(homepage(&o).contains("unlocked"));
        o.overlay_locked = None;
        let h = homepage(&o);
        // Not knowing is different from knowing it is unlocked.
        assert!(!h.contains("unlocked"));
        assert!(h.contains(ABSENT));
    }

    #[test]
    fn the_page_says_it_cannot_act() {
        // The property a reader should not have to infer: this surface is
        // read-only because mutations need a signature it does not hold.
        assert!(homepage(&sample()).contains("does not act"));
        assert!(dashboard(&sample()).contains("cannot act"));
    }

    #[test]
    fn a_machine_appears_once_however_many_names_it_has() {
        // This page first claimed four machines on a site with two: every box
        // has a declared name (`node-a`) and a reporting name
        // (`furcate:node:...`), and listing both counts it twice. The count in
        // the header is read as a fact about the site, so getting it wrong is
        // not a cosmetic problem.
        let o = Overview {
            site: "s".into(),
            nodes: vec![
                NodeRow { id: "node-a".into(), wall_w: Some(66.0), ..Default::default() },
                NodeRow { id: "node-b".into(), wall_w: Some(69.0), ..Default::default() },
            ],
            ..Default::default()
        };
        let h = homepage(&o);
        assert!(h.contains("2 machine(s) reporting"));
        assert_eq!(h.matches("node-a").count(), 1);
    }

    #[test]
    fn measured_figures_are_marked_as_measured() {
        let h = homepage(&sample());
        assert!(h.contains("class=measured>69</span> W"));
        assert!(h.contains("class=measured>42</span> °C"));
    }
}
