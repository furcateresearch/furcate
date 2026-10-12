//! Choose which machine in a site should run a piece of work.
//!
//! THE SHAPE THIS TAKES, AND WHY IT IS NOT THE SHAPE THAT WAS ASKED FOR
//!
//! The ask was a site that pools compute, memory and storage "so it works like
//! its own supercomputer". The interconnect refuses that, and it was measured
//! rather than assumed:
//!
//! ```text
//! node-a <-> node-b   1.4 ms,  772 Mbit/s  (counter-verified, 300 MB)
//! node-a <-> node-e    86.0 ms,  20% loss
//! ```
//!
//! Pooled memory needs a CXL switch or RDMA NICs; neither exists, and 772
//! Mbit/s is roughly 1% of a memory bus. Disaggregated KV-cache costs 200-500x
//! TTFT without RDMA, by NVIDIA Dynamo's own numbers. llama.cpp RPC sharding
//! measures *slower* than a single box at 5 Gbps — a link six times faster than
//! this one.
//!
//! What survives at this interconnect is placing **whole units of work on whole
//! machines**. That is what this does. It is the honest version of the ask, and
//! the useful one: the fleet already collects the inventory a placer needs, and
//! until now nothing consumed it.
//!
//! node-e is deliberately not special-cased here. It is 86 ms away, which makes
//! it a remote node rather than a site member, and the latency budget on a
//! Candidate is what expresses that — not a hardcoded hostname.

use furcate_host::acoustics::{Acoustics, BuildVerdict};
use std::collections::BTreeMap;

/// What a node last told us about itself, reduced to what a placement decision
/// actually needs.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub node_id: String,
    /// Seconds since this reading was taken. A placer that treats a stale
    /// reading as current will pile work onto a machine that died an hour ago.
    pub age_s: u64,
    /// Whether the last poll reached it at all. Distinct from age: a stale
    /// reading nobody retried is not the same as one that was retried and
    /// failed.
    pub reachable: bool,
    /// Whether the node's own lifecycle says it will take work. A node
    /// draining for maintenance is healthy and must still be skipped.
    pub accepts_work: bool,
    pub cpus: u32,
    pub mem_mb: u64,
    /// Memory currently committed to work already placed here.
    pub mem_committed_mb: u64,
    /// Round-trip from the controller. The measured spread across this fleet is
    /// 1.4 ms to 86 ms, so this is the field that decides whether a node is
    /// meaningfully part of the site for latency-sensitive work.
    pub rtt_ms: u32,
    /// What is left of the asking app's share on this host.
    ///
    /// The machine's free memory is not what may be sold. A share exists to keep
    /// tenant work off the capacity the daemon, the databases, the validator and
    /// model serving need, so the placer refuses past the share rather than past
    /// the machine — a 16 GB share on a 62 GB host is four standard boxes, and
    /// the other 46 GB is not an argument.
    ///
    /// [`Share::NONE`] is the default and the safe one: a host nobody wrote a
    /// share for takes no tenant work, because the alternative is that adding a
    /// machine to the fleet silently offers it for rent.
    pub share: Share,
    /// What this machine has declared about noise, if anything.
    ///
    /// `None` means no declaration, which `furcate_host::acoustics` already
    /// reads as a machine room — the unoccupied case, where width is the
    /// machine's business and not the clock's.
    pub acoustics: Option<Acoustics>,
    /// The hour it is *there*, which is not necessarily the hour it is here.
    ///
    /// `None` is a clock nobody can vouch for, and `Acoustics::builds_at` reads
    /// that as inside the window on an occupied site. That asymmetry is
    /// deliberate and is preserved rather than second-guessed here: work
    /// starting at 01:00 because a machine was unsure what time it was costs
    /// somebody's sleep, and a refusal at noon on a broken clock costs a delay.
    pub local_hour: Option<u8>,
}

/// What an app may still take on one host.
///
/// Three dimensions because the share file has three, and because a share that
/// capped only memory would let a tenant take every core on a machine that had
/// memory to spare.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Share {
    pub vcpu: u32,
    pub mem_mb: u64,
    pub disk_gb: u64,
}

impl Share {
    /// No share at all, which is what an undeclared host offers.
    pub const NONE: Share = Share { vcpu: 0, mem_mb: 0, disk_gb: 0 };

    /// Whether this share still covers `d`.
    pub fn covers(&self, d: &Demand) -> bool {
        self.vcpu >= d.cpus && self.mem_mb >= d.mem_mb && self.disk_gb >= d.disk_gb
    }

    /// What is left after `d` is taken.
    ///
    /// Saturating, so an over-commitment reads as nothing left rather than as a
    /// very large number.
    pub fn less(&self, d: &Demand) -> Share {
        Share {
            vcpu: self.vcpu.saturating_sub(d.cpus),
            mem_mb: self.mem_mb.saturating_sub(d.mem_mb),
            disk_gb: self.disk_gb.saturating_sub(d.disk_gb),
        }
    }

    /// The share this demand would consume, for putting in a refusal beside
    /// what is left.
    pub fn of(d: &Demand) -> Share {
        Share { vcpu: d.cpus, mem_mb: d.mem_mb, disk_gb: d.disk_gb }
    }
}

impl Candidate {
    fn mem_free_mb(&self) -> u64 {
        self.mem_mb.saturating_sub(self.mem_committed_mb)
    }
}

/// What the work needs.
#[derive(Clone, Debug, Default)]
pub struct Demand {
    /// Which app is asking, as the share file spells it.
    ///
    /// Carried so a refusal can name the line an operator has to edit, rather
    /// than leaving them to work out which of several shares was the one that
    /// ran out.
    pub app: String,
    pub cpus: u32,
    pub mem_mb: u64,
    /// Disk, in GiB. Zero for work that keeps nothing.
    pub disk_gb: u64,
    /// Reject any node slower than this. `None` means latency does not matter,
    /// which is true of batch work and false of anything user-facing.
    pub max_rtt_ms: Option<u32>,
    /// How many hours this must survive, for work bought by the hour.
    ///
    /// `None` for anything ended by something other than a clock. When it is
    /// set, a host is acceptable only if its declaration permits work at every
    /// hour the term covers: a scheduler that treats 18:00 as a failure produces
    /// an outage every evening at six, and one that places a thirty-day rental
    /// on a machine that refuses work at night has sold something it cannot
    /// deliver.
    pub term_hours: Option<u32>,
}

/// Why a node was not chosen. Refusals are named rather than filtered silently,
/// because "nowhere to put this" with no reason is the answer that wastes an
/// afternoon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Stale { age_s: u64 },
    Unreachable,
    Draining,
    NotEnoughCpu { has: u32, needs: u32 },
    NotEnoughMemory { free_mb: u64, needs_mb: u64 },
    TooFar { rtt_ms: u32, limit_ms: u32 },
    /// The machine has room; the app's share does not.
    ///
    /// Distinct from `NotEnoughMemory` deliberately, and the distinction is the
    /// whole reason a share exists: one says the machine is full, the other says
    /// this app has had its portion of a machine that is not. They have
    /// different remedies, and an operator handed the wrong one goes looking for
    /// memory that was there all along.
    OverShare { app: String, remaining: Share, needs: Share },
    /// The machine is within earshot of people who did not agree to host this —
    /// now, or at an hour this work would still be running.
    Quiet { verdict: BuildVerdict, at_hour: Option<u8> },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Stale { age_s } => write!(
                f,
                "its last reading is {age_s}s old and nothing newer arrived; \
                 `furcatectl fleet` says when each node last reported"
            ),
            Refusal::Unreachable => write!(f, "the last poll did not reach it at all"),
            Refusal::Draining => write!(
                f,
                "it is draining and will not take new work; it goes back in the \
                 pool when its maintenance is finished"
            ),
            Refusal::NotEnoughCpu { has, needs } => {
                write!(f, "it has {has} cores and this needs {needs}")
            }
            Refusal::NotEnoughMemory { free_mb, needs_mb } => {
                write!(f, "it has {free_mb} MiB free and this needs {needs_mb} MiB")
            }
            Refusal::TooFar { rtt_ms, limit_ms } => write!(
                f,
                "it is {rtt_ms} ms away and this work will not accept more than {limit_ms} ms"
            ),
            Refusal::OverShare { app, remaining, needs } => write!(
                f,
                "the share for `{app}` has {} vCPU, {} GiB and {} GiB of disk left, \
                 and this needs {}, {} and {}. Raise it in /etc/furcate/shares.yaml, \
                 ask for a smaller size, or wait for something to finish",
                remaining.vcpu,
                remaining.mem_mb / 1_024,
                remaining.disk_gb,
                needs.vcpu,
                needs.mem_mb / 1_024,
                needs.disk_gb
            ),
            Refusal::Quiet { at_hour, .. } => match at_hour {
                Some(h) => write!(
                    f,
                    "it is within earshot of people who did not agree to host this, \
                     and its declaration refuses work at {h:02}:00. \
                     `furcatectl thermal set` is where that window is declared"
                ),
                None => write!(
                    f,
                    "it is within earshot of people who did not agree to host this \
                     and could not say what hour it is, which is read as night"
                ),
            },
        }
    }
}

impl std::error::Error for Refusal {}

#[derive(Clone, Debug)]
pub struct Placement {
    pub chosen: Option<String>,
    /// Every node that was not chosen, and why. Always populated, including on
    /// success — an operator asking "why not that machine?" should not have to
    /// re-run anything.
    pub refused: BTreeMap<String, Refusal>,
}

/// A reading older than this is not evidence about the present.
///
/// The fleet poller runs every 30 s, so this allows four consecutive misses
/// before a node stops being placeable. Tighter than the 120 s the console uses
/// to *display* staleness, deliberately: showing a stale reading labelled stale
/// is honest, but *acting* on one is not.
pub const PLACEABLE_MAX_AGE_S: u64 = 90;

/// Pick the best node for `demand`, or explain why none fit.
///
/// Ties break toward the node with the most free memory, then by node id so the
/// result is deterministic. A placer that returns a different answer for
/// identical input makes every incident harder to reason about.
pub fn place(candidates: &[Candidate], demand: &Demand) -> Placement {
    let mut refused = BTreeMap::new();
    let mut best: Option<&Candidate> = None;

    for c in candidates {
        if let Some(r) = refuse(c, demand) {
            refused.insert(c.node_id.clone(), r);
            continue;
        }
        best = Some(match best {
            None => c,
            Some(b) => {
                // Most free memory wins; node id breaks exact ties.
                match c.mem_free_mb().cmp(&b.mem_free_mb()) {
                    std::cmp::Ordering::Greater => c,
                    std::cmp::Ordering::Less => b,
                    std::cmp::Ordering::Equal => {
                        if c.node_id < b.node_id { c } else { b }
                    }
                }
            }
        });
    }

    Placement { chosen: best.map(|c| c.node_id.clone()), refused }
}

/// Checked in the order an operator would check them: is this machine even
/// answering, does it want work, may this app have any of it, is anybody
/// asleep next to it, and only then does the work fit.
///
/// Quiet comes before the fit, and that placement is deliberate — it is the
/// order `furcate-build` already uses, *"decided before pressure so a build
/// waiting for load to fall does not start the moment it does, at night"*. The
/// share comes before quiet because being out of share is a fact about the
/// arrangement rather than about the hour, and an operator would rather be told
/// the permanent reason than the one that expires at 08:00.
fn refuse(c: &Candidate, d: &Demand) -> Option<Refusal> {
    if !c.reachable {
        return Some(Refusal::Unreachable);
    }
    if c.age_s > PLACEABLE_MAX_AGE_S {
        return Some(Refusal::Stale { age_s: c.age_s });
    }
    if !c.accepts_work {
        return Some(Refusal::Draining);
    }
    if !c.share.covers(d) {
        return Some(Refusal::OverShare {
            app: d.app.clone(),
            remaining: c.share,
            needs: Share::of(d),
        });
    }
    if let Some(r) = quiet_refusal(c, d) {
        return Some(r);
    }
    if let Some(limit) = d.max_rtt_ms {
        if c.rtt_ms > limit {
            return Some(Refusal::TooFar { rtt_ms: c.rtt_ms, limit_ms: limit });
        }
    }
    if c.cpus < d.cpus {
        return Some(Refusal::NotEnoughCpu { has: c.cpus, needs: d.cpus });
    }
    if c.mem_free_mb() < d.mem_mb {
        return Some(Refusal::NotEnoughMemory {
            free_mb: c.mem_free_mb(),
            needs_mb: d.mem_mb,
        });
    }
    None
}

/// Whether this machine's own declaration about noise refuses this work.
///
/// Two questions, not one. The first is whether it may start *now*. The second
/// only arises for work bought by the hour: whether it may still be running at
/// every hour between now and the end of the term. A machine that refuses work
/// at 22:00 can take a two-hour rental at nine in the morning and cannot take a
/// thirty-day one at any time, and a placer that asked only the first question
/// would sell the second and then have to break it.
///
/// `builds_at` is the same function the build arm consumes, deliberately: a
/// machine has one declaration about noise, and a second vocabulary for the same
/// window is how the two come to disagree.
fn quiet_refusal(c: &Candidate, d: &Demand) -> Option<Refusal> {
    let acoustics = c.acoustics?;

    let now = acoustics.builds_at(c.local_hour);
    if now == BuildVerdict::Refuse {
        return Some(Refusal::Quiet { verdict: now, at_hour: c.local_hour });
    }

    // A term the machine has to outlive. Every hour it covers is asked, and a
    // term of a day or more covers all of them.
    let hours = d.term_hours?;
    let start = c.local_hour?;
    let span = hours.min(24);
    for step in 0..span {
        let hour = ((start as u32 + step) % 24) as u8;
        if acoustics.builds_at(Some(hour)) == BuildVerdict::Refuse {
            return Some(Refusal::Quiet {
                verdict: BuildVerdict::Refuse,
                at_hour: Some(hour),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, cpus: u32, mem_mb: u64, rtt_ms: u32) -> Candidate {
        Candidate {
            node_id: id.into(),
            age_s: 5,
            reachable: true,
            accepts_work: true,
            cpus,
            mem_mb,
            mem_committed_mb: 0,
            rtt_ms,
            // Generous by default so that the tests written before shares
            // existed still test what they were written to test.
            share: Share { vcpu: 1_024, mem_mb: 1_024 * 1_024, disk_gb: 10_000 },
            acoustics: None,
            local_hour: Some(12),
        }
    }

    fn small() -> Demand {
        Demand { app: "boxes".into(), cpus: 1, mem_mb: 512, ..Demand::default() }
    }

    /// node-c's declaration, read off the machine: occupied, 18:00 to 08:00,
    /// and it refuses rather than narrowing.
    fn refuses_at_night() -> Acoustics {
        Acoustics {
            placement: furcate_host::acoustics::Placement::SharedSpace,
            quiet_hours: Some(furcate_host::acoustics::QuietHours { from: 18, to: 8 }),
            builds: furcate_host::acoustics::Builds::Refuse,
        }
    }

    #[test]
    fn picks_the_node_with_the_most_room() {
        let c = vec![node("node-a", 8, 62_000, 1), node("node-e", 20, 121_000, 86)];
        assert_eq!(place(&c, &small()).chosen.as_deref(), Some("node-e"));
    }

    #[test]
    fn a_latency_budget_excludes_the_remote_node_however_big_it_is() {
        // The case this exists for: node-e has twice the RAM and 2.5x the cores,
        // and is 86 ms away. For anything user-facing it is the wrong answer,
        // and size must not be allowed to argue otherwise.
        let c = vec![node("node-a", 8, 62_000, 1), node("node-e", 20, 121_000, 86)];
        let d = Demand { max_rtt_ms: Some(10), ..small() };
        let p = place(&c, &d);
        assert_eq!(p.chosen.as_deref(), Some("node-a"));
        assert_eq!(p.refused.get("node-e"), Some(&Refusal::TooFar { rtt_ms: 86, limit_ms: 10 }));
    }

    #[test]
    fn a_stale_reading_is_not_evidence_about_the_present() {
        let mut n = node("node-a", 8, 62_000, 1);
        n.age_s = PLACEABLE_MAX_AGE_S + 1;
        let p = place(&[n], &small());
        assert_eq!(p.chosen, None);
        assert!(matches!(p.refused.get("node-a"), Some(Refusal::Stale { .. })));
    }

    #[test]
    fn unreachable_is_reported_as_unreachable_not_as_stale() {
        // Both are true of a dead node; only one tells the operator whether
        // anybody has tried lately.
        let mut n = node("node-a", 8, 62_000, 1);
        n.reachable = false;
        n.age_s = 999;
        assert_eq!(place(&[n], &small()).refused.get("node-a"), Some(&Refusal::Unreachable));
    }

    #[test]
    fn a_draining_node_is_healthy_and_still_refused() {
        let mut n = node("node-a", 8, 62_000, 1);
        n.accepts_work = false;
        assert_eq!(place(&[n], &small()).refused.get("node-a"), Some(&Refusal::Draining));
    }

    #[test]
    fn already_committed_memory_is_not_free_memory() {
        // Placing against total rather than free is how a machine gets
        // oversubscribed into the swap-thrashing failure this fleet already hit.
        let mut n = node("node-a", 8, 62_000, 1);
        n.mem_committed_mb = 61_800;
        let d = Demand { mem_mb: 1_000, ..small() };
        assert_eq!(
            place(&[n], &d).refused.get("node-a"),
            Some(&Refusal::NotEnoughMemory { free_mb: 200, needs_mb: 1_000 })
        );
    }

    #[test]
    fn nowhere_to_put_it_still_says_why_for_every_node() {
        let c = vec![node("node-a", 8, 62_000, 1), node("node-b", 8, 62_000, 2)];
        let d = Demand { cpus: 64, ..small() };
        let p = place(&c, &d);
        assert_eq!(p.chosen, None);
        assert_eq!(p.refused.len(), 2, "every node must be accounted for");
    }

    #[test]
    fn the_same_input_always_gives_the_same_answer() {
        let c = vec![node("b-node", 8, 62_000, 1), node("a-node", 8, 62_000, 1)];
        for _ in 0..20 {
            assert_eq!(place(&c, &small()).chosen.as_deref(), Some("a-node"));
        }
    }

    #[test]
    fn an_empty_site_refuses_rather_than_inventing_a_node() {
        assert_eq!(place(&[], &small()).chosen, None);
    }

    #[test]
    fn a_host_nobody_wrote_a_share_for_takes_no_tenant_work() {
        // Otherwise adding a machine to the fleet silently offers it for rent.
        let mut n = node("node-a", 8, 62_000, 1);
        n.share = Share::NONE;
        let p = place(&[n], &small());
        assert_eq!(p.chosen, None);
        assert!(matches!(p.refused.get("node-a"), Some(Refusal::OverShare { .. })));
    }

    #[test]
    fn the_share_is_what_may_be_sold_and_not_the_machine() {
        // 16 GB of share on a 62 GB host is four standard boxes. The other
        // 46 GB is the daemon, the databases and the validator, and it is not
        // an argument.
        let mut n = node("node-b", 8, 62_000, 1);
        n.share = Share { vcpu: 4, mem_mb: 16 * 1_024, disk_gb: 100 };
        let standard = Demand {
            app: "boxes".into(),
            cpus: 2,
            mem_mb: 4 * 1_024,
            disk_gb: 20,
            ..Demand::default()
        };
        assert_eq!(place(&[n.clone()], &standard).chosen.as_deref(), Some("node-b"));

        // Two boxes in, and the third is refused by the share rather than by
        // the machine, which still has 54 GB free.
        n.share = n.share.less(&standard).less(&standard);
        let p = place(&[n], &standard);
        assert_eq!(p.chosen, None);
        assert_eq!(
            p.refused.get("node-b"),
            Some(&Refusal::OverShare {
                app: "boxes".into(),
                remaining: Share { vcpu: 0, mem_mb: 8 * 1_024, disk_gb: 60 },
                needs: Share { vcpu: 2, mem_mb: 4 * 1_024, disk_gb: 20 },
            })
        );
    }

    #[test]
    fn being_out_of_share_is_a_different_sentence_from_a_full_machine() {
        // An operator told the wrong one goes looking for memory that is
        // already there.
        let over = Refusal::OverShare {
            app: "boxes".into(),
            remaining: Share { vcpu: 1, mem_mb: 2 * 1_024, disk_gb: 10 },
            needs: Share { vcpu: 2, mem_mb: 4 * 1_024, disk_gb: 20 },
        };
        let msg = over.to_string();
        assert!(msg.contains("shares.yaml"), "{msg}");
        assert!(msg.contains("1 vCPU, 2 GiB"), "{msg}");
        assert!(msg.contains("needs 2, 4"), "{msg}");
    }

    #[test]
    fn a_share_that_covers_memory_but_not_cores_is_not_a_share_that_covers() {
        // A share capping only memory lets a tenant take every core on a
        // machine that had memory to spare.
        let mut n = node("node-a", 8, 62_000, 1);
        n.share = Share { vcpu: 1, mem_mb: 64 * 1_024, disk_gb: 1_000 };
        let d = Demand { app: "boxes".into(), cpus: 4, mem_mb: 8 * 1_024, ..Demand::default() };
        assert!(matches!(place(&[n], &d).refused.get("node-a"), Some(Refusal::OverShare { .. })));
    }

    #[test]
    fn a_refusing_window_is_a_refusal_and_not_a_silent_skip() {
        // node-c declares occupied, 18:00 to 08:00, builds=refuse. "Nowhere to
        // put this" with no reason is the answer that wastes an afternoon.
        let mut n = node("node-c", 56, 120_000, 1);
        n.acoustics = Some(refuses_at_night());
        n.local_hour = Some(23);
        let p = place(&[n], &small());
        assert_eq!(p.chosen, None);
        assert_eq!(
            p.refused.get("node-c"),
            Some(&Refusal::Quiet { verdict: BuildVerdict::Refuse, at_hour: Some(23) })
        );
    }

    #[test]
    fn the_same_machine_takes_the_same_work_in_the_morning() {
        let mut n = node("node-c", 56, 120_000, 1);
        n.acoustics = Some(refuses_at_night());
        n.local_hour = Some(10);
        assert_eq!(place(&[n], &small()).chosen.as_deref(), Some("node-c"));
    }

    #[test]
    fn a_term_is_never_placed_where_it_cannot_outlive_the_window() {
        // Nine in the morning, and the window opens at six. A two-hour rental
        // fits; a thirty-day one has been sold something that cannot be
        // delivered, and a scheduler that treats 18:00 as a failure produces an
        // outage every evening at six.
        let mut n = node("node-c", 56, 120_000, 1);
        n.acoustics = Some(refuses_at_night());
        n.local_hour = Some(9);

        let two_hours = Demand { term_hours: Some(2), ..small() };
        assert_eq!(place(&[n.clone()], &two_hours).chosen.as_deref(), Some("node-c"));

        let thirty_days = Demand { term_hours: Some(30 * 24), ..small() };
        let p = place(&[n], &thirty_days);
        assert_eq!(p.chosen, None);
        assert_eq!(
            p.refused.get("node-c"),
            Some(&Refusal::Quiet { verdict: BuildVerdict::Refuse, at_hour: Some(18) }),
            "the first hour of the term that the machine refuses"
        );
    }

    #[test]
    fn a_machine_room_takes_work_at_any_hour() {
        // An unoccupied placement means width is the machine's business and not
        // the clock's, and nothing here should invent a window for it.
        let mut n = node("node-a", 8, 62_000, 1);
        n.acoustics = Some(Acoustics::machine_room());
        for h in 0..24u8 {
            n.local_hour = Some(h);
            let d = Demand { term_hours: Some(24 * 365), ..small() };
            assert_eq!(place(&[n.clone()], &d).chosen.as_deref(), Some("node-a"), "at {h:02}:00");
        }
    }

    #[test]
    fn a_narrowing_window_slows_work_down_rather_than_refusing_it() {
        // `Narrow` is a width instruction, not a refusal, and reading it as one
        // would close a machine every night that had only asked to be quieter.
        let mut n = node("node-c", 56, 120_000, 1);
        n.acoustics = Some(Acoustics {
            builds: furcate_host::acoustics::Builds::Narrow,
            ..refuses_at_night()
        });
        n.local_hour = Some(23);
        assert_eq!(place(&[n], &small()).chosen.as_deref(), Some("node-c"));
    }

    #[test]
    fn a_clock_nobody_can_vouch_for_is_read_as_night_on_an_occupied_site() {
        // The asymmetry acoustics chose deliberately, preserved rather than
        // second-guessed: a refusal at noon on a broken clock costs a delay,
        // and the other mistake costs somebody's sleep.
        let mut n = node("node-c", 56, 120_000, 1);
        n.acoustics = Some(refuses_at_night());
        n.local_hour = None;
        assert!(matches!(
            place(&[n], &small()).refused.get("node-c"),
            Some(Refusal::Quiet { at_hour: None, .. })
        ));
    }

    #[test]
    fn a_share_that_ran_out_is_reported_before_an_hour_that_will_pass() {
        // An operator would rather be told the permanent reason than the one
        // that expires at 08:00.
        let mut n = node("node-c", 56, 120_000, 1);
        n.share = Share::NONE;
        n.acoustics = Some(refuses_at_night());
        n.local_hour = Some(23);
        assert!(matches!(
            place(&[n], &small()).refused.get("node-c"),
            Some(Refusal::OverShare { .. })
        ));
    }

    #[test]
    fn every_refusal_says_something_an_operator_can_act_on() {
        let refusals = [
            Refusal::Stale { age_s: 200 },
            Refusal::Unreachable,
            Refusal::Draining,
            Refusal::NotEnoughCpu { has: 2, needs: 8 },
            Refusal::NotEnoughMemory { free_mb: 100, needs_mb: 4_096 },
            Refusal::TooFar { rtt_ms: 86, limit_ms: 10 },
            Refusal::OverShare {
                app: "boxes".into(),
                remaining: Share::NONE,
                needs: Share { vcpu: 2, mem_mb: 4_096, disk_gb: 20 },
            },
            Refusal::Quiet { verdict: BuildVerdict::Refuse, at_hour: Some(2) },
        ];
        for r in refusals {
            let msg = r.to_string();
            assert!(msg.len() > 20, "{r:?} says too little: {msg}");
            assert!(!msg.ends_with('.'), "{msg} reads as a fragment in a list");
        }
    }
}
