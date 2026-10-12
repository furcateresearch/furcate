//! One card presented as several, and what that costs.
//!
//! A datacentre accelerator can be hard-partitioned into instances with their
//! own memory, their own compute slices and their own fault behaviour. It is
//! the difference between eight jobs contending for one card and eight jobs
//! each holding a smaller one, and for inference work it is usually the
//! difference between a card at 12% utilisation and a card that is full.
//!
//! Three things about it are easy to get wrong, and all three change what a
//! scheduler should do.
//!
//! ## An instance is not a fraction
//!
//! Partitioning is not divide-by-N. The hardware offers a fixed set of shapes,
//! the shapes do not tile freely, and the sum of a valid layout is reliably
//! *less* than the whole card — the slices are cut from a fixed number of
//! compute and memory units and some are stranded by every arrangement. Asking
//! for "half a card" is not a request the hardware can answer, and a placer
//! that models accelerators as a pool of fractional capacity will confidently
//! promise layouts that cannot be built.
//!
//! ## Repartitioning is a drain, not a setting
//!
//! Changing the layout requires the card to be idle. That makes it a
//! scheduling decision with a cost — every instance must finish or be killed
//! first — and not a knob to turn in response to load. Treating it as a runtime
//! adjustment produces a control loop that kills running work to make room for
//! work that would have fitted anyway.
//!
//! ## Isolation holds for contention and not for every fault
//!
//! The subtle one, and the reason this module sits beside [`crate::xid`].
//! Instances are genuinely isolated for memory and for compute: a job cannot
//! read another instance's memory or steal its throughput. They are *not*
//! isolated against every hardware fault, because they share silicon, power and
//! a memory system.
//!
//! That maps exactly onto the containment distinction the fault taxonomy
//! already draws. A contained fault stays inside the instance that caused it.
//! An uncontained one implicates every instance on that card, and a fleet that
//! drains only the instance named in the log leaves seven others running on
//! hardware it has already decided is untrustworthy.

use serde::{Deserialize, Serialize};

/// A partition profile, as the hardware names them.
///
/// The vendor's own notation: compute slices, then memory. `3g.40gb` is three
/// compute slices and forty gigabytes. Kept as the card's numbers rather than
/// as a percentage, because the numbers are what the hardware accepts and a
/// percentage is what invents layouts that do not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Compute slices.
    pub slices: u8,
    /// Memory, in gigabytes.
    pub memory_gb: u16,
}

impl Profile {
    pub const fn new(slices: u8, memory_gb: u16) -> Self {
        Profile { slices, memory_gb }
    }

    /// The vendor's name for this shape, e.g. `3g.40gb`.
    pub fn name(&self) -> String {
        format!("{}g.{}gb", self.slices, self.memory_gb)
    }
}

/// One partition of a card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    /// Identifier the driver gives this instance.
    pub id: String,
    /// Which card it is cut from. The field that makes a blast radius
    /// computable — without it an instance looks like an independent device.
    pub card_uuid: String,
    pub profile: Profile,
}

/// How a card is currently arranged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layout {
    pub card_uuid: String,
    /// Compute slices the card has in total, when partitioning is supported.
    ///
    /// `None` means the question was not answered — an older card, a driver
    /// that does not report it, or a reading that failed. Not zero, which would
    /// say the card has no compute at all.
    pub total_slices: Option<u8>,
    /// Total memory in gigabytes, on the same terms.
    pub total_memory_gb: Option<u16>,
    /// Whether the card is in partitioned mode at all.
    ///
    /// A card with partitioning switched off is one device, and that is a
    /// perfectly ordinary state rather than a misconfiguration.
    pub enabled: bool,
    pub instances: Vec<Instance>,
}

impl Layout {
    /// A card presenting itself whole.
    pub fn whole(card_uuid: impl Into<String>) -> Self {
        Layout {
            card_uuid: card_uuid.into(),
            total_slices: None,
            total_memory_gb: None,
            enabled: false,
            instances: Vec::new(),
        }
    }

    /// Compute slices currently handed out.
    pub fn slices_used(&self) -> u8 {
        self.instances.iter().map(|i| i.profile.slices).sum()
    }

    /// Memory currently handed out.
    pub fn memory_used_gb(&self) -> u16 {
        self.instances.iter().map(|i| i.profile.memory_gb).sum()
    }

    /// Compute slices the card has that no instance holds.
    ///
    /// `None` when the card never said how many it has — and that is not the
    /// same as none spare. A scheduler told "zero free" when the truth is
    /// "unknown" will refuse to place work that would have fitted.
    pub fn spare_slices(&self) -> Option<u8> {
        self.total_slices.map(|t| t.saturating_sub(self.slices_used()))
    }

    /// Whether this layout leaves compute nobody can reach.
    ///
    /// Some stranding is unavoidable — the shapes do not tile perfectly — so
    /// this is worth reporting and is not a fault. It is the figure that says
    /// whether a different layout would fit more work, which is a question only
    /// a person with a drain window can act on.
    pub fn stranded_slices(&self) -> Option<u8> {
        self.spare_slices().filter(|s| *s > 0)
    }

    /// Every instance that shares silicon with the one named.
    ///
    /// The blast radius of a card-level fault. Returns the siblings only —
    /// the instance itself is what the caller already has.
    pub fn siblings_of<'a>(&'a self, instance_id: &str) -> Vec<&'a Instance> {
        self.instances
            .iter()
            .filter(|i| i.id != instance_id)
            .collect()
    }
}

/// What a fault on one instance means for the rest of the card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blast {
    /// The fault stays inside the instance that hit it.
    ///
    /// The isolation is real: the other instances keep running and their
    /// results are as good as they were.
    OneInstance { id: String },
    /// Every instance on the card is implicated.
    ///
    /// An uncontained fault is a statement about the silicon, the power or the
    /// memory system, all of which are shared. Draining only the instance the
    /// log named would leave the others running on hardware already judged
    /// untrustworthy.
    WholeCard {
        card_uuid: String,
        instances: Vec<String>,
    },
    /// Containment is not known.
    ///
    /// Deliberately not folded into either. Assuming containment leaves work on
    /// a bad card; assuming the worst drains seven healthy instances over a bug
    /// in one job. Neither is a guess worth making silently.
    Unknown { card_uuid: String },
}

impl Blast {
    /// Instance identifiers that should stop receiving work.
    pub fn drains(&self) -> Vec<String> {
        match self {
            Blast::OneInstance { id } => vec![id.clone()],
            Blast::WholeCard { instances, .. } => instances.clone(),
            // Unknown containment drains nothing on its own. It is a question
            // for whoever is looking, not an action.
            Blast::Unknown { .. } => Vec::new(),
        }
    }
}

/// Work out what a fault on `instance_id` reaches.
///
/// `contained` is [`crate::xid::Class::contained`] — `Some(true)` for a fault
/// the hardware confined to one context, `Some(false)` for one it did not, and
/// `None` when the code has no containment meaning or none was reported.
pub fn blast(layout: &Layout, instance_id: &str, contained: Option<bool>) -> Blast {
    match contained {
        Some(true) => Blast::OneInstance {
            id: instance_id.to_string(),
        },
        Some(false) => Blast::WholeCard {
            card_uuid: layout.card_uuid.clone(),
            instances: if layout.instances.is_empty() {
                // An unpartitioned card is one instance by another name, and
                // the fault still takes all of it.
                vec![instance_id.to_string()]
            } else {
                layout.instances.iter().map(|i| i.id.clone()).collect()
            },
        },
        None => Blast::Unknown {
            card_uuid: layout.card_uuid.clone(),
        },
    }
}

/// Whether a layout can be changed right now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repartition {
    /// Nothing is running; the layout can be rebuilt.
    Ready,
    /// Instances are in use. Naming them, because "busy" without saying what is
    /// on it is the answer that sends somebody looking through eight dashboards.
    MustDrainFirst { holding: Vec<String> },
    /// The card does not partition, so there is nothing to arrange.
    NotSupported,
}

/// Can this card be repartitioned, given what is running on it?
///
/// `busy` is the set of instance identifiers currently holding work. The caller
/// supplies it because this crate reads hardware, not workloads — and guessing
/// from a memory reading would call a card idle because the allocator had not
/// yet reserved anything.
pub fn repartition(layout: &Layout, busy: &[String]) -> Repartition {
    if !layout.enabled && layout.instances.is_empty() && layout.total_slices.is_none() {
        return Repartition::NotSupported;
    }
    let holding: Vec<String> = layout
        .instances
        .iter()
        .filter(|i| busy.iter().any(|b| b == &i.id))
        .map(|i| i.id.clone())
        .collect();
    if holding.is_empty() {
        Repartition::Ready
    } else {
        Repartition::MustDrainFirst { holding }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(id: &str, slices: u8, gb: u16) -> Instance {
        Instance {
            id: id.into(),
            card_uuid: "GPU-aaa".into(),
            profile: Profile::new(slices, gb),
        }
    }

    /// A seven-slice card cut into three instances, which strands one slice.
    fn partitioned() -> Layout {
        Layout {
            card_uuid: "GPU-aaa".into(),
            total_slices: Some(7),
            total_memory_gb: Some(80),
            enabled: true,
            instances: vec![
                instance("mig0", 3, 40),
                instance("mig1", 2, 20),
                instance("mig2", 1, 10),
            ],
        }
    }

    #[test]
    fn a_profile_is_named_the_way_the_hardware_names_it() {
        assert_eq!(Profile::new(3, 40).name(), "3g.40gb");
        assert_eq!(Profile::new(1, 10).name(), "1g.10gb");
    }

    #[test]
    fn the_parts_do_not_add_up_to_the_whole_and_that_is_normal() {
        // The shapes do not tile freely, so some capacity is stranded by every
        // arrangement. A placer modelling cards as fractional capacity will
        // promise layouts the hardware cannot build.
        let l = partitioned();
        assert_eq!(l.slices_used(), 6);
        assert_eq!(l.spare_slices(), Some(1));
        assert_eq!(l.stranded_slices(), Some(1), "reported, and not a fault");
        assert_eq!(l.memory_used_gb(), 70);
    }

    #[test]
    fn a_card_that_never_said_its_size_reports_unknown_not_zero() {
        // A scheduler told "zero free" when the truth is "nobody asked" will
        // refuse work that would have fitted.
        let mut l = partitioned();
        l.total_slices = None;
        assert_eq!(l.spare_slices(), None);
        assert_eq!(l.stranded_slices(), None);
    }

    #[test]
    fn a_contained_fault_stops_one_instance() {
        // The isolation is real, and treating every fault as card-wide would
        // drain seven healthy instances over one job's bug.
        let l = partitioned();
        let b = blast(&l, "mig1", Some(true));
        assert_eq!(b, Blast::OneInstance { id: "mig1".into() });
        assert_eq!(b.drains(), vec!["mig1".to_string()]);
    }

    #[test]
    fn an_uncontained_fault_stops_every_instance_on_that_card() {
        // The reason this module sits beside the fault taxonomy. Instances
        // share silicon, power and a memory system; draining only the one the
        // log named leaves the others on hardware already judged untrustworthy.
        let l = partitioned();
        let b = blast(&l, "mig1", Some(false));
        match &b {
            Blast::WholeCard { card_uuid, instances } => {
                assert_eq!(card_uuid, "GPU-aaa");
                assert_eq!(instances.len(), 3);
            }
            other => panic!("expected the whole card, got {other:?}"),
        }
        assert_eq!(b.drains().len(), 3, "all of them, not just the named one");
    }

    #[test]
    fn unknown_containment_is_neither_assumed_safe_nor_assumed_worst() {
        let l = partitioned();
        let b = blast(&l, "mig1", None);
        assert!(matches!(b, Blast::Unknown { .. }));
        assert!(b.drains().is_empty(), "a question, not an action");
    }

    #[test]
    fn an_unpartitioned_card_still_loses_all_of_itself() {
        // One instance by another name.
        let l = Layout::whole("GPU-bbb");
        let b = blast(&l, "GPU-bbb", Some(false));
        assert_eq!(b.drains(), vec!["GPU-bbb".to_string()]);
    }

    #[test]
    fn siblings_are_what_a_card_level_fault_reaches() {
        let l = partitioned();
        let s = l.siblings_of("mig1");
        assert_eq!(s.len(), 2);
        assert!(!s.iter().any(|i| i.id == "mig1"), "itself is not a sibling");
    }

    #[test]
    fn repartitioning_an_idle_card_is_allowed() {
        assert_eq!(repartition(&partitioned(), &[]), Repartition::Ready);
    }

    #[test]
    fn repartitioning_names_what_is_in_the_way() {
        // "Busy" without saying what is on it sends somebody through eight
        // dashboards to find out.
        let l = partitioned();
        match repartition(&l, &["mig1".to_string(), "mig2".to_string()]) {
            Repartition::MustDrainFirst { holding } => {
                assert_eq!(holding, vec!["mig1".to_string(), "mig2".to_string()]);
            }
            other => panic!("expected a drain requirement, got {other:?}"),
        }
    }

    #[test]
    fn work_on_an_instance_that_is_not_there_does_not_block_anything() {
        // A stale workload record naming an instance from a previous layout
        // must not make the card permanently unrepartitionable.
        let l = partitioned();
        assert_eq!(
            repartition(&l, &["from-an-older-layout".to_string()]),
            Repartition::Ready
        );
    }

    #[test]
    fn a_card_that_does_not_partition_says_so_rather_than_looking_idle() {
        // Distinct from Ready. "Nothing to arrange" and "arrange freely" would
        // send a repartition attempt at hardware that has no such operation.
        assert_eq!(repartition(&Layout::whole("GPU-ccc"), &[]), Repartition::NotSupported);
    }
}
