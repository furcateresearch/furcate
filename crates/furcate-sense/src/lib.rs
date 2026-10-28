//! Sensors, actuators and leaf devices.
//!
//! A microcontroller cannot run gossip, consensus or a TPM stack, and
//! pretending otherwise is how edge systems get fragile. Instead a leaf
//! *attaches* to a parent node, attests with whatever root of trust its
//! silicon offers, and publishes signed readings through it. The parent
//! represents its leaves in the cluster, which keeps membership small and
//! consensus cheap while making every sensor in the building addressable from
//! every machine on it.

pub mod bhy2;
pub mod cascade;
pub mod frame;
pub mod identity;
pub mod leaf;
pub mod nicla;
pub mod registry;
pub mod serial;
pub mod text;

pub use leaf::{Attachment, Leaf, LeafError, Reading};
pub use registry::{Actuator, Modality, Sensor, SensorKind, SensorRegistry, Unit};
