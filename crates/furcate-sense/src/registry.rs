//! The sensor and actuator catalogue.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Celsius,
    Percent,
    Volts,
    Amps,
    Watts,
    Pascals,
    Lux,
    /// Dimensionless count.
    Count,
    /// Sound pressure level, A-weighted.
    Decibels,
    /// Volumetric flow, for cooling loops and make-up water.
    LitresPerMinute,
    /// Concentration, for air quality.
    Ppm,
    /// Air speed, for airflow across a rack face.
    MetresPerSecond,
    /// Acceleration magnitude, for vibration.
    MetresPerSecondSquared,
    /// A fraction between zero and one, for anything normalised.
    Fraction,
    /// Magnetic flux density.
    Microtesla,
    /// Angular rate.
    RadiansPerSecond,
    /// Electrical resistance, for gas sensors that report it.
    Ohms,
    /// A number with no unit that is not a count or a fraction: a quaternion
    /// component, or an index defined by the sensor.
    Unitless,
    /// Linear position or distance.
    Metres,
    /// Joint or shaft angle.
    Radians,
    /// Force along an axis.
    Newtons,
    /// Torque about an axis.
    NewtonMetres,
    /// Frequency, for a drive output or a mains measurement.
    Hertz,
    /// Electrical energy, for a meter register.
    KilowattHours,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorKind {
    Temperature,
    Humidity,
    Power,
    /// Electrical energy accumulated by a meter register, in kilowatt hours.
    Energy,
    Current,
    Voltage,
    Pressure,
    Light,
    Motion,
    /// Volumetric flow through a cooling or make-up water line.
    Flow,
    /// Air speed at a rack face or vent.
    Airflow,
    /// Structural vibration, which is how a failing fan or pump announces
    /// itself before it stops.
    Vibration,
    /// Air quality, typically CO2.
    AirQuality,
    /// Sound pressure level. A microphone reduced to a scalar — the level is
    /// a measurement, and anything further requires a model.
    SoundLevel,
    /// A quantity a model extracted from audio, such as a detected event.
    AudioEvent,
    /// A quantity a model extracted from images or video, such as a count of
    /// people in a room or whether a cabinet door is open.
    VisionDerived,
    /// Signed acceleration along one axis, gravity included. Distinct from
    /// `Vibration`, which is a magnitude.
    Acceleration,
    /// Angular rate about one axis.
    AngularRate,
    /// Magnetic flux density along one axis.
    MagneticField,
    /// Resistance of a gas sensor element. The raw quantity behind any air
    /// quality estimate, and a measurement in its own right.
    GasResistance,
    /// One component of an orientation estimate fused from several sensors.
    Orientation,
    /// A step count from a pedometer algorithm.
    StepCount,
    /// A class from an activity recognition algorithm.
    ActivityState,
    /// An air quality index computed from gas resistance.
    AirQualityIndex,
    /// A concentration estimated from gas resistance, such as a CO2 or
    /// breath-VOC equivalent. Not a measurement of that gas: `AirQuality`
    /// stays the kind for a sensor that measures CO2.
    GasEquivalent,
    /// Position of a joint, axis or body, linear or angular (the unit says which).
    Position,
    /// Velocity of a joint, axis or body, linear or angular.
    Velocity,
    /// Torque at a joint or shaft.
    Torque,
    /// Force at a tool or a load cell.
    Force,
    /// A status word, error code or state number reported by a controller or
    /// drive. Computed by the device from its own state, not transduced.
    StatusCode,
    /// Anything the schema does not name.
    Other,
}

/// Whether a reading was sensed or inferred.
///
/// A thermometer and a model that counts people in a camera frame both emit a
/// number per interval, and treating them the same is a mistake with
/// consequences: one has a calibration error, the other has a false-positive
/// rate that moves with lighting, occlusion and whatever the model was trained
/// on. Anything downstream that plans on the basis of a reading — and this
/// codebase plans power, cooling and shutdown on the basis of readings —
/// should be able to tell which kind it is holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// A transducer measuring a physical quantity.
    Direct,
    /// A value computed from other signals rather than transduced: a model's
    /// output over audio, images or video, or a fusion, counting or estimation
    /// algorithm running on the sensor itself. Which of those it was is
    /// recorded with the reading, not in this flag.
    Inferred,
}

impl SensorKind {
    /// How readings of this kind come to exist.
    pub fn modality(&self) -> Modality {
        match self {
            SensorKind::AudioEvent
            | SensorKind::VisionDerived
            | SensorKind::Orientation
            | SensorKind::StepCount
            | SensorKind::ActivityState
            | SensorKind::AirQualityIndex
            | SensorKind::GasEquivalent
            | SensorKind::StatusCode => Modality::Inferred,
            _ => Modality::Direct,
        }
    }

    /// Whether a reading of this kind may be used on its own to justify a
    /// physical action.
    ///
    /// Inferred readings may inform, corroborate and raise alarms, but a model
    /// output should not by itself power down a machine or open a valve. The
    /// rule is deliberately blunt: the failure mode of a subtle rule here is
    /// hardware acting on a hallucination.
    pub fn may_actuate_alone(&self) -> bool {
        matches!(self.modality(), Modality::Direct)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sensor {
    pub id: String,
    pub kind: SensorKind,
    pub unit: Unit,
    /// The leaf or node that publishes it.
    pub host: String,
    /// The failure domain it physically sits in, when known.
    pub domain: Option<String>,
    /// Nominal reporting interval in seconds.
    pub interval_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actuator {
    pub id: String,
    pub host: String,
    /// Whether operating it can affect power or safety, in which case it
    /// requires operator authority rather than ordinary API access.
    pub privileged: bool,
}

/// The cluster-wide catalogue, gossiped alongside membership.
#[derive(Debug, Default)]
pub struct SensorRegistry {
    sensors: BTreeMap<String, Sensor>,
    actuators: BTreeMap<String, Actuator>,
}

impl SensorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, sensor: Sensor) -> &mut Self {
        self.sensors.insert(sensor.id.clone(), sensor);
        self
    }

    pub fn register_actuator(&mut self, a: Actuator) -> &mut Self {
        self.actuators.insert(a.id.clone(), a);
        self
    }

    pub fn get(&self, id: &str) -> Option<&Sensor> {
        self.sensors.get(id)
    }

    pub fn actuator(&self, id: &str) -> Option<&Actuator> {
        self.actuators.get(id)
    }

    pub fn len(&self) -> usize {
        self.sensors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sensors.is_empty()
    }

    /// Every sensor of a kind, anywhere in the cluster.
    ///
    /// This is what "addressable from every machine" means in practice: a
    /// caller asks for temperature and gets every one, without needing to know
    /// which leaf is attached to which parent.
    pub fn of_kind(&self, kind: SensorKind) -> Vec<&Sensor> {
        self.sensors.values().filter(|s| s.kind == kind).collect()
    }

    /// Every sensor, in id order: what a cell caches so its leaves stay
    /// listed while the link above it is down.
    pub fn sensors(&self) -> Vec<&Sensor> {
        self.sensors.values().collect()
    }

    /// Sensors published by a given host.
    pub fn hosted_by(&self, host: &str) -> Vec<&Sensor> {
        self.sensors.values().filter(|s| s.host == host).collect()
    }

    /// Drop everything a host published, for when a leaf detaches.
    pub fn forget_host(&mut self, host: &str) -> usize {
        let before = self.sensors.len() + self.actuators.len();
        self.sensors.retain(|_, s| s.host != host);
        self.actuators.retain(|_, a| a.host != host);
        before - (self.sensors.len() + self.actuators.len())
    }

    /// Sensors that have not reported within a tolerance of their interval.
    pub fn stale(&self, last_seen: &BTreeMap<String, u64>, now: u64, tolerance: u64) -> Vec<&Sensor> {
        self.sensors
            .values()
            .filter(|s| match last_seen.get(&s.id) {
                Some(t) => now.saturating_sub(*t) > s.interval_s * tolerance,
                // Never reported at all counts as stale, not as healthy.
                None => true,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sensor(id: &str, kind: SensorKind, host: &str) -> Sensor {
        Sensor {
            id: id.into(),
            kind,
            unit: Unit::Celsius,
            host: host.into(),
            domain: Some("rack-1".into()),
            interval_s: 10,
        }
    }

    fn registry() -> SensorRegistry {
        let mut r = SensorRegistry::new();
        r.register(sensor("rack-temp", SensorKind::Temperature, "esp32-a"))
            .register(sensor("inlet-temp", SensorKind::Temperature, "esp32-b"))
            .register(sensor("ups-load", SensorKind::Power, "node-a"));
        r
    }

    #[test]
    fn sensors_are_addressable_by_kind_across_hosts() {
        let r = registry();
        assert_eq!(r.of_kind(SensorKind::Temperature).len(), 2);
        assert_eq!(r.of_kind(SensorKind::Power).len(), 1);
        assert_eq!(r.of_kind(SensorKind::Motion).len(), 0);
    }

    #[test]
    fn a_detaching_leaf_takes_its_sensors_with_it() {
        let mut r = registry();
        assert_eq!(r.forget_host("esp32-a"), 1);
        assert_eq!(r.len(), 2);
        assert!(r.get("rack-temp").is_none());
    }

    #[test]
    fn a_sensor_that_never_reported_is_stale() {
        let r = registry();
        let seen = BTreeMap::new();
        assert_eq!(r.stale(&seen, 0, 3).len(), 3);
    }

    #[test]
    fn staleness_respects_the_reporting_interval() {
        let r = registry();
        let mut seen = BTreeMap::new();
        for id in ["rack-temp", "inlet-temp", "ups-load"] {
            seen.insert(id.to_string(), 100u64);
        }
        // Interval 10, tolerance 3 → stale after 30s.
        assert!(r.stale(&seen, 120, 3).is_empty());
        assert_eq!(r.stale(&seen, 131, 3).len(), 3);
    }

    #[test]
    fn privileged_actuators_are_marked() {
        let mut r = registry();
        r.register_actuator(Actuator {
            id: "pdu-outlet-3".into(),
            host: "node-a".into(),
            privileged: true,
        });
        assert!(r.actuator("pdu-outlet-3").unwrap().privileged);
    }

    #[test]
    fn hosted_by_finds_a_leafs_contributions() {
        let r = registry();
        assert_eq!(r.hosted_by("esp32-b").len(), 1);
    }
}

#[cfg(test)]
mod modality_tests {
    use super::*;

    #[test]
    fn a_thermometer_is_a_direct_measurement() {
        assert_eq!(SensorKind::Temperature.modality(), Modality::Direct);
        assert_eq!(SensorKind::Flow.modality(), Modality::Direct);
    }

    #[test]
    fn a_model_output_over_audio_or_video_is_inferred() {
        // Sound *level* is measured; a detected event in that sound is not.
        assert_eq!(SensorKind::SoundLevel.modality(), Modality::Direct);
        assert_eq!(SensorKind::AudioEvent.modality(), Modality::Inferred);
        assert_eq!(SensorKind::VisionDerived.modality(), Modality::Inferred);
    }

    #[test]
    fn an_inferred_reading_cannot_actuate_hardware_on_its_own() {
        // The failure mode of a subtler rule is a machine powering down
        // because a model mistook a shadow for smoke.
        assert!(!SensorKind::VisionDerived.may_actuate_alone());
        assert!(!SensorKind::AudioEvent.may_actuate_alone());
        assert!(SensorKind::Temperature.may_actuate_alone());
    }
}
