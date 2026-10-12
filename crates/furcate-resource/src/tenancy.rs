//! What a tenant is given: buckets, databases, and the isolation between them.
//!
//! The rest of this crate is about what a machine has. This is about what has
//! been handed out, and to whom.
//!
//! ## Why database-per-tenant is the default
//!
//! Postgres offers three isolations: a database per tenant, a schema per
//! tenant, or shared tables filtered by row-level security. RLS scales to
//! hundreds of thousands of tenants and is the standard answer for a SaaS.
//!
//! It is the wrong default here, for a reason particular to this system rather
//! than a general preference. Furcate's claim is that an operator can leave and
//! take their data. With a database per tenant, leaving is one dump of one
//! database — a thing an operator can run and verify. With row-level security,
//! leaving is a filtered export that somebody has to write correctly, and the
//! correctness of that filter is exactly what nobody can check afterwards. RLS
//! also puts isolation in the hands of the application setting a session
//! variable on every query, so one missed call leaks between tenants; a
//! database boundary does not have that failure mode.
//!
//! Furcate's tenants are households, teams and organisations — tens or
//! hundreds, not millions — so the isolation that scales worst is the one that
//! fits. Denser isolations are available and have to be asked for by name.
//!
//! ## Why one engine takes several shapes
//!
//! Vector, time-series, graph and geospatial are extensions of Postgres rather
//! than separate products: pgvector, TimescaleDB, Apache AGE, PostGIS. On a
//! small cluster that is one engine to patch, one backup to test and one set of
//! credentials to audit, instead of five of each. Five engines on three
//! machines is five ways to be behind on a security release.
//!
//! What genuinely is not Postgres gets its own engine: a key-value store, and
//! an object store speaking S3.
//!
//! ## What this module does not do
//!
//! It does not run anything. Declaring a database and placing the engine that
//! serves it are different jobs, and the second one belongs to workloads, which
//! already knows about failure domains. This decides what may exist, under what
//! name, with what isolation — and refuses the combinations that would be
//! unsafe or unnameable.

use serde::{Deserialize, Serialize};

/// The kind of thing a tenant is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// Ordinary tables.
    Relational,
    /// Embeddings and nearest-neighbour search. Postgres with pgvector.
    Vector,
    /// Measurements over time. Postgres with TimescaleDB.
    TimeSeries,
    /// Nodes and edges. Postgres with Apache AGE.
    Graph,
    /// Places and shapes. Postgres with PostGIS.
    Geospatial,
    /// Keys and values, in memory.
    KeyValue,
    /// Objects in buckets, over S3.
    Objects,
}

/// What actually serves a shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Postgres,
    /// The key-value store. Named for the fork rather than the original
    /// because the original's licence now carries network copyleft, which
    /// matters precisely because this system exists to serve other people.
    Valkey,
    /// S3-compatible object storage.
    ObjectStore,
}

impl Shape {
    pub fn engine(&self) -> Engine {
        match self {
            Shape::Relational
            | Shape::Vector
            | Shape::TimeSeries
            | Shape::Graph
            | Shape::Geospatial => Engine::Postgres,
            Shape::KeyValue => Engine::Valkey,
            Shape::Objects => Engine::ObjectStore,
        }
    }

    /// The extension a shape needs, where it is one.
    pub fn extension(&self) -> Option<&'static str> {
        match self {
            Shape::Vector => Some("vector"),
            Shape::TimeSeries => Some("timescaledb"),
            Shape::Graph => Some("age"),
            Shape::Geospatial => Some("postgis"),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Shape::Relational => "relational",
            Shape::Vector => "vector",
            Shape::TimeSeries => "time-series",
            Shape::Graph => "graph",
            Shape::Geospatial => "geospatial",
            Shape::KeyValue => "key-value",
            Shape::Objects => "objects",
        }
    }
}

/// How far apart two tenants' data is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// Shared tables, separated by policy on every query. Densest, and the only
    /// one where a single missed call leaks between tenants.
    Rows,
    /// A schema each, in one database.
    Schema,
    /// A database each. The default, and the only one where leaving is a dump.
    Database,
}

impl Isolation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Isolation::Rows => "rows",
            Isolation::Schema => "schema",
            Isolation::Database => "database",
        }
    }

    /// What an operator gives up by choosing this.
    pub fn caveat(&self) -> Option<&'static str> {
        match self {
            Isolation::Database => None,
            Isolation::Schema => Some(
                "one engine holds every tenant, so a restore touches all of them",
            ),
            Isolation::Rows => Some(
                "isolation depends on every query setting the tenant; one missed call leaks",
            ),
        }
    }
}

/// Something a tenant has been given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub tenant: String,
    pub name: String,
    pub shape: Shape,
    pub isolation: Isolation,
}

/// Names a bucket may have.
///
/// S3's rules, not ours: a bucket name appears in a hostname, so it has to be a
/// DNS label. Enforcing this at the point of asking beats discovering it when
/// the first client cannot resolve the endpoint.
pub fn valid_bucket(name: &str) -> Result<(), String> {
    if name.len() < 3 || name.len() > 63 {
        return Err("a bucket name is between 3 and 63 characters".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err("a bucket name may hold lowercase letters, digits, dashes and dots".into());
    }
    if name.starts_with(['-', '.']) || name.ends_with(['-', '.']) {
        return Err("a bucket name starts and ends with a letter or a digit".into());
    }
    if name.contains("..") {
        return Err("a bucket name does not contain two dots in a row".into());
    }
    // A name that parses as an address makes the endpoint ambiguous, and the
    // failure appears as a client silently talking to the wrong thing.
    if name.split('.').count() == 4 && name.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return Err("a bucket name may not look like an IP address".into());
    }
    Ok(())
}

/// Names a database may have.
pub fn valid_database(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 63 {
        return Err("a database name is between 1 and 63 characters".into());
    }
    if !name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return Err("a database name starts with a lowercase letter".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err("a database name may hold lowercase letters, digits and underscores".into());
    }
    Ok(())
}

/// Whether a grant may be made, given what already exists.
///
/// The interesting refusals are the ones about other tenants: a name that
/// collides across a boundary is how one tenant reads another's data by
/// accident, and it is far cheaper to refuse here than to discover later.
pub fn admits(existing: &[Grant], want: &Grant) -> Result<(), String> {
    match want.shape {
        Shape::Objects => valid_bucket(&want.name)?,
        _ => valid_database(&want.name)?,
    }
    if want.tenant.trim().is_empty() {
        return Err("a grant needs a tenant".into());
    }

    for g in existing {
        if g.name != want.name {
            continue;
        }
        // A bucket name is global to the object store, the way it is on every
        // S3 service, so two tenants cannot both have one.
        if want.shape == Shape::Objects {
            return Err(format!(
                "a bucket called `{}` already belongs to {}",
                want.name, g.tenant
            ));
        }
        if g.tenant == want.tenant && g.shape == want.shape {
            return Err(format!("{} already has `{}`", want.tenant, want.name));
        }
        // Same database name, different tenants, sharing one engine: under
        // schema or row isolation these land in the same place.
        if g.tenant != want.tenant
            && (want.isolation < Isolation::Database || g.isolation < Isolation::Database)
        {
            return Err(format!(
                "`{}` is taken by {} and this isolation shares one engine, so the two would collide",
                want.name, g.tenant
            ));
        }
    }
    Ok(())
}

/// How a tenant's data leaves.
///
/// The claim the whole isolation choice is in service of, made concrete: an
/// operator should be able to read this and know what they would run.
pub fn how_to_leave(g: &Grant) -> &'static str {
    match (g.shape, g.isolation) {
        (Shape::Objects, _) => "copy the bucket with any S3 client; nothing here is a special format",
        (_, Isolation::Database) => "one dump of one database, restorable anywhere Postgres runs",
        (_, Isolation::Schema) => "a dump of one schema, which no other tenant shares",
        (_, Isolation::Rows) => {
            "a filtered export somebody has to write, and check, for every table"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(tenant: &str, name: &str, shape: Shape, iso: Isolation) -> Grant {
        Grant { tenant: tenant.into(), name: name.into(), shape, isolation: iso }
    }

    #[test]
    fn the_shapes_that_are_postgres_say_which_extension_they_need() {
        assert_eq!(Shape::Vector.engine(), Engine::Postgres);
        assert_eq!(Shape::Vector.extension(), Some("vector"));
        assert_eq!(Shape::Graph.extension(), Some("age"));
        assert_eq!(Shape::TimeSeries.extension(), Some("timescaledb"));
        // Not everything is Postgres, and pretending otherwise would put an
        // object store behind a connection string.
        assert_eq!(Shape::Objects.engine(), Engine::ObjectStore);
        assert_eq!(Shape::KeyValue.engine(), Engine::Valkey);
        assert_eq!(Shape::Relational.extension(), None);
    }

    #[test]
    fn a_bucket_name_has_to_survive_being_a_hostname() {
        assert!(valid_bucket("photos").is_ok());
        assert!(valid_bucket("my-photos.2026").is_ok());
        assert!(valid_bucket("ab").is_err(), "too short");
        assert!(valid_bucket("My_Photos").is_err(), "uppercase and underscore");
        assert!(valid_bucket("-photos").is_err());
        assert!(valid_bucket("a..b").is_err());
        // The endpoint becomes ambiguous and a client talks to the wrong thing.
        assert!(valid_bucket("10.0.0.1").is_err());
    }

    #[test]
    fn a_database_name_is_a_postgres_identifier() {
        assert!(valid_database("orders").is_ok());
        assert!(valid_database("orders_2026").is_ok());
        assert!(valid_database("2026_orders").is_err(), "starts with a digit");
        assert!(valid_database("Orders").is_err());
        assert!(valid_database("").is_err());
    }

    #[test]
    fn two_tenants_cannot_hold_the_same_bucket() {
        // Bucket names are global on every S3 service, so this is not a policy
        // choice — it is the shape of the thing.
        let have = [g("alice", "photos", Shape::Objects, Isolation::Database)];
        let want = g("bob", "photos", Shape::Objects, Isolation::Database);
        assert!(admits(&have, &want).expect_err("collides").contains("alice"));
    }

    #[test]
    fn separate_databases_may_share_a_name_across_tenants() {
        // The point of the default isolation: `orders` in alice's database is
        // not `orders` in bob's, and refusing this would make the strongest
        // isolation feel more restrictive than the weakest.
        let have = [g("alice", "orders", Shape::Relational, Isolation::Database)];
        let want = g("bob", "orders", Shape::Relational, Isolation::Database);
        assert!(admits(&have, &want).is_ok());
    }

    #[test]
    fn a_shared_engine_makes_the_same_name_a_collision() {
        let have = [g("alice", "orders", Shape::Relational, Isolation::Schema)];
        let want = g("bob", "orders", Shape::Relational, Isolation::Database);
        assert!(admits(&have, &want).expect_err("collides").contains("collide"));
    }

    #[test]
    fn a_tenant_cannot_be_given_the_same_thing_twice() {
        let have = [g("alice", "orders", Shape::Relational, Isolation::Database)];
        let want = g("alice", "orders", Shape::Relational, Isolation::Database);
        assert!(admits(&have, &want).is_err());
    }

    #[test]
    fn every_isolation_says_how_a_tenant_leaves() {
        // The claim the default is in service of. An operator reading this
        // should know what they would actually run.
        let db = g("alice", "orders", Shape::Relational, Isolation::Database);
        assert!(how_to_leave(&db).contains("one dump"));
        let rows = g("alice", "orders", Shape::Relational, Isolation::Rows);
        assert!(how_to_leave(&rows).contains("somebody has to write"));
    }

    #[test]
    fn the_denser_isolations_state_what_they_cost() {
        assert!(Isolation::Database.caveat().is_none());
        assert!(Isolation::Schema.caveat().is_some());
        assert!(Isolation::Rows.caveat().expect("a caveat").contains("leaks"));
    }

    #[test]
    fn isolation_is_ordered_so_the_strongest_is_the_largest() {
        // Relied on by `admits`, and by anything choosing a default.
        assert!(Isolation::Database > Isolation::Schema);
        assert!(Isolation::Schema > Isolation::Rows);
    }
}
