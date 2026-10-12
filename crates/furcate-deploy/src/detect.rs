//! Working out what a source tree is, and refusing when it is not clear.
//!
//! The temptation here is to guess. A guess that half-works is worse than a
//! refusal, because it produces a deployed site that is missing pages nobody
//! notices until somebody follows a link — so every branch below either
//! recognises a framework it can name or says it does not.
//!
//! ## Why the framework is not the interesting output
//!
//! What the rest of the system needs is not "this is Next.js"; it is **which
//! runtime tier this needs** and **where the built files land**. A framework
//! name is how we work those out and how we explain the answer to an operator.
//! Everything downstream reads [`Plan`], not the name.

use serde::{Deserialize, Serialize};

/// What a built site needs in order to serve.
///
/// Deliberately ordered by cost. A site that can be static should be static:
/// no process to supervise, no memory to leak, nothing to restart, and a
/// rollback that is a pointer move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Files behind a web server. No runtime at all.
    Static,
    /// A long-lived process the machine supervises, reverse-proxied.
    Node,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Static => "static",
            Tier::Node => "node",
        }
    }
}

/// A framework this system can build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    NextStatic,
    NextServer,
    Astro,
    Vite,
    SvelteKit,
    Flask,
    FastApi,
    Django,
    Praecise,
    /// A Node application that is none of the above — its own server, started
    /// the way Node projects say they are started.
    Node,
    /// HTML on disk, already built by whatever made it.
    Plain,
    /// A program the tree already carries, built by whatever made it: a Rust
    /// or Go binary, say. Nothing is installed and nothing is inferred; the
    /// tree's `furcate-deploy.json` says how it starts, and that is all there
    /// is to know.
    Native,
}

impl Framework {
    pub fn as_str(&self) -> &'static str {
        match self {
            Framework::NextStatic => "next (static export)",
            Framework::NextServer => "next (server)",
            Framework::Astro => "astro",
            Framework::Vite => "vite",
            Framework::SvelteKit => "sveltekit",
            Framework::Flask => "flask",
            Framework::FastApi => "fastapi",
            Framework::Django => "django",
            Framework::Praecise => "praecise (agent app)",
            Framework::Node => "node (own server)",
            Framework::Plain => "static files",
            Framework::Native => "native (own binary)",
        }
    }
}

/// How to build a tree, and what to do with the result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub framework: Framework,
    pub tier: Tier,
    /// Shell-free: the program and its arguments, so nothing is word-split.
    pub build: Vec<String>,
    pub install: Vec<Vec<String>>,
    /// Where the build leaves what should be served, relative to the source.
    pub output: String,
    /// How to START a supervised tier, shell-free like the others.
    ///
    /// Empty for `Tier::Static`, which has nothing to start. A supervised tier
    /// with an empty `run` is a bug rather than a default: the deploy refuses
    /// instead of writing a unit that would fail at first start, because a unit
    /// that cannot start is discovered by whoever visits the site.
    ///
    /// The process is expected to honour `PORT` from the environment. That is
    /// the one convention this system imposes, it is what every framework here
    /// already does, and it is what lets the port be allocated by the deployer
    /// rather than hardcoded by the application.
    #[serde(default)]
    pub run: Vec<String>,
}

/// Why a tree could not be planned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// No manifest and no HTML: there is nothing here to serve.
    Empty,
    /// A `package.json` naming a framework this system has not been taught.
    Framework(String),
    /// The tree is a workspace, and this member cannot be deployed out of it.
    Member(String),
    /// The tree declared how it starts, and the declaration cannot be honoured.
    Declared(String),
}

impl std::fmt::Display for Unknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unknown::Empty => write!(
                f,
                "nothing here looks like a site: no package.json, and no index.html"
            ),
            Unknown::Member(m) | Unknown::Declared(m) => write!(f, "{m}"),
            Unknown::Framework(n) => write!(
                f,
                "`{n}` is not a framework this knows how to build, and it declares no \
                 `start` script to run it with. Give it a `start` script, add the \
                 framework to detect.rs, or build it yourself and deploy the output \
                 directory"
            ),
        }
    }
}

impl std::error::Error for Unknown {}

/// What the detector was able to read off the tree.
///
/// Passed in rather than read from disk so this is testable without a
/// filesystem, and so the caller — which already has to touch the disk — does
/// it in exactly one place.
#[derive(Clone, Debug, Default)]
pub struct Evidence<'a> {
    /// Parsed `package.json`, if there is one.
    pub package_json: Option<&'a serde_json::Value>,
    /// Contents of `next.config.*`, if there is one.
    pub next_config: Option<&'a str>,
    pub has_astro_config: bool,
    /// Contents of `astro.config.*`. Astro's tier turns on `output`, and a
    /// boolean "a config exists" cannot answer that.
    pub astro_config: Option<&'a str>,
    pub has_vite_config: bool,
    pub has_svelte_config: bool,
    /// A praecise app: `praecise.config.ts`, or one of the folders the framework
    /// treats as the app. "A folder is an app", so the folder is the evidence.
    pub has_praecise_layout: bool,
    /// Contents of `svelte.config.js`. SvelteKit's output is ENTIRELY
    /// adapter-dependent and the adapter is named here.
    pub svelte_config: Option<&'a str>,
    pub has_index_html: bool,
    /// Declared Python dependencies, from pyproject.toml or requirements.txt,
    /// lowercased. Normalised by the caller because PEP 503 says `Flask`,
    /// `flask` and `FLASK` are the same name and only one of them is what a
    /// project happened to type.
    pub python_deps: Vec<String>,
    /// `manage.py` at the root. The strongest Django signal there is: the
    /// dependency list can name django because something else pulled it in,
    /// but only a Django project has this file.
    pub has_manage_py: bool,
    /// The Django WSGI module path, e.g. `mysite.wsgi:application`, found by
    /// locating the package that holds `wsgi.py` beside `manage.py`. Without it
    /// there is nothing to hand gunicorn, and a placeholder that expands to
    /// nothing produces a unit that restarts forever.
    pub django_wsgi: Option<String>,
    /// Which Python installer to use, decided by lockfile.
    pub python_install: Option<PyInstall>,
    /// Which module exposes the ASGI app, as `package.module:attr`.
    ///
    /// `main:app` is the common case but far from the only one — a service laid
    /// out as `app/main.py` is `app.main:app`, and starting that as `main:app`
    /// fails with ModuleNotFoundError at first start rather than at deploy
    /// time. The caller looks at the tree; this only carries the answer.
    pub asgi_module: Option<String>,
    /// A lockfile tells us which package manager the project actually uses.
    /// Guessing npm on a pnpm project is how a build fails at install time
    /// with an error about a lockfile nobody mentioned.
    pub lockfile: Option<Manager>,
    /// How the tree says it is started, from `start` in `furcate-deploy.json`.
    /// See [`declared_commands`]; when present it is believed over anything
    /// this module would infer.
    pub declared_start: Option<Vec<String>>,
    /// How the tree says it is built, from `build` in the same file. `Some`
    /// of an empty list is a statement too: there is nothing to build.
    pub declared_build: Option<Vec<String>>,
}

/// Read `start` and `build` from a parsed `furcate-deploy.json`.
///
/// Each is a program and its arguments as a JSON array of strings, shell-free
/// like every command in a [`Plan`]. Either may be absent, which says nothing.
///
/// An argument is refused rather than quoted if it could mean something other
/// than itself on the way to `ExecStart`: whitespace, because the unit joins
/// arguments with spaces and `deploy relink` splits them again; quotes and
/// backslashes, which systemd unquotes; `%`, which systemd expands as a
/// specifier; and a `;`, which it reads as the start of a second command.
/// `${PORT}` stays allowed, because that expansion is the one convention the
/// platform imposes and every plan here already uses it.
#[allow(clippy::type_complexity)]
pub fn declared_commands(
    manifest: &serde_json::Value,
) -> Result<(Option<Vec<String>>, Option<Vec<String>>), String> {
    fn one(manifest: &serde_json::Value, key: &str) -> Result<Option<Vec<String>>, String> {
        let Some(v) = manifest.get(key) else {
            return Ok(None);
        };
        let list = v
            .as_array()
            .ok_or_else(|| format!("`{key}` must be an array: [\"node\", \"src/server.ts\"]"))?;
        let mut out = Vec::with_capacity(list.len());
        for a in list {
            let a = a
                .as_str()
                .ok_or_else(|| format!("every element of `{key}` must be a string"))?;
            if a.is_empty()
                || a.chars().any(|c| {
                    c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | '%' | ';')
                })
            {
                return Err(format!(
                    "`{a}` in `{key}` cannot be written into a unit as one argument; \
                     arguments may not be empty or contain whitespace, quotes, `\\`, `%` or `;`"
                ));
            }
            out.push(a.to_string());
        }
        Ok(Some(out))
    }
    let start = one(manifest, "start")?;
    if start.as_ref().is_some_and(|s| s.is_empty()) {
        return Err("`start` is empty; there is nothing to run".into());
    }
    Ok((start, one(manifest, "build")?))
}

/// How to install Python dependencies, chosen by which lockfile exists.
///
/// A lockfile is preferred over `requirements.txt` when both are present: the
/// lockfile is the one that pins transitively, and a project carrying both
/// usually generates the requirements file from the lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyInstall {
    Uv,
    Poetry,
    Pipenv,
    Pip,
    /// A PEP 621 `pyproject.toml` and no lockfile.
    ///
    /// Common for a service that was only ever built as a container: the image
    /// pinned the versions, so nothing in the repository had to. Without this
    /// the project looks like it has no dependencies at all, and the deploy
    /// gets as far as starting a process that cannot import its own imports.
    Pyproject,
}

impl PyInstall {
    /// Install into `.venv` inside the release, never system-wide. Two sites on
    /// one machine will disagree about a dependency eventually, and the loser
    /// of that argument should not be whichever deployed second.
    pub fn install(&self) -> Vec<Vec<String>> {
        // Everything goes through `uv`, including the plain-requirements case.
        //
        // `python3 -m venv` needs `ensurepip`, which Debian splits into a
        // separate package -- and /usr here is a read-only system extension, so
        // it cannot be apt-installed on the node. uv creates the environment
        // and installs into it with no system pip at all, which is why it ships
        // in the extension alongside node. It is also the only one of these
        // that resolves a lockfile and a requirements file with the same tool.
        let uv = |args: &[&str]| {
            std::iter::once("uv".to_string())
                .chain(args.iter().map(|a| a.to_string()))
                .collect::<Vec<String>>()
        };
        match self {
            PyInstall::Uv => vec![uv(&["sync", "--frozen"])],
            PyInstall::Poetry => vec![vec!["poetry".into(), "install".into(), "--no-root".into()]],
            PyInstall::Pipenv => vec![vec!["pipenv".into(), "install".into(), "--deploy".into()]],
            // Install the project itself, which pulls its declared
            // dependencies. Not `uv sync`, which requires a lockfile.
            PyInstall::Pyproject => vec![
                uv(&["venv", "--clear", ".venv"]),
                uv(&["pip", "install", "--python", ".venv", "."]),
            ],
            PyInstall::Pip => vec![
                // --clear because a deploy must be repeatable. Without it a
                // redeploy dies on "a virtual environment already exists",
                // which makes the SECOND deploy of every Python site fail.
                uv(&["venv", "--clear", ".venv"]),
                uv(&["pip", "install", "--python", ".venv", "-r", "requirements.txt"]),
            ],
        }
    }
    /// The interpreter a run command should use.
    pub fn bin(&self, prog: &str) -> String {
        match self {
            PyInstall::Uv => format!("uv run {prog}"),
            _ => format!(".venv/bin/{prog}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manager {
    Npm,
    Pnpm,
    Yarn,
}

impl Manager {
    /// How to fetch dependencies, locked and without executing them.
    ///
    /// Two properties, both non-negotiable.
    ///
    /// **Locked.** `npm ci` needs a lockfile in step with package.json and
    /// fails loudly when it is not. A build that quietly resolves different
    /// versions than the ones somebody tested is the whole problem deploys
    /// exist to prevent.
    ///
    /// **Scripts off.** Installing a package otherwise *runs* it: `postinstall`
    /// and friends execute during install, from every transitive dependency,
    /// before a line of the site's own code. That is the vector behind
    /// event-stream, the Nx compromise and Shai-Hulud, and it is not a rare
    /// failure — it is the ordinary behaviour of the tool. A deploy is a place
    /// where somebody else's dependency tree meets the operator's machine, so
    /// nothing from it executes at install time.
    ///
    /// The site's own build still runs, because building the site is the job.
    /// The difference is that it is the code somebody chose to deploy rather
    /// than whatever their fourth-level dependency shipped this morning.
    ///
    /// A package that genuinely needs its install scripts — native modules
    /// compiled locally — will fail here rather than silently working. That is
    /// the right way round: an explicit failure an operator can decide about,
    /// not silent execution nobody asked for.
    fn install(&self, locked: bool) -> Vec<String> {
        match self {
            Manager::Npm => vec!["npm".into(), if locked { "ci" } else { "install" }.into(), "--ignore-scripts".into()],
            Manager::Pnpm => vec![
                "pnpm".into(),
                "install".into(),
                if locked { "--frozen-lockfile" } else { "--no-frozen-lockfile" }.into(),
                "--ignore-scripts".into(),
            ],
            // --immutable means "the lockfile is already right", so it is exactly
            // as wrong without one as `npm ci` is.
            Manager::Yarn if locked => vec![
                "yarn".into(),
                "install".into(),
                "--immutable".into(),
                "--mode=skip-build".into(),
            ],
            Manager::Yarn => vec!["yarn".into(), "install".into(), "--mode=skip-build".into()],
        }
    }

    /// Run a member's script from the workspace root.
    ///
    /// Addressed by package NAME rather than directory: all three managers
    /// accept a name, only some accept a path, and the name is what the member
    /// itself declares. A directory is where it happens to sit today.
    fn run_in(&self, member: &str, script: &str) -> Vec<String> {
        match self {
            Manager::Npm => vec![
                "npm".into(),
                "run".into(),
                script.into(),
                format!("--workspace={member}"),
            ],
            Manager::Pnpm => vec![
                "pnpm".into(),
                "--filter".into(),
                member.into(),
                "run".into(),
                script.into(),
            ],
            Manager::Yarn => vec![
                "yarn".into(),
                "workspace".into(),
                member.into(),
                "run".into(),
                script.into(),
            ],
        }
    }

    fn run(&self, script: &str) -> Vec<String> {
        match self {
            Manager::Npm => vec!["npm".into(), "run".into(), script.into()],
            Manager::Pnpm => vec!["pnpm".into(), "run".into(), script.into()],
            Manager::Yarn => vec!["yarn".into(), "run".into(), script.into()],
        }
    }
}

/// Does this Next config ask for a static export?
///
/// Read from the config text rather than by running the config, because
/// running it means running the project's JavaScript to find out how to build
/// the project — and this decision is made before anything of theirs executes.
fn next_exports(config: Option<&str>) -> bool {
    let Some(c) = config else { return false };
    // Tolerant of quoting and spacing, and deliberately not a parser: the
    // question is only whether the author asked for `export`, and a wrong
    // answer here is caught downstream when the output directory is missing.
    let flat: String = c.chars().filter(|c| !c.is_whitespace()).collect();
    flat.contains("output:\"export\"") || flat.contains("output:'export'")
}

/// Does `package.json` declare this script?
///
/// Declared and non-empty. A `"start": ""` is not a way to start anything, and
/// treating it as one produces a unit that exits immediately and a health gate
/// that fails with nothing to point at.
fn script(pkg: &serde_json::Value, name: &str) -> bool {
    pkg.get("scripts")
        .and_then(|s| s.get(name))
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.trim().is_empty())
}

fn dep(pkg: &serde_json::Value, name: &str) -> bool {
    ["dependencies", "devDependencies"]
        .iter()
        .any(|k| pkg.get(k).and_then(|d| d.get(name)).is_some())
}

/// The npm package praecise's runtime is published as.
pub const PRAECISE_PACKAGE: &str = "@praecise/harness";

/// The name it was published under before, deprecated rather than bridged.
///
/// Still recognised, because every agent app deployed today depends on it and a
/// redeploy must not turn one into "not a framework this knows" or hand it a
/// launcher importing a package it does not have. Nothing new is steered to it.
pub const PRAECISE_PACKAGE_LEGACY: &str = "praecise";

/// Which of the two names an app's launcher should import from.
///
/// The one the app actually depends on, read from every manifest that governs
/// it (a workspace member and its root). The current name wins when both are
/// present, which is the state an app is in half way through migrating. When
/// neither is named — an app recognised by its layout alone, its dependency
/// hoisted from somewhere this was not shown — the current name, because that
/// is the one a fresh install resolves.
pub fn praecise_package(manifests: &[&serde_json::Value]) -> &'static str {
    if manifests.iter().any(|p| dep(p, PRAECISE_PACKAGE)) {
        PRAECISE_PACKAGE
    } else if manifests.iter().any(|p| dep(p, PRAECISE_PACKAGE_LEGACY)) {
        PRAECISE_PACKAGE_LEGACY
    } else {
        PRAECISE_PACKAGE
    }
}

/// Read a tree and say how to build it.
/// Plan one member of a workspace.
///
/// Install and build happen at the ROOT, because the root is the only place a
/// workspace resolves. A member's dependency on a sibling is a link that the
/// root install creates — install from inside the member and the sibling is
/// simply not there; build the member alone and it builds against whatever the
/// sibling left behind last time, which is the kind of failure that only shows
/// up after a dependency changes and nobody can explain why.
///
/// Only the *run* is scoped to the member, because the run is the one thing
/// that genuinely is about the member.
pub fn plan_member(
    root: &Evidence<'_>,
    member: &Evidence<'_>,
    member_dir: &str,
) -> Result<Plan, Unknown> {
    let root_pkg = root
        .package_json
        .ok_or_else(|| Unknown::Member("the workspace root has no package.json".into()))?;
    let member_pkg = member
        .package_json
        .ok_or_else(|| Unknown::Member(format!("{member_dir} has no package.json")))?;
    let member_name = member_pkg
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| {
            Unknown::Member(format!(
                "{member_dir} declares no name, so there is nothing to scope the run to"
            ))
        })?;

    // What KIND of thing the member is, decided from the member's own evidence
    // — a Next app in a monorepo is still a Next app.
    let inner = plan(member)?;

    // The lockfile that governs is the root's. A workspace has one.
    let mgr = root.lockfile.unwrap_or(Manager::Npm);
    let locked = root.lockfile.is_some();

    // The root's own build script is the workspace's declared way of building
    // itself, dependency order included — that is what turbo and nx are for.
    // Preferring it over building the member alone is what makes a sibling
    // dependency come out right. A member that declares its build outright is
    // believed over both; the command runs from the root like the others.
    let build = if let Some(b) = &member.declared_build {
        b.clone()
    } else if script(root_pkg, "build") {
        mgr.run("build")
    } else if !inner.build.is_empty() {
        mgr.run_in(member_name, "build")
    } else {
        Vec::new()
    };

    let run = if inner.tier == Tier::Static {
        Vec::new()
    } else if let Some(start) = &member.declared_start {
        // Relative to the release, which for a supervised member is the whole
        // workspace (see `output` below), so a declared path names the member's
        // directory from the root: ["node", "packages/api/dist/server.js"].
        start.clone()
    } else {
        if !script(member_pkg, "start") {
            return Err(Unknown::Member(format!(
                "{member_name} is a supervised tier but declares no `start` script, \
                 so there is no way to start it"
            )));
        }
        mgr.run_in(member_name, "start")
    };

    Ok(Plan {
        framework: inner.framework,
        tier: inner.tier,
        install: vec![mgr.install(locked)],
        build,
        // What gets PUBLISHED, and the two tiers want different things.
        //
        // A static member is a directory of files, so publish that directory —
        // rebased on the root, because what the member calls `out` is
        // `packages/site/out` from here.
        //
        // A supervised member publishes the WHOLE workspace. Its release has
        // its dependencies installed into it, and a workspace only installs
        // from its root: without the root manifest, the lockfile and the
        // sibling packages in the release, `npm ci` there has nothing to
        // resolve and the member cannot start. Publishing just the member
        // directory would produce a release that builds, places, and then
        // fails at the point a visitor arrives.
        output: if inner.tier == Tier::Static {
            format!("{}/{}", member_dir.trim_end_matches('/'), inner.output)
        } else {
            ".".into()
        },
        run,
    })
}

pub fn plan(ev: &Evidence<'_>) -> Result<Plan, Unknown> {
    // A tree that says how it starts is believed before anything is inferred.
    //
    // Inference is right when nothing was said and wrong the moment it
    // contradicts what was. The case that forced this: a workspace that is its
    // own HTTP server lists `praecise` among its dev dependencies, so it was
    // planned as an agent app, and every deploy wrote a praecise loader into
    // `.furcate-serve.mjs` and started that. Operators put the real launcher
    // back by hand after each one. No evidence this module reads can tell a
    // server that uses a framework as a tool from an app built on it; the
    // project can, in one line.
    //
    // Node only, because the platform installs a declared server's
    // dependencies from its package.json. Checked before Python for the same
    // reason Python is checked before package.json: the more specific
    // statement wins, and nothing is more specific than the project saying so.
    if let Some(start) = &ev.declared_start {
        let Some(pkg) = ev.package_json else {
            // No package.json and no Python project: the tree carries its own
            // program. That is a statement, not a gap, so it is planned as
            // exactly what it says and nothing is installed around it.
            //
            // A Python project that declares `start` is still refused: it has
            // dependencies this would silently skip installing, and a service
            // that fails on its first import is found by whoever calls it.
            if ev.python_install.is_some() {
                return Err(Unknown::Declared(
                    "furcate-deploy.json declares `start` for a Python project. A declared \
                     start is honoured for Node servers and for a program the tree already \
                     carries; a Python service is started from its framework"
                        .into(),
                ));
            }
            return Ok(Plan {
                framework: Framework::Native,
                tier: Tier::Node,
                install: Vec::new(),
                build: ev.declared_build.clone().unwrap_or_default(),
                output: ".".into(),
                run: start.clone(),
            });
        };
        let locked = ev.lockfile.is_some();
        let mgr = ev.lockfile.unwrap_or(Manager::Npm);
        return Ok(Plan {
            framework: Framework::Node,
            tier: Tier::Node,
            install: vec![mgr.install(locked)],
            build: match &ev.declared_build {
                Some(b) => b.clone(),
                None if script(pkg, "build") => mgr.run("build"),
                None => Vec::new(),
            },
            output: ".".into(),
            run: start.clone(),
        });
    }

    // Python first: a repo can carry a package.json for front-end tooling and
    // still be a Python service. Deciding on package.json alone would call a
    // Django project with a Tailwind build "vite" and serve its static folder.
    if let Some(install) = ev.python_install {
        let has = |n: &str| ev.python_deps.iter().any(|d| d == n);

        // manage.py beats the dependency list. A list can name django because
        // something else pulled it in; only a Django project has this file.
        if ev.has_manage_py || has("django") {
            // Refuse rather than guess. `mysite.wsgi:application` cannot be
            // inferred from the dependency list, and a wrong module name yields
            // a unit that starts, fails and restarts forever.
            let Some(wsgi) = ev.django_wsgi.clone() else {
                return Err(Unknown::Framework(
                    "django (no <project>/wsgi.py found beside manage.py)".into(),
                ));
            };
            return Ok(Plan {
                framework: Framework::Django,
                tier: Tier::Node,
                install: install.install(),
                build: vec![],
                output: ".".into(),
                // WSGI through gunicorn. Django documents both interfaces and
                // states no preference, so this takes the one whose entry point
                // `startproject` has always generated. ASGI is a deliberate
                // choice an operator makes, not a default guessed from a tree.
                run: vec![
                    install.bin("gunicorn"),
                    "--bind".into(),
                    "127.0.0.1:${PORT}".into(),
                    "--workers".into(),
                    "3".into(),
                    wsgi,
                ],
            });
        }
        if has("fastapi") {
            return Ok(Plan {
                framework: Framework::FastApi,
                tier: Tier::Node,
                install: install.install(),
                build: vec![],
                output: ".".into(),
                // NOT `fastapi run`: fastapi-cli is not a base dependency, it
                // ships only under the `standard` extra, so a project listing
                // plain `fastapi` has no `fastapi` binary and the unit would
                // fail 203/EXEC. uvicorn is the documented alternative and is
                // present far more often.
                run: vec![
                    install.bin("uvicorn"),
                    ev.asgi_module.clone().unwrap_or_else(|| "main:app".into()),
                    "--host".into(),
                    "127.0.0.1".into(),
                    "--port".into(),
                    "${PORT}".into(),
                ],
            });
        }
        if has("flask") {
            return Ok(Plan {
                framework: Framework::Flask,
                tier: Tier::Node,
                install: install.install(),
                build: vec![],
                output: ".".into(),
                // Flask is WSGI-only and its deployment docs list gunicorn
                // first. `flask run` is the development server and its own docs
                // say not to deploy it.
                run: vec![
                    install.bin("gunicorn"),
                    "--bind".into(),
                    "127.0.0.1:${PORT}".into(),
                    "--workers".into(),
                    "3".into(),
                    "app:app".into(),
                ],
            });
        }
        // A Python project whose framework is not recognised. Refuse by name
        // rather than guess an entry point: a wrong module:callable produces a
        // unit that starts, fails, and restarts forever.
        return Err(Unknown::Framework("python".into()));
    }

    let Some(pkg) = ev.package_json else {
        // No manifest. HTML on disk is still a site, and is the one case that
        // needs no build at all.
        return if ev.has_index_html {
            Ok(Plan {
                framework: Framework::Plain,
                tier: Tier::Static,
                install: vec![],
                build: vec![],
                output: ".".into(),
                run: vec![],
            })
        } else {
            Err(Unknown::Empty)
        };
    };

    // Default to npm when no lockfile is present: it is the manager whose
    // absence of a lockfile is least surprising, and install still works.
    // Whether a lockfile was actually FOUND, not merely which manager we guessed.
    // `npm ci` requires one and exits 1 without it -- so defaulting to npm and
    // then running `ci` fails on exactly the projects that have no lockfile,
    // which is every freshly written app.
    let locked = ev.lockfile.is_some();
    let mgr = ev.lockfile.unwrap_or(Manager::Npm);

    if dep(pkg, PRAECISE_PACKAGE) || dep(pkg, PRAECISE_PACKAGE_LEGACY) || ev.has_praecise_layout {
        return Ok(Plan {
            framework: Framework::Praecise,
            tier: Tier::Node,
            install: vec![mgr.install(locked)],
            // No build step. praecise compiles the app itself, into
            // .praecise/build, using the TypeScript in the project -- so a
            // `npm run build` here would either not exist or build something
            // else entirely.
            build: vec![],
            output: ".".into(),
            // The launcher the deploy writes beside the app. `praecise-harness dev`
            // would also serve HTTP, but it watches the tree and reloads, which
            // is not what a release directory wants.
            run: vec!["node".into(), ".furcate-serve.mjs".into()],
        });
    }
    if dep(pkg, "next") {
        let exports = next_exports(ev.next_config);
        return Ok(Plan {
            framework: if exports {
                Framework::NextStatic
            } else {
                Framework::NextServer
            },
            tier: if exports { Tier::Static } else { Tier::Node },
            install: vec![mgr.install(locked)],
            build: mgr.run("build"),
            // `out/` only exists under `output: 'export'`. A server build
            // serves from the project root through its own server.
            output: if exports { "out".into() } else { ".".into() },
            // A Next server build is started through the project's own script
            // rather than `node .next/standalone/server.js`: standalone does
            // not copy `public/` or `.next/static`, so starting it directly
            // serves a site with no images and no CSS -- which looks like a
            // broken deploy and is a missing copy step. `next start` serves
            // from the project tree where both still are.
            run: if exports { vec![] } else { mgr.run("start") },
        });
    }
    if dep(pkg, "astro") || ev.has_astro_config {
        let cfg = ev.astro_config.unwrap_or("");
        // `output: 'server'` is the only value that needs a process. Astro 7
        // removed 'hybrid', so the choice really is static or server, and a
        // static build with per-route `prerender = false` still needs an
        // adapter -- which is what the second test catches.
        let server = cfg.contains("output: 'server'")
            || cfg.contains("output: \"server\"")
            || cfg.contains("adapter:");
        if !server {
            return Ok(Plan {
                framework: Framework::Astro,
                tier: Tier::Static,
                install: vec![mgr.install(locked)],
                build: mgr.run("build"),
                output: "dist".into(),
                run: vec![],
            });
        }
        // An adapter in `middleware` mode exports a handler for an existing
        // server rather than starting one. There is nothing here to supervise,
        // and pretending otherwise gives a unit that exits immediately.
        if cfg.contains("mode: 'middleware'") || cfg.contains("mode: \"middleware\"") {
            return Err(Unknown::Framework(
                "astro (@astrojs/node in middleware mode exports a handler, not a server)".into(),
            ));
        }
        if !dep(pkg, "@astrojs/node") {
            return Err(Unknown::Framework(
                "astro (server output needs an adapter; only @astrojs/node can be supervised here)"
                    .into(),
            ));
        }
        return Ok(Plan {
            framework: Framework::Astro,
            tier: Tier::Node,
            install: vec![mgr.install(locked)],
            build: mgr.run("build"),
            output: ".".into(),
            // @astrojs/node standalone writes dist/server/entry.mjs and reads
            // HOST and PORT from the environment, both of which the unit sets.
            run: vec!["node".into(), "dist/server/entry.mjs".into()],
        });
    }
    if dep(pkg, "@sveltejs/kit") || ev.has_svelte_config {
        let cfg = ev.svelte_config.unwrap_or("");
        // adapter-auto resolves at BUILD time by sniffing the CI environment --
        // Vercel, Netlify, Cloudflare, and so on. On a machine that is none of
        // those it cannot decide, so its output is genuinely unpredictable.
        // Refusing names the fix; guessing produces a site that builds and does
        // not serve.
        if cfg.contains("adapter-auto") || dep(pkg, "@sveltejs/adapter-auto") {
            return Err(Unknown::Framework(
                "sveltekit (adapter-auto cannot be resolved off a known platform — \
                 set adapter-node or adapter-static explicitly)"
                    .into(),
            ));
        }
        if cfg.contains("adapter-static") || dep(pkg, "@sveltejs/adapter-static") {
            return Ok(Plan {
                framework: Framework::SvelteKit,
                tier: Tier::Static,
                install: vec![mgr.install(locked)],
                build: mgr.run("build"),
                // adapter-static defaults `pages` and `assets` to `build`.
                output: "build".into(),
                run: vec![],
            });
        }
        if cfg.contains("adapter-node") || dep(pkg, "@sveltejs/adapter-node") {
            return Ok(Plan {
                framework: Framework::SvelteKit,
                tier: Tier::Node,
                install: vec![mgr.install(locked)],
                build: mgr.run("build"),
                output: ".".into(),
                // `node build` is what adapter-node documents; it resolves
                // build/index.js. HOST and PORT come from the environment.
                run: vec!["node".into(), "build".into()],
            });
        }
        // A platform adapter (vercel, netlify, cloudflare) builds for somewhere
        // that is not this machine.
        return Err(Unknown::Framework(
            "sveltekit (no adapter-node or adapter-static found — a platform \
             adapter builds for somewhere other than this machine)"
                .into(),
        ));
    }
    if dep(pkg, "vite") || ev.has_vite_config {
        return Ok(Plan {
            framework: Framework::Vite,
            tier: Tier::Static,
            install: vec![mgr.install(locked)],
            build: mgr.run("build"),
            output: "dist".into(),
            run: vec![],
        });
    }

    // A Node application that is none of the frameworks above.
    //
    // The evidence is a `start` script, because that is what Node projects use
    // to say how they are started — it is the one convention shared by projects
    // that share nothing else. Guessing an entry point instead (server.js,
    // index.js, main) would be inventing a contract the project never agreed
    // to, and getting it wrong produces a site that deploys and does not serve.
    //
    // `build` is run only when declared. Plenty of servers have nothing to
    // build, and running a script that does not exist fails the deploy for a
    // reason that has nothing to do with the application.
    if script(pkg, "start") {
        return Ok(Plan {
            framework: Framework::Node,
            tier: Tier::Node,
            install: vec![mgr.install(locked)],
            build: if script(pkg, "build") { mgr.run("build") } else { vec![] },
            // The release directory itself: a server serves from where it runs,
            // and there is no build output directory to name.
            output: ".".into(),
            run: mgr.run("start"),
        });
    }

    let named = pkg
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("this project")
        .to_string();
    Err(Unknown::Framework(named))
}

#[cfg(test)]
mod workspace_tests {
    use super::*;
    use serde_json::json;

    fn ev<'a>(pkg: &'a serde_json::Value, lock: Option<Manager>) -> Evidence<'a> {
        Evidence {
            package_json: Some(pkg),
            lockfile: lock,
            ..Default::default()
        }
    }

    #[test]
    fn a_member_installs_and_builds_at_the_root_and_runs_scoped_to_itself() {
        let root = json!({
            "name": "acme",
            "workspaces": ["packages/*"],
            "scripts": {"build": "turbo run build"}
        });
        let member = json!({
            "name": "@acme/api",
            "scripts": {"start": "node dist/server.js", "build": "tsc -p tsconfig.json"}
        });
        let p = plan_member(
            &ev(&root, Some(Manager::Npm)),
            &ev(&member, None),
            "packages/api",
        )
        .unwrap();

        // Root install — the only place the workspace resolves.
        assert_eq!(p.install, vec![vec!["npm", "ci", "--ignore-scripts"]]);
        // The workspace's own build, so siblings are built in order.
        assert_eq!(p.build, vec!["npm", "run", "build"]);
        // Run scoped to the member.
        assert_eq!(
            p.run,
            vec!["npm", "run", "start", "--workspace=@acme/api"]
        );
        assert_eq!(p.tier, Tier::Node);
    }

    #[test]
    fn without_a_root_build_script_the_member_is_built_on_its_own() {
        let root = json!({"name": "w", "workspaces": ["packages/*"]});
        let member = json!({
            "name": "@w/api",
            "scripts": {"start": "node s.js", "build": "tsc"}
        });
        let p = plan_member(&ev(&root, Some(Manager::Npm)), &ev(&member, None), "packages/api")
            .unwrap();
        assert_eq!(p.build, vec!["npm", "run", "build", "--workspace=@w/api"]);
    }

    #[test]
    fn a_members_output_is_named_from_the_workspace_root() {
        // A static member: what it calls `out` is not `out` from the root.
        let root = json!({"name": "w", "workspaces": ["packages/*"]});
        let member = json!({
            "name": "@w/site",
            "dependencies": {"next": "15.0.0"},
            "scripts": {"build": "next build"}
        });
        let m = Evidence {
            package_json: Some(&member),
            next_config: Some("module.exports = { output: 'export' }"),
            ..Default::default()
        };
        let p = plan_member(&ev(&root, Some(Manager::Npm)), &m, "packages/site").unwrap();
        assert_eq!(p.tier, Tier::Static);
        assert!(
            p.output.starts_with("packages/site/"),
            "output not rebased on the root: {}",
            p.output
        );
        // Nothing to supervise, so nothing to start.
        assert!(p.run.is_empty());
    }

    #[test]
    fn a_supervised_member_publishes_the_whole_workspace_not_just_itself() {
        // Its release gets `npm ci` run inside it, and a workspace installs
        // only from its root. Publish the member alone and there is no root
        // manifest, no lockfile and no sibling to resolve against.
        let root = json!({
            "name": "acme",
            "workspaces": ["packages/*"],
            "scripts": {"build": "turbo run build"}
        });
        let member = json!({"name": "@acme/api", "scripts": {"start": "node dist/server.js"}});
        let p = plan_member(
            &ev(&root, Some(Manager::Npm)),
            &ev(&member, None),
            "packages/api",
        )
        .unwrap();
        assert_eq!(p.tier, Tier::Node);
        assert_eq!(p.output, ".", "a supervised member must publish its workspace");
    }

    #[test]
    fn a_supervised_member_with_no_start_script_is_refused_not_guessed() {
        // A recognised server framework — so the question is not "what is this",
        // it is "how does it start". A member with no framework AND no start
        // script is refused earlier, as an unknown framework, which is a
        // different and equally correct answer.
        let root = json!({"name": "w", "workspaces": ["packages/*"]});
        let member = json!({
            "name": "@w/api",
            "dependencies": {"next": "15.0.0"},
            "scripts": {"build": "next build"}
        });
        let e = plan_member(&ev(&root, Some(Manager::Npm)), &ev(&member, None), "packages/api")
            .unwrap_err();
        // It is refused for being unstartable, not for being an unknown
        // framework — the distinction is what tells the operator what to fix.
        assert!(matches!(e, Unknown::Member(_)), "wrong refusal: {e:?}");
        assert!(e.to_string().contains("start"), "unhelpful: {e}");
    }

    #[test]
    fn an_unlocked_workspace_does_not_get_a_locked_install() {
        let root = json!({"name": "w", "workspaces": ["packages/*"]});
        let member = json!({"name": "@w/api", "scripts": {"start": "node s.js"}});
        let p = plan_member(&ev(&root, None), &ev(&member, None), "packages/api").unwrap();
        assert_eq!(p.install, vec![vec!["npm", "install", "--ignore-scripts"]]);
    }
}

#[cfg(test)]
mod node_tier_tests {
    use super::*;
    use serde_json::json;

    fn ev(pkg: &serde_json::Value) -> Evidence<'_> {
        Evidence {
            package_json: Some(pkg),
            next_config: None,
            has_astro_config: false,
            astro_config: None,
            has_vite_config: false,
            has_svelte_config: false,
            has_praecise_layout: false,
            svelte_config: None,
            has_index_html: false,
            python_deps: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn a_plain_node_server_is_supervised_and_started_by_its_own_script() {
        let pkg = json!({"name": "api", "scripts": {"start": "node dist/server.js"}});
        let plan = plan(&ev(&pkg)).expect("a start script is enough");
        assert_eq!(plan.framework, Framework::Node);
        assert_eq!(plan.tier, Tier::Node);
        assert_eq!(plan.run, vec!["npm", "run", "start"]);
        // Nothing to build was declared, so nothing is built.
        assert!(plan.build.is_empty());
    }

    #[test]
    fn a_declared_build_is_run_and_an_undeclared_one_is_not() {
        let pkg = json!({
            "name": "api",
            "scripts": {"start": "node dist/server.js", "build": "tsc -b"}
        });
        let plan = plan(&ev(&pkg)).unwrap();
        assert_eq!(plan.build, vec!["npm", "run", "build"]);
    }

    #[test]
    fn without_a_start_script_it_refuses_rather_than_guessing_an_entry_point() {
        // server.js sitting in the directory is not permission to run it.
        let pkg = json!({"name": "api", "scripts": {"test": "vitest"}});
        let err = plan(&ev(&pkg)).unwrap_err();
        assert_eq!(err, Unknown::Framework("api".into()));
        // And the operator is told the way out.
        assert!(err.to_string().contains("`start` script"), "unhelpful: {err}");
    }

    #[test]
    fn an_empty_start_script_is_not_a_way_to_start_anything() {
        let pkg = json!({"name": "api", "scripts": {"start": "   "}});
        assert!(plan(&ev(&pkg)).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pkg(deps: serde_json::Value) -> serde_json::Value {
        json!({"name": "a-site", "dependencies": deps})
    }

    #[test]
    fn a_next_project_without_an_export_needs_a_node_process() {
        let p = pkg(json!({"next": "^16.0.0"}));
        let plan = plan(&Evidence {
            package_json: Some(&p),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(plan.tier, Tier::Node);
        assert_eq!(plan.framework, Framework::NextServer);
    }

    #[test]
    fn a_next_project_that_exports_is_static_and_serves_from_out() {
        let p = pkg(json!({"next": "^16.0.0"}));
        let plan = plan(&Evidence {
            package_json: Some(&p),
            next_config: Some(r#"export default { output: "export" };"#),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(plan.tier, Tier::Static);
        assert_eq!(plan.output, "out");
    }

    #[test]
    fn the_export_check_survives_the_quoting_people_actually_use() {
        // Single quotes, and spread over lines, because both are ordinary and
        // a check that only matched one of them would be a silent downgrade
        // to a node process for a site that needs none.
        for c in [
            "export default {\n  output: 'export',\n}",
            "const c={output:\"export\"};export default c",
            "export default {\n  output:   'export'\n}",
        ] {
            assert!(next_exports(Some(c)), "should have matched: {c}");
        }
        assert!(!next_exports(Some("export default { reactStrictMode: true }")));
        assert!(!next_exports(None));
    }

    #[test]
    fn html_on_disk_is_a_site_and_needs_no_build() {
        let plan = plan(&Evidence {
            has_index_html: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(plan.framework, Framework::Plain);
        assert!(plan.build.is_empty(), "there is nothing to build");
    }

    #[test]
    fn an_empty_directory_is_refused_rather_than_deployed() {
        assert_eq!(plan(&Evidence::default()).unwrap_err(), Unknown::Empty);
    }

    #[test]
    fn an_unrecognised_framework_is_named_in_the_refusal() {
        let p = pkg(json!({"some-framework": "1"}));
        let e = plan(&Evidence {
            package_json: Some(&p),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(e, Unknown::Framework("a-site".into()));
        // The message has to tell somebody what to do next, not only that
        // the answer is no.
        assert!(e.to_string().contains("deploy the output directory"));
    }

    #[test]
    fn the_lockfile_picks_the_package_manager() {
        let p = pkg(json!({"astro": "^4"}));
        let plan = plan(&Evidence {
            package_json: Some(&p),
            lockfile: Some(Manager::Pnpm),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            plan.install,
            vec![vec!["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]]
        );
    }

    #[test]
    fn no_manager_executes_dependency_code_at_install_time() {
        // Installing a package otherwise runs it, from every transitive
        // dependency, before any of the site's own code — the vector behind
        // event-stream, Nx and Shai-Hulud. A deploy is where somebody else's
        // dependency tree meets the operator's machine.
        for m in [Manager::Npm, Manager::Pnpm, Manager::Yarn] {
            let i = m.install(true).join(" ");
            assert!(
                i.contains("--ignore-scripts") || i.contains("skip-build"),
                "{i} would execute dependency install scripts"
            );
        }
    }

    #[test]
    fn installs_are_locked_for_every_manager() {
        // A deploy that resolves different versions than the ones somebody
        // tested is the failure this whole system exists to prevent, so no
        // manager may install loosely.
        for m in [Manager::Npm, Manager::Pnpm, Manager::Yarn] {
            let i = m.install(true).join(" ");
            assert!(
                i.contains("ci") || i.contains("frozen") || i.contains("immutable"),
                "{i} does not pin the lockfile"
            );
        }
    }

    #[test]
    fn a_dev_dependency_counts_as_evidence() {
        let p = json!({"name":"s","devDependencies":{"vite":"^5"}});
        let plan = plan(&Evidence {
            package_json: Some(&p),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(plan.framework, Framework::Vite);
    }
}

#[cfg(test)]
mod declared_tests {
    use super::*;
    use serde_json::json;

    fn declared(manifest: serde_json::Value) -> (Option<Vec<String>>, Option<Vec<String>>) {
        declared_commands(&manifest).unwrap()
    }

    /// The workspace that forced this, as its package.json reads: a Next front
    /// end and its own server, with praecise only as a dev dependency.
    fn own_server_workspace() -> serde_json::Value {
        json!({
            "name": "recursive-self-workspace",
            "type": "module",
            "scripts": {"start": "node src/server.ts", "build": "next build"},
            "dependencies": {"next": "16", "pg": "8"},
            "devDependencies": {"praecise": "1", "typescript": "5"}
        })
    }

    #[test]
    fn without_a_declaration_that_workspace_is_still_read_as_an_agent_app() {
        // Recorded so the test below means something: inference alone gets
        // this tree wrong, and nothing in package.json can say otherwise.
        let pkg = own_server_workspace();
        let p = plan(&Evidence { package_json: Some(&pkg), ..Default::default() }).unwrap();
        assert_eq!(p.framework, Framework::Praecise);
        assert_eq!(p.run, vec!["node", ".furcate-serve.mjs"]);
    }

    #[test]
    fn a_declared_start_is_believed_over_every_inference() {
        let pkg = own_server_workspace();
        let (start, build) = declared(json!({"start": ["node", "src/server.ts"]}));
        let p = plan(&Evidence {
            package_json: Some(&pkg),
            lockfile: Some(Manager::Npm),
            declared_start: start,
            declared_build: build,
            ..Default::default()
        })
        .unwrap();
        // Not praecise, so the deploy writes no loader over the launcher, and
        // not the generated launcher, so the app's own server is what runs.
        assert_eq!(p.framework, Framework::Node);
        assert_eq!(p.tier, Tier::Node);
        assert_eq!(p.run, vec!["node", "src/server.ts"]);
        assert!(!p.run.iter().any(|a| a.contains(".furcate-serve")));
        assert_eq!(p.install, vec![vec!["npm", "ci", "--ignore-scripts"]]);
        // Build not declared: the package's own build script, as for any server.
        assert_eq!(p.build, vec!["npm", "run", "build"]);
    }

    #[test]
    fn an_empty_declared_build_means_there_is_nothing_to_build() {
        // A workspace that builds its pages before deploying must not have the
        // deploy build them again, as root, in its source tree.
        let pkg = own_server_workspace();
        let (start, build) = declared(json!({"start": ["node", "src/server.ts"], "build": []}));
        let p = plan(&Evidence {
            package_json: Some(&pkg),
            declared_start: start,
            declared_build: build,
            ..Default::default()
        })
        .unwrap();
        assert!(p.build.is_empty());
    }

    #[test]
    fn a_declared_start_with_no_package_json_is_a_native_program() {
        // The tree carries its own binary. Nothing to install, nothing to
        // infer: it runs exactly what it declared, supervised like any server.
        let (start, build) = declared(json!({"start": ["./bin/server"]}));
        let p = plan(&Evidence { declared_start: start, declared_build: build, ..Default::default() })
            .unwrap();
        assert_eq!(p.framework, Framework::Native);
        assert_eq!(p.tier, Tier::Node);
        assert!(p.install.is_empty());
        assert!(p.build.is_empty());
        assert_eq!(p.run, vec!["./bin/server"]);
    }

    #[test]
    fn a_native_program_may_declare_its_own_build() {
        let (start, build) =
            declared(json!({"start": ["./bin/server"], "build": ["make", "release"]}));
        let p = plan(&Evidence { declared_start: start, declared_build: build, ..Default::default() })
            .unwrap();
        assert_eq!(p.framework, Framework::Native);
        assert_eq!(p.build, vec!["make", "release"]);
    }

    #[test]
    fn a_python_project_that_declares_start_is_refused_by_name() {
        // Its dependencies would silently go uninstalled.
        let (start, _) = declared(json!({"start": ["./server"]}));
        let e = plan(&Evidence {
            declared_start: start,
            python_install: Some(PyInstall::Pip),
            python_deps: vec!["fastapi".into()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(e, Unknown::Declared(_)), "{e:?}");
        assert!(e.to_string().contains("Python"));
    }

    #[test]
    fn saying_nothing_declares_nothing() {
        assert_eq!(declared(json!({})), (None, None));
        assert_eq!(declared(json!({"routes": []})), (None, None));
    }

    #[test]
    fn a_declaration_that_would_mean_something_else_in_a_unit_is_refused() {
        for bad in [
            json!({"start": []}),
            json!({"start": "node src/server.ts"}),
            json!({"start": ["node", 3]}),
            json!({"start": ["node", ""]}),
            json!({"start": ["node", "src/my server.ts"]}),
            json!({"start": ["node", "a;b"]}),
            json!({"start": ["node", "%h/server.js"]}),
            json!({"start": ["node", "\"quoted\""]}),
            json!({"build": ["npm", "run build"]}),
        ] {
            assert!(declared_commands(&bad).is_err(), "{bad} should be refused");
        }
        // The port expansion every plan already relies on stays allowed.
        let (start, _) = declared(json!({"start": ["node", "server.js", "--port", "${PORT}"]}));
        assert_eq!(start.unwrap()[3], "${PORT}");
    }

    #[test]
    fn a_workspace_member_that_declares_its_start_needs_no_start_script() {
        let root = json!({"name": "w", "workspaces": ["packages/*"]});
        let member = json!({"name": "@w/api", "devDependencies": {"praecise": "1"}});
        let (start, build) = declared(json!({
            "start": ["node", "packages/api/dist/server.js"],
            "build": ["npm", "run", "build", "--workspace=@w/api"]
        }));
        let m = Evidence {
            package_json: Some(&member),
            declared_start: start,
            declared_build: build,
            ..Default::default()
        };
        let r = Evidence { package_json: Some(&root), lockfile: Some(Manager::Npm), ..Default::default() };
        let p = plan_member(&r, &m, "packages/api").unwrap();
        assert_eq!(p.framework, Framework::Node);
        assert_eq!(p.run, vec!["node", "packages/api/dist/server.js"]);
        assert_eq!(p.build, vec!["npm", "run", "build", "--workspace=@w/api"]);
        assert_eq!(p.output, ".");
    }
}

#[cfg(test)]
mod praecise_package_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_app_on_the_renamed_package_is_an_agent_app() {
        let pkg = json!({"name": "a", "dependencies": {"@praecise/harness": "^2"}});
        let p = plan(&Evidence { package_json: Some(&pkg), ..Default::default() }).unwrap();
        assert_eq!(p.framework, Framework::Praecise);
        assert_eq!(p.run, vec!["node", ".furcate-serve.mjs"]);
    }

    #[test]
    fn an_app_not_yet_migrated_is_still_an_agent_app() {
        // Every app deployed before the rename. A redeploy must not turn one
        // into an unknown framework.
        let pkg = json!({"name": "a", "dependencies": {"praecise": "^1"}});
        let p = plan(&Evidence { package_json: Some(&pkg), ..Default::default() }).unwrap();
        assert_eq!(p.framework, Framework::Praecise);
    }

    #[test]
    fn the_launcher_imports_what_the_app_depends_on_preferring_the_new_name() {
        let new = json!({"dependencies": {"@praecise/harness": "^2"}});
        let old = json!({"dependencies": {"praecise": "^1"}});
        let both = json!({"dependencies": {"praecise": "^1"}, "devDependencies": {"@praecise/harness": "^2"}});
        let neither = json!({"dependencies": {}});
        assert_eq!(praecise_package(&[&new]), "@praecise/harness");
        assert_eq!(praecise_package(&[&old]), "praecise");
        assert_eq!(praecise_package(&[&both]), "@praecise/harness", "half-migrated takes the new name");
        assert_eq!(praecise_package(&[&neither]), "@praecise/harness");
        assert_eq!(praecise_package(&[]), "@praecise/harness");
        // A workspace member whose dependency is declared at the root.
        assert_eq!(praecise_package(&[&neither, &old]), "praecise");
    }
}
