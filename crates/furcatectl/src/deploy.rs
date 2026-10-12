//! `furcate deploy` — the side of the deploy that touches the world.
//!
//! `furcate-deploy` decides; this runs. Detection, the release identity, the
//! edge configuration and the verdict all come from that crate and are tested
//! without a filesystem. What lives here is the part that cannot be: running
//! somebody's build, writing files, reloading a server, and making the HTTP
//! request that answers whether any of it worked.

use anyhow::{bail, Context, Result};
use furcate_deploy::{detect, edge, release, verify};
use furcate_ledger::OpKind;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where releases, the rendered edge config and the edge's own state live.
fn root() -> String {
    std::env::var("FURCATE_DEPLOY_ROOT")
        .unwrap_or_else(|_| "/var/lib/furcate/deploy".to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Read a tree well enough to plan a build: every file the detector can use is
// read in one place, so the detector itself stays a function of its inputs.

/// Dependency names a Python project declares, lowercased.
///
/// PEP 503 says `Flask`, `flask` and `FLASK` name the same distribution, and
/// `-`, `_` and `.` are equivalent separators. Normalising here means detection
/// compares names rather than whatever a project happened to type.
fn python_deps(src: &Path) -> Vec<String> {
    fn norm(raw: &str) -> Option<String> {
        // Strip everything that is not the name: extras, markers, versions.
        let name: String = raw
            .trim()
            .trim_start_matches(['"', '\''])
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        if name.is_empty() {
            return None;
        }
        Some(name.to_ascii_lowercase().replace(['_', '.'], "-"))
    }

    let mut out: Vec<String> = Vec::new();

    // requirements.txt: one requirement per line, `#` comments, `-r` includes
    // which are deliberately not followed -- a detector that chases includes
    // can be walked around the filesystem by a repository.
    if let Ok(t) = std::fs::read_to_string(src.join("requirements.txt")) {
        for line in t.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            if let Some(n) = norm(line) {
                out.push(n);
            }
        }
    }

    // pyproject.toml: scanned rather than parsed. A real TOML parser is the
    // right answer and is not worth a dependency for "does this list flask" --
    // but say so, because a scan cannot tell a dependency from a string that
    // merely mentions one.
    if let Ok(t) = std::fs::read_to_string(src.join("pyproject.toml")) {
        let mut in_deps = false;
        for line in t.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                in_deps = l.contains("dependencies") || l.contains("[tool.poetry.dependencies]");
                continue;
            }
            if l.starts_with("dependencies") && l.contains('[') {
                in_deps = true;
                continue;
            }
            if in_deps {
                if let Some(n) = norm(l) {
                    out.push(n);
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// `<project>.wsgi:application`, by finding the package that holds wsgi.py.
///
/// `startproject` puts it in a package beside manage.py, so one level of
/// directories is enough and walking deeper would start matching vendored
/// copies in a virtualenv.
fn django_wsgi(src: &Path) -> Option<String> {
    let rd = std::fs::read_dir(src).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() && p.join("wsgi.py").exists() {
            let name = p.file_name()?.to_str()?;
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            return Some(format!("{name}.wsgi:application"));
        }
    }
    None
}

/// Which installer to run, decided by lockfile.
///
/// A lockfile beats `requirements.txt` when both exist: it is the one that pins
/// transitively, and a project carrying both usually generates the requirements
/// file from the lock.
fn python_install(src: &Path) -> Option<detect::PyInstall> {
    if src.join("uv.lock").exists() {
        Some(detect::PyInstall::Uv)
    } else if src.join("poetry.lock").exists() {
        Some(detect::PyInstall::Poetry)
    } else if src.join("Pipfile.lock").exists() {
        Some(detect::PyInstall::Pipenv)
    } else if src.join("requirements.txt").exists() {
        Some(detect::PyInstall::Pip)
    } else if src.join("pyproject.toml").exists() {
        // No lockfile, but the project still declares what it needs.
        Some(detect::PyInstall::Pyproject)
    } else {
        None
    }
}

/// Where the ASGI app object lives, as uvicorn spells it.
///
/// Probed in the order a human would look, and only reported when the file is
/// actually there. Returning None leaves the caller on its own default rather
/// than asserting a layout this tree does not have.
fn asgi_module(src: &Path) -> Option<String> {
    for (path, module) in [
        ("main.py", "main:app"),
        ("app.py", "app:app"),
        ("app/main.py", "app.main:app"),
        ("src/main.py", "src.main:app"),
        ("api/main.py", "api.main:app"),
    ] {
        let f = src.join(path);
        if f.is_file() {
            // The file existing is not the same as it defining `app`.
            if let Ok(text) = std::fs::read_to_string(&f) {
                if text.contains("app = ") || text.contains("app=") {
                    return Some(module.to_string());
                }
            }
        }
    }
    None
}

type Evidence5 = (
    Option<serde_json::Value>,
    Option<String>,
    Option<String>,
    Option<String>,
    detect::Evidence<'static>,
);

/// Read once, here, so detection stays testable without a filesystem.
fn evidence_of(src: &Path) -> Result<Evidence5> {
    let pkg_path = src.join("package.json");
    let pkg = if pkg_path.exists() {
        let text = std::fs::read_to_string(&pkg_path)
            .with_context(|| format!("reading {}", pkg_path.display()))?;
        Some(serde_json::from_str::<serde_json::Value>(&text).with_context(|| {
            format!("{} is not valid JSON", pkg_path.display())
        })?)
    } else {
        None
    };

    let next_config = ["next.config.ts", "next.config.js", "next.config.mjs"]
        .iter()
        .map(|n| src.join(n))
        .find(|p| p.exists())
        .and_then(|p| std::fs::read_to_string(p).ok());

    let astro_cfg = ["astro.config.mjs", "astro.config.ts", "astro.config.js"]
        .iter()
        .map(|n| src.join(n))
        .find(|p| p.exists())
        .and_then(|p| std::fs::read_to_string(p).ok());
    let svelte_cfg = ["svelte.config.js", "svelte.config.mjs"]
        .iter()
        .map(|n| src.join(n))
        .find(|p| p.exists())
        .and_then(|p| std::fs::read_to_string(p).ok());

    let lockfile = if src.join("pnpm-lock.yaml").exists() {
        Some(detect::Manager::Pnpm)
    } else if src.join("yarn.lock").exists() {
        Some(detect::Manager::Yarn)
    } else if src.join("package-lock.json").exists() {
        Some(detect::Manager::Npm)
    } else {
        None
    };

    // What the tree says about itself outranks what can be read off it, so it
    // is read here with the rest of the evidence and handed to the detector
    // rather than patched onto a plan afterwards.
    let (declared_start, declared_build) = match std::fs::read_to_string(src.join("furcate-deploy.json")) {
        Ok(text) => {
            let v: serde_json::Value = serde_json::from_str(&text)
                .with_context(|| format!("{}/furcate-deploy.json is not valid JSON", src.display()))?;
            detect::declared_commands(&v)
                .map_err(|e| anyhow::anyhow!("{e} (in {}/furcate-deploy.json)", src.display()))?
        }
        Err(_) => (None, None),
    };

    let ev = detect::Evidence {
        package_json: None,
        next_config: None,
        has_astro_config: ["astro.config.mjs", "astro.config.ts", "astro.config.js"]
            .iter()
            .any(|n| src.join(n).exists()),
        astro_config: None,
        has_vite_config: ["vite.config.ts", "vite.config.js"]
            .iter()
            .any(|n| src.join(n).exists()),
        has_svelte_config: src.join("svelte.config.js").exists(),
        has_praecise_layout: src.join("praecise.config.ts").exists()
            || src.join("agents").is_dir()
            || src.join("workflows").is_dir(),
        svelte_config: None,
        has_index_html: src.join("index.html").exists(),
        python_deps: python_deps(src),
        // The strongest Django signal there is. A dependency list can name
        // django because something else pulled it in; only a Django project
        // has this file at its root.
        has_manage_py: src.join("manage.py").exists(),
        python_install: python_install(src),
        asgi_module: asgi_module(src),
        django_wsgi: django_wsgi(src),
        lockfile,
        declared_start,
        declared_build,
    };
    Ok((pkg, next_config, astro_cfg, svelte_cfg, ev))
}

/// Collect a built tree into the entries the release hash is taken over.
///
/// Symlinks are not followed. A build that emits one is emitting something
/// this cannot serve from an immutable release directory, and following it
/// would hash whatever it happened to point at today.
fn collect(dir: &Path) -> Result<Vec<release::Entry>> {
    // Never published. For a framework build these are not in the output
    // directory anyway, but a site that is already built is served from its
    // own root — and publishing the file that configures the deploy, or the
    // repository's history, because it happened to sit beside index.html is
    // not something anybody would ask for.
    // Never copied, for any tier. A static site does not serve dependencies,
    // and a supervised one INSTALLS them into the release rather than
    // inheriting a directory of symlinks that a content walker cannot carry.
    let never: &[&str] = &["furcate-deploy.json", ".git", ".env", "node_modules"];

    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let entry = entry?;
            let p = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if never.iter().any(|n| *n == name) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&p)?;
            if meta.is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(dir)
                .expect("walked from dir")
                .to_string_lossy()
                // `/` on every platform, so the same tree hashes the same
                // wherever it was built.
                .replace('\\', "/");
            out.push(release::Entry {
                path: rel,
                bytes: std::fs::read(&p)?,
            });
        }
    }
    Ok(out)
}

fn copy_tree(entries: &[release::Entry], dest: &Path) -> Result<u64> {
    let mut bytes = 0u64;
    for e in entries {
        let target = dest.join(&e.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, &e.bytes)?;
        bytes += e.bytes.len() as u64;
    }
    Ok(bytes)
}

/// Point `current` at a release, atomically.
///
/// Written to a temporary name and renamed over the old one, because a
/// `remove` followed by a `create` has a window in which the site is a broken
/// link — short, and exactly long enough to serve a 404 to whoever asked
/// during it.
fn point_current(link: &Path, to: &Path) -> Result<()> {
    let tmp = link.with_extension("switching");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(to, &tmp)?;
    std::fs::rename(&tmp, link)?;
    Ok(())
}

fn run(cmd: &[String], cwd: &Path) -> Result<()> {
    let (prog, args) = cmd.split_first().context("an empty command")?;
    // Prepend the extension's runtimes rather than trusting the caller's PATH.
    // A build triggered by a webhook inherits whatever systemd gave
    // furcate-gitdeploy, which does not include the runtime directory -- so
    // `npm` resolves in an interactive shell and not from a unit, and the
    // deploy fails only in production.
    // Every runtime the extension ships, not just node. uv lives beside it and
    // is how Python dependencies are installed, so a build that could find npm
    // and not uv would work for one language and fail for the other.
    const RT: &str = "/usr/lib/furcate/runtimes/node/bin:/usr/lib/furcate/runtimes/python";
    let path = match std::env::var("PATH") {
        Ok(p) => format!("{RT}:{p}"),
        Err(_) => format!("{RT}:/usr/local/bin:/usr/bin:/bin"),
    };
    // A writable HOME and cache, because the caller may be a sandboxed unit.
    //
    // furcate-gitdeploy runs with ProtectHome=yes, so /root is read-only and
    // every build tool that writes to $HOME fails there: uv stops with
    // "Failed to initialize cache at /root/.cache/uv: Read-only file system",
    // npm the same for its own cache. Running furcatectl by hand as root works
    // fine, which is what makes this the kind of bug that only ever appears via
    // the webhook -- in production, on somebody else's push.
    //
    // /var/tmp rather than the release: a cache that survives between deploys
    // is the difference between a 20-second rebuild and a 4-minute one, and it
    // is writable under every sandbox these units use.
    const CACHE: &str = "/var/tmp/furcate-build-cache";

    // The interpreter, unlike the cache, must NOT live under /var/tmp.
    //
    // uv provisions its own CPython and points the venv's `bin/python` at it by
    // symlink. With HOME under /var/tmp that interpreter lands there too -- and
    // every supervised unit runs with PrivateTmp=yes, which gives the service a
    // private /tmp AND /var/tmp. The interpreter is then invisible to the very
    // process that needs it: the venv is complete, `uvicorn` is present and
    // executable, and starting it fails 203/EXEC "No such file or directory",
    // naming the script rather than the interpreter in its shebang that is
    // actually missing. Every Python site would fail this way, always, and the
    // error points at the wrong file.
    //
    // /var/lib/furcate rather than the release directory: one interpreter
    // shared by every site and every release, not re-downloaded per deploy.
    const PYTHON_DIR: &str = "/var/lib/furcate/python";

    let _ = std::fs::create_dir_all(CACHE);
    let _ = std::fs::create_dir_all(PYTHON_DIR);
    let status = Command::new(prog)
        .args(args)
        .current_dir(cwd)
        .env("PATH", path)
        .env("HOME", CACHE)
        .env("XDG_CACHE_HOME", CACHE)
        .env("UV_CACHE_DIR", format!("{CACHE}/uv"))
        .env("UV_PYTHON_INSTALL_DIR", PYTHON_DIR)
        .env("npm_config_cache", format!("{CACHE}/npm"))
        .status()
        .with_context(|| format!("running `{}`", cmd.join(" ")))?;
    if !status.success() {
        bail!("`{}` failed with {}", cmd.join(" "), status);
    }
    Ok(())
}


// ── The supervised tier ────────────────────────────────────────────────────
//
// Everything below is what the refusal above used to stand in for: "a node tier
// needs a supervised unit and a port allocation". The rest of the pipeline was
// already built for it -- `edge.rs` renders `Serve::Proxy` and `load_sites`
// reads `upstream.json` -- so this supplies the two missing parts and nothing
// else changes.

/// Ports handed to supervised sites. Deliberately a narrow, boring band that no
/// framework defaults into: 3000 (Next), 5173 (Vite), 8000 (uvicorn/django) and
/// 8080 are all outside it, so a developer running the app by hand on a laptop
/// never collides with what the deployer chose here.
const PORT_LOW: u16 = 8600;
const PORT_HIGH: u16 = 8699;

/// The port this site already owns, or the lowest free one in the band.
///
/// Persisted per site rather than derived from the name. A hash would be
/// stable without state, but two names eventually collide and the failure --
/// two units binding one port, one of them silently dead -- is far worse than
/// keeping a file. Once allocated it never moves, so a redeploy does not
/// change the upstream and the edge does not have to be re-rendered for a
/// reason nobody asked for.
fn allocate_port(site_dir: &Path) -> Result<u16> {
    let file = site_dir.join("port");
    if let Ok(t) = std::fs::read_to_string(&file) {
        if let Ok(p) = t.trim().parse::<u16>() {
            return Ok(p);
        }
    }
    // Taken = every port any site already holds, not merely what is listening.
    // A site whose process is currently stopped still owns its port; handing it
    // to another site would break the first one the moment it starts again.
    let mut taken: Vec<u16> = Vec::new();
    if let Some(sites) = site_dir.parent() {
        if let Ok(rd) = std::fs::read_dir(sites) {
            for e in rd.flatten() {
                if let Ok(t) = std::fs::read_to_string(e.path().join("port")) {
                    if let Ok(p) = t.trim().parse::<u16>() {
                        taken.push(p);
                    }
                }
            }
        }
    }
    // ...and anything already listening, whoever owns it. The loop above sees
    // only ports recorded under `sites/`, so a site that was REMOVED while its
    // unit kept running is invisible to it: the site directory moved to
    // `removed/`, taking the port file with it, while the process carried on
    // holding the port. Handing that port to a new site gives it one that
    // cannot be bound -- it crash-loops on EADDRINUSE while the squatter keeps
    // answering, which is indistinguishable from success unless you look.
    taken.extend(listening_ports());

    let port = (PORT_LOW..=PORT_HIGH)
        .find(|p| !taken.contains(p))
        .context("no free port in the supervised band 8600-8699")?;
    std::fs::create_dir_all(site_dir)?;
    std::fs::write(&file, format!("{port}\n"))?;
    Ok(port)
}

/// The bearer token this site's control surface requires, stable across
/// restarts.
///
/// `serve()` mints one per start and prints it. That is right for a dev server
/// and wrong for a hosted one: the credential changes on every restart, so no
/// client can hold it, and nothing prints it when the process is a unit rather
/// than a terminal. Generated once, stored 0600 beside the port, and handed to
/// the app through the environment.
fn site_token(site_dir: &Path) -> Result<String> {
    let file = site_dir.join("token");
    if let Ok(t) = std::fs::read_to_string(&file) {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    // 32 bytes of urandom, hex.
    //
    // read_exact, NOT std::fs::read. `/dev/urandom` is a character device with
    // no EOF, so `fs::read` never returns -- it allocates until the machine runs
    // out of memory, and `.take(32)` afterwards never gets the chance to run.
    // Written here as a spinning process with no output, which is exactly how it
    // presented: a deploy stuck at 100% CPU immediately after allocating a port.
    use std::io::Read as _;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("reading 32 bytes from /dev/urandom")?;
    let tok: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::create_dir_all(site_dir)?;
    std::fs::write(&file, format!("{tok}\n"))?;
    let _ = std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    Ok(tok)
}

const SYSTEMD_DIR: &str = "/etc/systemd/system";

fn unit_path(name: &str) -> PathBuf {
    PathBuf::from(SYSTEMD_DIR).join(format!("furcate-app-{name}.service"))
}

/// Write the unit that supervises this site.
///
/// `WorkingDirectory` is the `current` SYMLINK, never the release directory it
/// points at. That single choice is what makes rollback work: moving the link
/// and restarting the unit is the whole operation, and the unit file does not
/// have to be rewritten to go back to a release it already ran.
/// Turn a program name into something systemd can actually spawn.
///
/// `ExecStart` is resolved by systemd against ITS OWN path, not against the
/// unit's `Environment=PATH`. Setting PATH in the unit and naming a bare `npm`
/// produces `203/EXEC — Unable to locate executable`, which reads like a
/// missing binary and is a missing ABSOLUTE PATH. Found the first time this
/// deployed a real Next.js app, having predicted the exact symptom in a comment
/// two functions up and then made the mistake anyway.
fn absolute_prog(prog: &str, link: &Path) -> String {
    if prog.starts_with('/') {
        return prog.to_string();
    }
    // Interpreters from a per-release virtualenv are relative to the release,
    // which the `current` symlink names.
    if prog.starts_with("./") || prog.starts_with(".venv/") {
        return link.join(prog.trim_start_matches("./")).display().to_string();
    }
    for dir in [
        "/usr/lib/furcate/runtimes/node/bin",
        "/usr/lib/furcate/runtimes/python",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ] {
        let c = Path::new(dir).join(prog);
        if c.exists() {
            return c.display().to_string();
        }
    }
    // Unresolved: leave it, so the unit fails loudly and names what is missing
    // rather than being silently rewritten into something that is not there.
    prog.to_string()
}

/// Where a site's secrets live.
///
/// Beside the site's port and token, and deliberately NOT in the release: the
/// release is content-addressed and its hash is what `deploy verify` checks, so
/// a secret inside it would be published in the identity of the site.
///
/// This is why `.env` is on the never-copy list. That was right, and it left
/// applications with no way to receive a credential at all — which for an app
/// framework whose entire configuration model is `.env` keys means a deployed
/// agent cannot reach a model, a tool, or anything else that needs one.
fn env_file(site_dir: &Path) -> PathBuf {
    site_dir.join("env")
}

/// Where a site keeps what must outlive a release.
///
/// Beside the release directories rather than inside one, for the opposite
/// reason the env file is: a release is immutable and replaced on every deploy,
/// and anything an application writes there — runs, memory, a forecast register
/// — is gone the next time somebody ships. Applications worked that out on their
/// own and pointed their own variable (`RS_STATE_DIR`, and others) at `state/`,
/// which the unit then made read-only: `ProtectSystem=strict` grants writes only
/// where `ReadWritePaths` says, and the generator named `current` alone. Every
/// write failed EROFS or ENOENT at the last step of a workflow, after the model
/// spend, and each site was mended with a hand-written drop-in that the next
/// site to need one did not have.
fn state_dir(site_dir: &Path) -> PathBuf {
    site_dir.join("state")
}

/// Create the state directory if the site does not have one yet.
///
/// Never re-moded once it exists. An operator who has already tightened it, or
/// an application that has populated it, made a decision this has no business
/// reverting on a redeploy. 0750 at creation: the unit runs as root and is the
/// only thing that needs in, and nothing on the platform reads it on the site's
/// behalf the way furcated reads `site.json`.
fn ensure_state_dir(site_dir: &Path) -> Result<PathBuf> {
    let dir = state_dir(site_dir);
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o750));
    }
    Ok(dir)
}

/// Everything a supervised site's unit is written from.
///
/// A struct because the list kept growing one positional argument at a time,
/// and two adjacent `&Path`s are exactly the kind of argument pair that gets
/// swapped without the compiler noticing.
struct UnitSpec<'a> {
    name: &'a str,
    /// The command line, already resolved to an absolute program.
    exec: &'a str,
    port: u16,
    link: &'a Path,
    state: &'a Path,
    hosts: &'a str,
    /// `PRAECISE_TOKEN=...`, root 0600 beside the site. Loaded by systemd as
    /// root before the drop, never written into the unit: /etc/systemd/system
    /// is world-readable, so a token in the unit is every site's token to
    /// every local account.
    token_env: &'a Path,
    secrets: &'a Path,
    memory: &'a release::MemoryBound,
    /// The account the site runs as. `None` only for a site started through a
    /// container runtime, whose socket is root-equivalent anyway.
    user: Option<&'a str>,
    /// Hardware the site declared it needs. Empty for nearly every site, and
    /// then the unit names no device at all.
    devices: &'a [release::Device],
}

/// The memory bound placed for a site, or the default.
///
/// `<site>/memory.json`, a sibling of `routes.json` for the same reason: it is
/// what the source's `furcate-deploy.json` declared, kept where a relink can
/// read it without the source. A file that cannot be read or does not check
/// falls back to the DEFAULT bound, never to none — a typo in a manifest must
/// not be the thing that lets one site take the machine.
fn placed_memory(site_dir: &Path) -> release::MemoryBound {
    let file = site_dir.join("memory.json");
    let Ok(text) = std::fs::read_to_string(&file) else {
        return release::MemoryBound::default();
    };
    match serde_json::from_str::<release::MemoryBound>(&text)
        .map_err(|e| e.to_string())
        .and_then(|m| m.check().map(|_| m))
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "deploy: {} was refused ({e}); the site keeps the default bound",
                file.display()
            );
            release::MemoryBound::default()
        }
    }
}

/// The devices placed for a site, or none.
///
/// `<site>/devices.json`, beside `memory.json` and for the same reason: what
/// the source declared, kept where a relink can read it without the source.
/// Unlike memory, a file that cannot be read or does not check falls back to
/// NO devices: the safe default for a bound is a bound, and the safe default
/// for a grant is no grant.
fn placed_devices(site_dir: &Path) -> Vec<release::Device> {
    let file = site_dir.join("devices.json");
    let Ok(text) = std::fs::read_to_string(&file) else {
        return Vec::new();
    };
    match serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|e| e.to_string())
        .and_then(|v| release::Device::parse_list(&v))
    {
        Ok(d) => d,
        Err(e) => {
            eprintln!("deploy: {} was refused ({e}); the site is granted no devices", file.display());
            Vec::new()
        }
    }
}

/// The account a site runs as: `app-<site>`, cut to 31 characters. Linux
/// allows 32, but systemd-sysusers refuses anything longer than 31 as "not a
/// valid user or group name" -- and one refused line fails the whole file, for
/// every site in it. Measured: `app-exampleworkshop-platform-run` (32) was
/// refused on node-a.
fn site_user(name: &str) -> String {
    format!("app-{name}").chars().take(31).collect()
}

/// A site started through a container runtime keeps root: the runtime's socket
/// is root-equivalent, so a user in front of it would only be a label.
fn runs_privileged(exec: &str) -> bool {
    let prog = exec.split_whitespace().next().unwrap_or("");
    matches!(prog.rsplit('/').next(), Some("docker") | Some("podman"))
}

/// The lines that make a site run as its own account instead of root.
///
/// Every site ran as root with a full capability set until 2026-09-22, when an
/// image-optimizer RCE in one Next.js app made its attacker root on the host,
/// able to read every other site's secrets. The sandbox kept the payload in one
/// private /tmp; root is what made one app bug a host compromise.
///
/// The release is created root-owned by the deploy that placed it, so the hand
/// over runs on EVERY start, as root (`+`), before the drop. `chown -hR` never
/// follows a symlink, so a link inside node_modules cannot aim it at a system
/// file.
fn identity_lines(u: &UnitSpec<'_>) -> String {
    let Some(user) = u.user else {
        return "# Started through a container runtime: its socket is root-equivalent,\n\
                # so this site keeps root rather than wear a user that means nothing.\n"
            .to_string();
    };
    format!(
        "# Its own account, no capabilities. npm writes its cache under HOME.\n\
         User={user}\n\
         Group={user}\n\
         CapabilityBoundingSet=\n\
         AmbientCapabilities=\n\
         Environment=HOME={state}\n\
         ExecStartPre=+/bin/mkdir -p {state}\n\
         ExecStartPre=+/bin/chown -hR {user}:{user} {link}/ {state}\n",
        state = u.state.display(),
        link = u.link.display(),
    )
}

/// Declare a site's account so systemd-sysusers creates it, and recreates it
/// on any machine that replays the file.
fn ensure_site_user(name: &str, user: &str, site_dir: &Path) -> Result<()> {
    const SYSUSERS: &str = "/etc/sysusers.d/furcate-apps.conf";
    std::fs::create_dir_all("/etc/sysusers.d")?;
    let have = std::fs::read_to_string(SYSUSERS).unwrap_or_default();
    if !have.lines().any(|l| l.split_whitespace().nth(1) == Some(user)) {
        let line = format!(
            "u {user} - \"Furcate site {name}\" {} /usr/sbin/nologin\n",
            state_dir(site_dir).display()
        );
        std::fs::write(SYSUSERS, format!("{have}{line}"))?;
    }
    let ok = Command::new("systemd-sysusers")
        .arg(SYSUSERS)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        anyhow::bail!("systemd-sysusers could not create {user} for {name}");
    }
    Ok(())
}

/// The unit file's text. Pure, so what the generator promises a site can be
/// read by a test rather than by inspecting /etc on a production machine.
fn render_unit(u: &UnitSpec<'_>) -> String {
    format!(
        "# Generated by `furcatectl deploy`. Edits are overwritten on next deploy.\n\
         [Unit]\n\
         Description=Furcate site {name} (supervised)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         # A site that dies at 03:00 should say so rather than be discovered.\n\
         OnFailure=notify-failure@%N.service\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         WorkingDirectory={link}\n\
         # PORT is the one convention imposed on an application. HOST/HOSTNAME\n\
         # are set too because Next reads HOSTNAME and most others read HOST,\n\
         # and binding 0.0.0.0 would publish a site the edge is supposed to be\n\
         # the only way into.\n\
         # Runtimes ship INSIDE the Furcate system extension, so a cluster\n\
         # update delivers them to every node instead of each being wired up by\n\
         # hand. /usr is read-only, hence /usr/lib/furcate/runtimes rather than\n\
         # /usr/local. A unit inheriting systemd default PATH cannot find node,\n\
         # and the failure is 203/EXEC -- which reads like a missing binary\n\
         # rather than a missing PATH entry.\n\
         Environment=PATH=/usr/lib/furcate/runtimes/node/bin:/usr/lib/furcate/runtimes/python:/usr/local/bin:/usr/bin:/bin\n\
         Environment=PORT={port}\n\
         Environment=HOST=127.0.0.1\n\
         Environment=HOSTNAME=127.0.0.1\n\
         Environment=NODE_ENV=production\n\
         # Durable state: kept beside the releases, so it survives a deploy,\n\
         # and granted below, so the application can actually write it. One\n\
         # name for every site instead of each application inventing its own.\n\
         Environment=FURCATE_STATE_DIR={state}\n\
         # The site's own secrets, if it has any. Leading `-` so a site with\n\
         # none still starts: having no credentials is a valid state, and a\n\
         # missing optional file must not be a boot failure.\n\
         EnvironmentFile=-{secrets}\n\
         # The names this app will answer to. praecise refuses any Host header\n\
         # it was not told about, which is DNS-rebinding protection and is also\n\
         # the reason a site can pass its health check and refuse every real\n\
         # request if this is missing.\n\
         Environment=PRAECISE_HOSTS={hosts}\n\
         EnvironmentFile={token_env}\n\
         {identity}\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         # Long enough for a framework to finish its own shutdown, short enough\n\
         # that a deploy is not held up by one that ignores SIGTERM.\n\
         TimeoutStopSec=20\n\
         KillSignal=SIGTERM\n\
         # Bound what one site can take, so a leak costs the site and not the\n\
         # machine. MemoryHigh throttles: past it the site is slowed and its\n\
         # memory reclaimed hard, and nothing dies, so a leak becomes a symptom\n\
         # somebody can see. MemoryMax kills, but inside this cgroup only: the\n\
         # choice is not whether to kill the site, it is whether the site gets\n\
         # to kill the machine, sshd included. This bounds one site, not the\n\
         # sum. Override per site with `memory` in furcate-deploy.json.\n\
         MemoryHigh={memory_high}\n\
         MemoryMax={memory_max}\n\
         \n\
         NoNewPrivileges=true\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         # `current` and `state` and nothing else. Under ProtectSystem=strict\n\
         # a path missing here is read-only, and the failure is EROFS at the\n\
         # moment the application first writes, not at start.\n\
         ReadWritePaths={link} {state}\n\
         # AF_NETLINK is here because frameworks enumerate interfaces at start.\n\
         # Next calls uv_interface_addresses for its startup banner; without\n\
         # netlink that throws errno 97 and the server ends up listening on a\n\
         # socket it never serves -- a process that looks alive to anything\n\
         # checking for a listener. This is a deployed application, not the\n\
         # agent: it holds no operator key, so the trade the agent declines is\n\
         # not the same trade here.\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\
         {devices}\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        name = u.name,
        link = u.link.display(),
        state = u.state.display(),
        port = u.port,
        exec = u.exec,
        hosts = u.hosts,
        token_env = u.token_env.display(),
        identity = identity_lines(u),
        secrets = u.secrets.display(),
        memory_high = u.memory.high,
        memory_max = u.memory.max,
        devices = device_lines(u.devices),
    )
}

/// The lines that grant a site its declared devices, or nothing.
fn device_lines(devices: &[release::Device]) -> String {
    if devices.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "# Hardware this site declared in furcate-deploy.json. Naming a device\n\
         # closes every other one: the unit's device policy becomes this list.\n",
    );
    for d in devices {
        out.push_str(d.unit_lines());
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn write_unit(
    name: &str,
    run: &[String],
    port: u16,
    link: &Path,
    state: &Path,
    hosts: &str,
    token: &str,
    secrets: &Path,
    memory: &release::MemoryBound,
) -> Result<()> {
    let (prog, args) = run.split_first().context("a supervised site with no run command")?;
    let exec = std::iter::once(absolute_prog(prog, link))
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    let site_dir = secrets.parent().context("a site's env file has no parent")?;
    let token_env = site_dir.join("token.env");
    std::fs::write(&token_env, format!("PRAECISE_TOKEN={token}\n"))?;
    std::fs::set_permissions(&token_env, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let user = (!runs_privileged(&exec)).then(|| site_user(name));
    if let Some(u) = &user {
        ensure_site_user(name, u, site_dir)?;
    }
    let devices = placed_devices(site_dir);
    let unit = render_unit(&UnitSpec {
        name,
        exec: &exec,
        port,
        link,
        state,
        hosts,
        token_env: &token_env,
        secrets,
        memory,
        user: user.as_deref(),
        devices: &devices,
    });
    std::fs::write(unit_path(name), unit)?;
    // Not `let _`: a reload that silently did not happen means the restart below
    // starts the unit this one was meant to replace, and the only symptom is a
    // grant that is in the file and not in the sandbox. Measured on a site that
    // was given a state directory for the first time.
    let reloaded = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !reloaded {
        eprintln!("reload    daemon-reload FAILED; the unit on disk is not the one systemd will start");
    }
    Ok(())
}

/// Wait until the application actually SERVES, or give up.
///
/// A started unit proves systemd forked something. A listening socket proves
/// only that something called listen(). Neither proves a request gets an
/// answer -- and the difference is not academic: the first Next.js app deployed
/// here bound its port and then threw during startup, so a TCP-connect gate
/// passed while every request timed out. That is the same mistake as monitoring
/// a host by ping.
///
/// So: send a real request and require a real status line. Any HTTP status
/// counts, including 404 and 500 -- the question is whether the application is
/// answering, not whether it likes this particular path.
/// Every TCP port something is currently listening on.
///
/// Read from `/proc/net/tcp`, which is the kernel's own answer rather than a
/// guess assembled from what this tool happens to know about.
fn listening_ports() -> Vec<u16> {
    let mut out = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let mut cols = line.split_whitespace();
            let Some(local) = cols.nth(1) else { continue };
            // Columns are: sl, local, rem, st -- so having taken `local`, the
            // state is one PAST the next column, not the next one. Reading
            // `rem` as the state matches nothing, which fails silently as "no
            // port is listening": the check looks present while doing nothing.
            if cols.nth(1).is_none_or(|st| st != "0A") {
                continue;
            }
            if let Some((_, port_hex)) = local.rsplit_once(':') {
                if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// The socket inodes held by every process in a unit's cgroup.
///
/// The cgroup rather than the MainPID, because the process that binds is very
/// often not the one systemd started: `npm run start` execs npm, which forks
/// node, and it is node that listens. Everything the unit spawned is inside the
/// unit's cgroup, and nothing else is.
fn unit_socket_inodes(unit: &str) -> Vec<u64> {
    let mut inodes = Vec::new();
    let procs = format!("/sys/fs/cgroup/system.slice/{unit}/cgroup.procs");
    let Ok(text) = std::fs::read_to_string(procs) else {
        return inodes;
    };
    for pid in text.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                // "socket:[12345]"
                if let Some(rest) = t.strip_prefix("socket:[") {
                    if let Some(num) = rest.strip_suffix(']') {
                        if let Ok(i) = num.parse::<u64>() {
                            inodes.push(i);
                        }
                    }
                }
            }
        }
    }
    inodes
}

/// Is the process listening on `port` one of ours?
///
/// The question the old gate could not ask. It connected to the port and
/// accepted any HTTP reply as proof of life -- so a *different* service holding
/// that port reported our deploy healthy while our own unit crash-looped on
/// EADDRINUSE behind it. A deploy that says "serving" while serving somebody
/// else's application is worse than one that fails, because nobody goes looking.
fn port_owned_by_unit(port: u16, unit: &str) -> bool {
    let ours = unit_socket_inodes(unit);
    if ours.is_empty() {
        return false;
    }
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // local_address st ... inode is column 9 on both tcp and tcp6.
            if cols.len() < 10 || cols[3] != "0A" {
                continue;
            }
            let Some((_, port_hex)) = cols[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(port_hex, 16).ok() != Some(port) {
                continue;
            }
            if let Ok(inode) = cols[9].parse::<u64>() {
                if ours.contains(&inode) {
                    return true;
                }
            }
        }
    }
    false
}

fn health_gate(port: u16, secs: u64, unit: &str) -> bool {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if let Ok(mut c) = TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(700)) {
            let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(4)));
            let _ = c.set_write_timeout(Some(std::time::Duration::from_secs(4)));
            let req = format!(
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: furcate-health\r\nConnection: close\r\n\r\n"
            );
            if c.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 64];
                if let Ok(n) = c.read(&mut buf) {
                    // Answering is not enough. It has to be OUR process
                    // answering -- see port_owned_by_unit.
                    if n > 0 && buf.starts_with(b"HTTP/") && port_owned_by_unit(port, unit) {
                        return true;
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// `systemctl`, never waiting on systemd's job queue.
///
/// `systemctl start|restart|stop` blocks until the JOB completes, and a job can
/// sit behind unrelated ones -- on a busy machine, behind every `user@N.service`
/// and login session scope in the queue. A deploy that waits there hangs with no
/// output and no timeout: observed stuck for eight minutes at exactly this step
/// while `systemctl list-jobs` showed session scopes queued ahead of it.
///
/// `--no-block` is correct here rather than a workaround, because the very next
/// thing this does is poll the port until the application answers. The health
/// gate is the real synchronisation point; waiting for systemd to say "started"
/// adds a deadlock risk and proves nothing the gate does not prove better.
fn systemctl(args: &[&str]) -> bool {
    let blocking = matches!(args.first().copied(), Some("start" | "restart" | "stop"));
    let mut cmd = Command::new("systemctl");
    if blocking {
        cmd.arg("--no-block");
    }
    cmd.args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The command that asks, from inside a running unit's own mount namespace,
/// whether its state directory takes a write.
///
/// Inside the namespace because that is the only place the answer is true.
/// `ProtectSystem=strict` is a read-only remount that exists only in the
/// unit's namespace: root on the host can write `state/` whatever the unit's
/// sandbox says, so a probe from outside passes for exactly the unit this is
/// meant to catch. `nsenter -m` joins that namespace and nothing else.
///
/// The path is passed as `$1`, never spliced into the script, and the probe
/// file is removed again so the application never sees it.
fn state_probe(pid: u32, state: &Path) -> Vec<String> {
    vec![
        "nsenter".into(),
        "-t".into(),
        pid.to_string(),
        "-m".into(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        r#"p="$1/.furcate-write-probe"; : > "$p" && rm -f "$p""#.into(),
        "furcate-state-probe".into(),
        state.display().to_string(),
    ]
}

/// Whether a running unit can write its state directory: `None` when there is
/// no process to ask or no way to ask it.
///
/// The health gate proves the application answers; it cannot prove the
/// application can keep anything, and the failure that motivated the state
/// directory arrived at the last step of a workflow, long after a health check
/// would have passed.
fn state_writable_in_unit(unit: &str, state: &Path) -> Option<bool> {
    let pid = systemctl_output(&["show", "-p", "MainPID", "--value", unit])?
        .parse::<u32>()
        .ok()
        .filter(|p| *p > 0)?;
    let cmd = state_probe(pid, state);
    Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .map(|s| s.success())
}

/// Say whether the unit can write its state, after a health gate has passed.
///
/// Reported, not rolled back: every release of a site runs under the same unit
/// and the same grant, so going back to the previous release would change
/// nothing about this, and the site is serving.
fn report_state_writable(unit: &str, state: &Path) {
    match state_writable_in_unit(unit, state) {
        Some(true) => println!("state     writable from inside the unit's sandbox"),
        Some(false) => {
            // The commonest cause is the unit on disk not being the one running:
            // a grant added by this deploy reaches the sandbox only after systemd
            // has re-read the file. Reload, restart once, and ask again — and if
            // it is still refused, that is a real answer rather than a race.
            println!("state     not writable yet; reloading the unit and asking once more");
            systemctl(&["daemon-reload"]);
            systemctl(&["restart", unit]);
            match state_writable_in_unit(unit, state) {
                Some(true) => println!("state     writable from inside the unit's sandbox"),
                _ => eprintln!(
                    "state     NOT WRITABLE from inside {unit}: every write to FURCATE_STATE_DIR will fail.\n\
                     \x20         The site is serving. Check ReadWritePaths in:  systemctl cat {unit}"
                ),
            }
        }
        None => println!("state     not probed (no running process to ask, or no nsenter here)"),
    }
}

/// The launcher a praecise app is served by, importing from `package`.
///
/// `package` is one of the two constants in `detect`, never text from a
/// manifest, so nothing an application writes can reach this import line.
fn praecise_launcher(package: &str) -> String {
    format!(
        r#"#!/usr/bin/env node
// Written by `furcatectl deploy`. Edits are overwritten on the next deploy.
//
// serve() binds loopback and refuses a public bind without a token; the edge is
// the only way in, so loopback is right. PRAECISE_HOSTS carries the site's
// domains: `hosts` is a Host-header allowlist and without it every request that
// arrives through the edge -- which all of them do -- is refused, while the
// health check on loopback still passes.
import {{ App, serve }} from "{package}";

const app = await App.load();
const token = process.env.PRAECISE_TOKEN;
await serve({{
  app,
  port: Number(process.env.PORT ?? 0),
  host: "127.0.0.1",
  hosts: (process.env.PRAECISE_HOSTS ?? "").split(",").filter(Boolean),
  ...(token ? {{ token }} : {{}}),
}});
"#
    )
}

/// `systemctl`, answering with what it printed when it ran and succeeded.
///
/// The shape `withdraw_unit` takes, so the order of what it does to systemd,
/// and what it refuses to do when a step fails, can be tested without one.
fn systemctl_output(args: &[&str]) -> Option<String> {
    let out = Command::new("systemctl").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// A unit that has finished stopping, as `ActiveState` reports it.
///
/// `failed` counts: a unit that exited non-zero on SIGTERM is not running, and
/// refusing to withdraw it would leave a site that cannot be removed because
/// its application handled shutdown badly.
fn is_stopped(active_state: &str) -> bool {
    matches!(active_state, "inactive" | "failed")
}

/// Stop a site's unit and take away everything that would start it again: the
/// enablement, the unit file, and its drop-in directory.
///
/// The gap this closes: `deploy remove` moved the site directory aside and
/// re-rendered the edge, and never touched the unit. The process kept running
/// with its working directory moved out from under it and its port still
/// bound, so a withdrawn site went on doing work — for an application that also
/// runs a job worker against a shared database, real work, invisible, for a
/// site that no longer exists. Its drop-ins stayed behind too, which is how
/// `furcate-app-dash-test-rs.service.d` outlived its site.
///
/// The order is the point. Stop first, and confirm it: `systemctl stop` is only
/// a request (sent `--no-block`, for the reason given on `systemctl`), so the
/// unit's `ActiveState` is polled until it reports stopped. If it never does,
/// this fails having removed NOTHING, so the caller can stop before moving the
/// site either — a unit that will not stop is a problem to look at, and a
/// half-removed site hides it. Then disable, before the file goes, because
/// disabling is what removes the `wants` symlink and a deleted unit leaves that
/// link dangling. Then the files, copied to `archive` first when one is given:
/// drop-ins are the one thing here written by hand, usually with a reason in
/// them. Then a daemon-reload, so systemd forgets it.
fn withdraw_unit(
    name: &str,
    systemd_dir: &Path,
    archive: Option<&Path>,
    ctl: &mut dyn FnMut(&[&str]) -> Option<String>,
    wait: std::time::Duration,
) -> Result<()> {
    let unit = format!("furcate-app-{name}.service");
    let file = systemd_dir.join(&unit);
    let dropins = systemd_dir.join(format!("{unit}.d"));
    let has_files = file.exists() || dropins.exists();

    // 1 · stop, and see that it stopped.
    let deadline = std::time::Instant::now() + wait;
    let mut asked = false;
    loop {
        match ctl(&["show", "-p", "ActiveState", "--value", &unit]) {
            Some(s) if is_stopped(&s) => {
                if asked {
                    println!("stop      {unit} stopped");
                }
                break;
            }
            Some(s) => {
                if !asked {
                    // Deliberately not the `systemctl` helper's arm list:
                    // this is the one stop whose completion is waited for.
                    ctl(&["stop", "--no-block", &unit]);
                    println!("stop      {unit} ({s}; asked to stop)");
                    asked = true;
                } else if std::time::Instant::now() >= deadline {
                    bail!(
                        "{unit} is still {s} {}s after it was asked to stop, so nothing was removed: \
                         the unit, its drop-ins and the site are all where they were.\n\
                         Inspect with:  systemctl status {unit}",
                        wait.as_secs()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            // No answer. With no unit file there is nothing of ours to have
            // been running; with one, "could not ask" is not "stopped".
            None if !has_files => break,
            None => bail!(
                "could not ask systemd whether {unit} is running, so nothing was removed; \
                 a unit this cannot see stop is not one to delete"
            ),
        }
    }
    if !has_files {
        println!("unit      none for {name} (a static site has no process)");
        return Ok(());
    }

    // 2 · disable, while the file it names still exists.
    if ctl(&["disable", &unit]).is_none() {
        bail!(
            "{unit} stopped but could not be disabled, so its files were kept: deleting them now \
             would leave a dangling `wants` link that fails at the next boot.\n\
             Run:  systemctl disable {unit}  and remove again"
        );
    }
    println!("disable   {unit}");

    // 3 · the files, archived first.
    if let Some(dir) = archive {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        if file.is_file() {
            std::fs::copy(&file, dir.join(&unit))?;
        }
        if dropins.is_dir() {
            let into = dir.join(format!("{unit}.d"));
            std::fs::create_dir_all(&into)?;
            for e in std::fs::read_dir(&dropins)?.flatten() {
                if e.path().is_file() {
                    std::fs::copy(e.path(), into.join(e.file_name()))?;
                }
            }
        }
    }
    if file.exists() {
        std::fs::remove_file(&file).with_context(|| format!("removing {}", file.display()))?;
        println!("unit      {} removed", file.display());
    }
    if dropins.is_dir() {
        // Named one by one: each was written by a person, and whoever reads
        // this output should be able to see what went.
        let mut names: Vec<String> = std::fs::read_dir(&dropins)?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        std::fs::remove_dir_all(&dropins)
            .with_context(|| format!("removing {}", dropins.display()))?;
        let listed = if names.is_empty() { "empty".to_string() } else { names.join(", ") };
        println!("drop-ins  {} removed ({listed})", dropins.display());
    }
    if let Some(dir) = archive {
        println!("archived  {}", dir.display());
    }

    // 4 · forget it.
    if ctl(&["daemon-reload"]).is_some() {
        println!("reload    systemd no longer knows {unit}");
    } else {
        // Reported, not fatal: the unit is stopped, disabled and gone from
        // disk, so nothing can start it. A stale entry in systemd's memory
        // is untidy, not dangerous.
        eprintln!("reload    daemon-reload FAILED; run: systemctl daemon-reload");
    }
    Ok(())
}

/// Load the site's policy, or refuse.
///
/// Absent, unreadable and unparseable are three different outcomes, as
/// everywhere else that reads this file: falling back to a permissive default
/// because a file could not be read is how authority an operator removed gets
/// quietly restored.
fn policy() -> Result<furcate_policy::PolicySet> {
    let candidates = furcate_policy::file::default_candidates(
        &furcate_paths::config("overlay-policy.yaml")
            .display()
            .to_string(),
    );
    let (set, source) = furcate_policy::file::load_from(&candidates)
        .map_err(|e| anyhow::anyhow!("{e}\nRefusing to deploy without knowing what is permitted"))?;
    if let furcate_policy::file::Source::File(p) = &source {
        println!("policy    {p} ({} rules)", set.policies.len());
    }
    Ok(set)
}

fn record(kind: OpKind, actor: &str, subject: &str, result: &str) {
    let path = PathBuf::from(root()).join("ledger.json");
    let mut chain = furcate_ledger::load(&path)
        .ok()
        .flatten()
        .unwrap_or_default();
    let ms = now() * 1000;
    chain.append(ms, kind, actor, subject, result);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = furcate_ledger::save(&chain, &path) {
        // Said out loud rather than swallowed: a deploy whose record failed to
        // write is a deploy nobody can account for afterwards, and that is
        // worth knowing at the moment it happens.
        eprintln!("deploy: the record could not be written ({e})");
    }
}

/// Everything after the build: identity, policy, placement, edge, verdict.
#[allow(clippy::too_many_arguments)]
/// Does a workspace glob cover this path?
///
/// Deliberately not a glob library: the shapes that appear in a `workspaces`
/// list are `packages/*`, `apps/**` and literal paths, and a wrong answer here
/// only decides whether to look one directory further up.
fn glob_covers(pattern: &str, rel: &str) -> bool {
    let pat: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let seg: Vec<&str> = rel.trim_end_matches('/').split('/').collect();
    let mut i = 0;
    while i < pat.len() {
        if pat[i] == "**" {
            // Matches the rest, however deep.
            return true;
        }
        if i >= seg.len() {
            return false;
        }
        if pat[i] != "*" && pat[i] != seg[i] {
            return false;
        }
        i += 1;
    }
    pat.len() == seg.len()
}

/// The workspace that governs `src`, if `src` is a member of one.
///
/// Walks up looking for a `package.json` that both declares `workspaces` and
/// actually claims this directory. Both halves matter: a repository can have a
/// `package.json` above a project without that project being part of it, and
/// treating an unrelated ancestor as the workspace root would install and build
/// something nobody asked to deploy.
fn workspace_root_of(src: &Path) -> Option<(PathBuf, String)> {
    let mut dir = src.parent()?;
    loop {
        let manifest = dir.join("package.json");
        if manifest.is_file() {
            if let Ok(text) = std::fs::read_to_string(&manifest) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    // npm/yarn put an array at `workspaces`; yarn also allows
                    // `{ "packages": [...] }`.
                    let globs = v
                        .get("workspaces")
                        .and_then(|w| w.as_array().cloned().or_else(|| {
                            w.get("packages").and_then(|p| p.as_array()).cloned()
                        }))
                        .unwrap_or_default();
                    // A member of an npm workspace has a package.json. A
                    // Python service that merely SITS inside the repository
                    // does not, and treating it as a member would install and
                    // build the whole JavaScript workspace to deploy it.
                    if !src.join("package.json").is_file() {
                        return None;
                    }
                    if let Ok(rel) = src.strip_prefix(dir) {
                        let rel = rel.to_string_lossy().replace('\\', "/");
                        if globs
                            .iter()
                            .filter_map(|g| g.as_str())
                            .any(|g| glob_covers(g, &rel))
                        {
                            return Some((dir.to_path_buf(), rel));
                        }
                    }
                }
            }
        }
        dir = dir.parent()?;
    }
}

/// Make the edge actually use the config that was just written.
///
/// Rendering the Caddyfile is not serving it. Leaving the reload to the caller
/// reads as caution — "placing is not serving" — but it means the normal path
/// through this command leaves the edge answering from a config that no longer
/// matches the sites on disk, and nothing fails until somebody visits.
///
/// For a NEW domain it is worse than stale routing: the running config has no
/// site block for that name, so the TLS handshake is aborted before on-demand
/// issuance is ever attempted. The client sees `tlsv1 alert internal error`
/// and the edge logs nothing at all, because from its point of view nothing
/// happened. That is a deploy which reports success and serves nothing.
///
/// Failure to reload is reported, not fatal: the release is already placed, and
/// a machine without this unit (a workstation, a test) should not fail a deploy
/// over a service it does not run.
fn reload_edge() -> bool {
    matches!(
        std::process::Command::new("systemctl")
            .args(["reload", "furcate-edge"])
            .status(),
        Ok(st) if st.success()
    )
}

pub fn deploy(src: &str, name: &str, domains: &str, principal: &str) -> Result<()> {
    if !release::valid_name(name) {
        bail!("`{name}` is not a usable site name: lowercase letters, digits and dashes");
    }
    let mut domains: Vec<String> = domains
        .split(',')
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    // A local site is never published, so naming a domain for it contradicts
    // the manifest. Refused rather than resolved either way: one of the two
    // statements is a mistake, and guessing which would publish or hide a
    // service its operator meant the other way.
    let local = site_local(Path::new(src))?;
    if local && !domains.is_empty() {
        bail!(
            "furcate-deploy.json says `local`, but domains were given: a local site answers \
             only on its loopback port. Drop the domains, or drop `local` to publish it"
        );
    }

    // No DOMAINS given: keep the names this site already answers on rather
    // than replacing them with the platform address alone. A redeploy is not
    // a statement that the operator wants to drop every custom name — and
    // silently dropping them takes a site off its own domain while reporting
    // success. Naming domains explicitly still replaces, because that IS a
    // statement.
    if domains.is_empty() && !local {
        let manifest = PathBuf::from(release::site_dir(&root(), name)).join("site.json");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            if let Ok(existing) = serde_json::from_str::<release::Site>(&text) {
                domains = existing.domains;
            }
        }
    }
    // Emptiness is checked AFTER the zone has had its chance to supply an
    // address, below: on a cluster with a platform zone, `deploy SRC NAME` is
    // a complete instruction and asking for a domain as well is asking the
    // operator to repeat what the cluster already knows. On a cluster without
    // one there is still nothing to serve, and it still refuses.
    for d in &domains {
        if !release::valid_domain(d) {
            bail!("`{d}` is not a domain this will put into a server configuration");
        }
    }

    let src = std::fs::canonicalize(src).with_context(|| format!("no such directory: {src}"))?;

    // What the tree declares about how its process is bounded, read before
    // anything is built: a manifest that cannot be honoured should fail here,
    // not after a release has been placed.
    let has_manifest = src.join("furcate-deploy.json").exists();
    let declared_memory = site_memory(&src)?;
    let declared_devices = site_devices(&src)?;
    let declared_headers = site_headers(&src)?;

    // 1 · Detect ---------------------------------------------------------
    let (pkg, next_config, astro_cfg, svelte_cfg, mut ev) = evidence_of(&src)?;
    ev.package_json = pkg.as_ref();
    ev.next_config = next_config.as_deref();
    ev.astro_config = astro_cfg.as_deref();
    ev.svelte_config = svelte_cfg.as_deref();

    // Point at the package you want deployed; if it belongs to a workspace,
    // the workspace is what gets installed and built. A member cannot be
    // resolved from inside itself -- its dependency on a sibling is a link the
    // root install creates -- so the build directory becomes the root even
    // though the operator named the member.
    let (plan, build_dir) = match workspace_root_of(&src) {
        Some((root_dir, rel)) => {
            let (rpkg, rnext, rastro, rsvelte, mut rev) = evidence_of(&root_dir)?;
            rev.package_json = rpkg.as_ref();
            rev.next_config = rnext.as_deref();
            rev.astro_config = rastro.as_deref();
            rev.svelte_config = rsvelte.as_deref();
            let plan =
                detect::plan_member(&rev, &ev, &rel).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("workspace {} → {rel}", root_dir.display());
            (plan, root_dir)
        }
        None => (
            detect::plan(&ev).map_err(|e| anyhow::anyhow!("{e}"))?,
            src.clone(),
        ),
    };
    println!("detected  {} → {} tier", plan.framework.as_str(), plan.tier.as_str());
    if ev.declared_start.is_some() {
        println!("start     {} (declared in furcate-deploy.json)", plan.run.join(" "));
    }

    // The platform address, assigned here rather than before detection
    // because which zone a site belongs in depends on what it turned out to
    // be: an agent application is called by other software and answers under
    // the agent zone, everything else is opened in a browser and answers
    // under the platform zone. The detector is the only thing that knows
    // which, and it has only just run.
    //
    // FURCATE_DEPLOY_ZONE still wins when it is set, because an operator
    // naming a zone explicitly is stating an intent the detector cannot see.
    // Otherwise the cluster's own zone files decide, so `deploy SRC NAME`
    // needs no domain argument at all.
    let assigned = if local {
        println!("address   none: local, answers only on 127.0.0.1");
        None
    } else {
        match std::env::var("FURCATE_DEPLOY_ZONE") {
        Ok(z) if !z.is_empty() => Some(release::zone_domain(name, &z)),
        _ => furcate_deploy::placed::zone_for(&root(), Some(plan.framework.as_str()))
            .map(|z| furcate_deploy::placed::zone_name(name, &z)),
        }
    };
    if let Some(assigned) = assigned {
        if !release::valid_domain(&assigned) {
            bail!("`{assigned}` is not a usable domain; check the zone configuration");
        }
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(&assigned)) {
            println!("address   {assigned}");
            domains.push(assigned);
        }
    }

    // Now it is fair to refuse: the zone has had its chance.
    if domains.is_empty() && !local {
        bail!(
            "a site needs at least one domain to answer on, and this cluster has no platform \
             zone to supply one (furcatectl edge zone ZONE)"
        );
    }

    // A supervised tier still refuses when it has nothing to start: a unit with
    // no ExecStart fails at first start, and it fails where a visitor finds it.
    if plan.tier != detect::Tier::Static && plan.run.is_empty() {
        bail!(
            "{} is a supervised tier but no start command is known for it.\n\
             For Next.js, set `output: 'export'` if the site has no server-side routes",
            plan.framework.as_str()
        );
    }

    // 2 · Build ----------------------------------------------------------
    //
    // A deploy runs as root, and a build writes into the tree it was given:
    // node_modules, .next, dist. Left as they are, those files are root's, and
    // the person who owns the checkout can no longer install a package in it —
    // `npm i` fails with EACCES until somebody chowns it back by hand, which is
    // a thing to remember rather than a thing that works. So the tree is handed
    // back to whoever owned it before the build.
    let tree_owner = std::fs::metadata(&build_dir).ok().map(|m| {
        use std::os::unix::fs::MetadataExt;
        (m.uid(), m.gid())
    });

    for step in &plan.install {
        println!("install   {}", step.join(" "));
        run(step, &build_dir)?;
    }
    if !plan.build.is_empty() {
        println!("build     {}", plan.build.join(" "));
        run(&plan.build, &build_dir)?;
    }

    if let Some((uid, gid)) = tree_owner {
        if uid != 0 {
            // Best effort, and never fatal: a deploy that placed a site must not
            // fail because a chown did. `-h` so a symlink is changed rather than
            // its target, which may live outside the tree.
            let ok = Command::new("chown")
                .args(["-R", "-h", &format!("{uid}:{gid}")])
                .arg(&build_dir)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                eprintln!("owner     could not hand {} back to {uid}:{gid}; `npm i` there will need sudo", build_dir.display());
            }
        }
    }

    let out = build_dir.join(&plan.output);
    if !out.is_dir() {
        bail!(
            "the build finished but {} does not exist. That is usually a framework \
             configured to output somewhere else",
            out.display()
        );
    }

    // 3 · Identity -------------------------------------------------------
    let mut entries = collect(&out)?;
    if entries.is_empty() {
        bail!("{} is empty; there is nothing to serve", out.display());
    }
    let id = release::hash(&mut entries);
    let files = entries.len();
    println!("release   {} ({files} files)", release::short(&id));

    // 4 · Propose --------------------------------------------------------
    let req = furcate_policy::Request {
        principal: principal.to_string(),
        action: furcate_deploy::ACTION.to_string(),
        resource: furcate_deploy::request(principal, name),
        // This path runs from the CLI against the local policy file and has no
        // proved caller to carry roles from, so a rule naming a role does not
        // apply here. Stated rather than defaulted, so the next reader knows it
        // is a decision.
        roles: Vec::new(),
    };
    let decision = policy()?.evaluate(&req, now());
    if !decision.allowed {
        record(
            OpKind::Deploy,
            principal,
            &format!("{name}@{}", release::short(&id)),
            &format!("refused: {}", decision.because),
        );
        bail!(
            "policy refused this deploy: {}{}",
            decision.because,
            if decision.structural {
                "\nThis is an invariant, not a rule — no policy file can permit it."
            } else {
                ""
            }
        );
    }

    // 5 · Place ----------------------------------------------------------
    let root = root();
    let dir = PathBuf::from(release::release_dir(&root, name, &id));
    let bytes = if dir.exists() {
        // Same bytes as a release already on disk. Re-placing them would be a
        // no-op that rewrites timestamps, so the link move is the whole
        // operation — which is also exactly what a rollback is.
        println!("placed    already on disk, reusing");
        entries.iter().map(|e| e.bytes.len() as u64).sum()
    } else {
        std::fs::create_dir_all(&dir)?;
        copy_tree(&entries, &dir)?
    };
    // A native program is the one file a release must be able to EXECUTE, and
    // a release is placed from bytes, which carry no mode. Marked here rather
    // than recorded in the release, so the release id stays a hash of what
    // was published and every existing site keeps the id it has.
    if plan.framework == detect::Framework::Native {
        let prog = native_program(&plan.run, &dir)?;
        std::fs::set_permissions(&prog, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        println!("program   {} (executable)", prog.display());
    }
    let link = PathBuf::from(release::current_link(&root, name));
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Read where `current` pointed BEFORE moving it. This is the only moment
    // the previous release is knowable, and it is what a failed health gate
    // rolls back to. Reading it afterwards would return the release that just
    // failed.
    let previous = std::fs::read_link(&link).ok();
    point_current(&link, &dir)?;
    println!("current   → {}", dir.display());

    // Every placed site gets a state directory, a static one included. One
    // layout for every site means a site that later gains a process finds its
    // state where the platform said it would be, and a rename or a removal
    // carries it without asking what tier the site was.
    let state = ensure_state_dir(&PathBuf::from(release::site_dir(&root, name)))?;
    println!("state     {} (outlives every release)", state.display());

    // A praecise app is served by a launcher this writes, because the framework
    // ships a stdio launcher (for subprocess clients) and a watching dev server,
    // and a hosted deployment wants neither.
    if plan.framework == detect::Framework::Praecise {
        // Imported from the package this app actually depends on. The runtime
        // is published as `@praecise/harness` now, and the unscoped `praecise`
        // is deprecated; a launcher that imported only the new name would take
        // down every app that has not migrated the moment it was redeployed.
        // The workspace root is read too, since that is where a member's
        // dependency may be declared.
        let root_manifest: Option<serde_json::Value> = (build_dir != src)
            .then(|| std::fs::read_to_string(build_dir.join("package.json")).ok())
            .flatten()
            .and_then(|t| serde_json::from_str(&t).ok());
        let manifests: Vec<&serde_json::Value> =
            ev.package_json.into_iter().chain(root_manifest.as_ref()).collect();
        let package = detect::praecise_package(&manifests);
        std::fs::write(dir.join(".furcate-serve.mjs"), praecise_launcher(package))?;
        println!("launcher  .furcate-serve.mjs (imports {package}; serve over HTTP, loopback, host-gated)");
    }

    // 5b · Supervise -----------------------------------------------------
    if plan.tier != detect::Tier::Static {
        // Dependencies land in the release, from the lockfile. This is the step
        // that makes `node_modules/.bin` exist with its symlinks intact, which
        // a copy cannot do.
        for step in &plan.install {
            println!("deps      {} (into the release)", step.join(" "));
            run(step, &dir)?;
        }
        let sdir = PathBuf::from(release::site_dir(&root, name));
        std::fs::create_dir_all(&sdir)?;
        let port = allocate_port(&sdir)?;
        println!("port      {port} (held by this site across redeploys)");

        let token = site_token(&sdir)?;
        // An agent app is the case where the platform has something to offer:
        // a database and a model both already exist here. Other tiers get
        // nothing they did not ask for.
        if plan.framework == detect::Framework::Praecise {
            provision_backends(name, &sdir)?;
        }
        // A manifest is a statement about memory whether or not it names it:
        // naming it places an override, leaving it out returns the site to the
        // default. No manifest at all changes nothing, exactly as for routes —
        // a redeploy from a release directory, which never carries one, must
        // not quietly undo a bound somebody declared.
        if has_manifest {
            let file = sdir.join("memory.json");
            match &declared_memory {
                Some(m) => std::fs::write(&file, serde_json::to_string_pretty(m)?)?,
                None => {
                    let _ = std::fs::remove_file(&file);
                }
            }
        }
        let memory = placed_memory(&sdir);
        println!("memory    high {} / max {} (this site, not the sum)", memory.high, memory.max);
        // Devices follow the same rule as memory: a manifest that names none
        // takes back any grant, and no manifest at all changes nothing.
        if has_manifest {
            let file = sdir.join("devices.json");
            if declared_devices.is_empty() {
                let _ = std::fs::remove_file(&file);
            } else {
                std::fs::write(&file, serde_json::to_string_pretty(&declared_devices)?)?;
            }
        }
        let devices = placed_devices(&sdir);
        if !devices.is_empty() {
            let names: Vec<_> = devices.iter().map(|d| format!("{d:?}").to_lowercase()).collect();
            println!("devices   {}", names.join(", "));
        }
        write_unit(
            name,
            &plan.run,
            port,
            &link,
            &state,
            &domains.join(","),
            &token,
            &env_file(&sdir),
            &memory,
        )?;
        let unit = format!("furcate-app-{name}.service");
        systemctl(&["enable", &unit]);
        println!("start     {}", plan.run.join(" "));
        systemctl(&["restart", &unit]);

        // The gate. Not "did systemd fork something" but "does the port answer".
        if !health_gate(port, 90, &unit) {
            eprintln!("health    {port} did not serve HTTP within 90s — rolling back");
            match &previous {
                Some(prev) => {
                    // Put the link back and restart, so the site keeps serving
                    // whatever it was serving before this deploy was attempted.
                    let _ = point_current(&link, prev);
                    systemctl(&["restart", &unit]);
                    let recovered = health_gate(port, 45, &unit);
                    eprintln!(
                        "rollback  → {} ({})",
                        prev.display(),
                        if recovered { "serving again" } else { "NOT answering — the site is down" }
                    );
                }
                None => {
                    // Nothing to go back to: this was the first deploy. Stop the
                    // unit rather than leave a restart loop behind.
                    systemctl(&["stop", &unit]);
                    systemctl(&["disable", &unit]);
                    eprintln!("rollback  first deploy of this site, so the unit was stopped");
                }
            }
            bail!(
                "{name} did not answer on 127.0.0.1:{port} within 90s. \n\
                 The release is on disk and the unit exists; inspect with:\n  \
                 journalctl -u furcate-app-{name} -n 50"
            );
        }
        println!("health    serving HTTP on 127.0.0.1:{port}");
        report_state_writable(&unit, &state);
        if plan.framework == detect::Framework::Praecise {
            println!(
                "token     {}/token (0600) — the bearer /mcp and /api require",
                sdir.display()
            );
        }

        // Only now does the edge learn about it. Writing this before the gate
        // would route traffic at a process that had not proven it serves.
        std::fs::write(
            sdir.join("upstream.json"),
            format!("\"127.0.0.1:{port}\"\n"),
        )?;
    }

    // 6 · Serve ----------------------------------------------------------
    let site = release::Site {
        name: name.to_string(),
        domains: domains.clone(),
        tier: plan.tier,
        framework: Some(plan.framework.as_str().to_string()),
        local,
    };
    let manifest = PathBuf::from(release::site_dir(&root, name)).join("site.json");
    std::fs::write(&manifest, serde_json::to_string_pretty(&site)?)?;

    // Redirects the framework declared and a static export dropped. They
    // travel with the source, so they are versioned with the site rather than
    // living only in whatever the last deploy happened to render.
    // A source tree with no `furcate-deploy.json` makes **no statement** about
    // redirects or routes, so the ones already placed are left alone.
    //
    // The alternative — treating absent as empty — silently discarded a site's
    // routing the first time somebody redeployed from a release directory,
    // which does not carry the manifest. The site kept serving and its API
    // stopped being routed, with nothing to see. Clearing routes is still
    // possible and is now something you say rather than something that
    // happens to you: ship a manifest with an empty list.
    let sdir = PathBuf::from(release::site_dir(&root, name));
    if src.join("furcate-deploy.json").exists() {
        let redirects = site_redirects(&src)?;
        if !redirects.is_empty() {
            println!("redirects {} carried to the edge", redirects.len());
        }
        std::fs::write(
            sdir.join("redirects.json"),
            serde_json::to_string_pretty(&redirects)?,
        )?;

        let routes = site_routes(&src)?;
        if !routes.is_empty() {
            println!("routes    {} back end(s) on this site's own origin", routes.len());
        }
        std::fs::write(sdir.join("routes.json"), serde_json::to_string_pretty(&routes)?)?;

        if !declared_headers.is_empty() {
            println!("headers   {} set by the edge on every response", declared_headers.len());
        }
        std::fs::write(
            sdir.join("headers.json"),
            serde_json::to_string_pretty(&declared_headers)?,
        )?;
    } else if sdir.join("routes.json").exists()
        || sdir.join("redirects.json").exists()
        || sdir.join("headers.json").exists()
    {
        println!("config    no furcate-deploy.json here; keeping the placed redirects, routes and headers");
    }

    let hosts = load_sites(&root)?;
    let e = edge_config(&root);
    let conf_path = PathBuf::from(&root).join("Caddyfile");
    std::fs::create_dir_all(format!("{root}/edge"))?;
    std::fs::write(&conf_path, edge::render(&e, &hosts))?;
    println!("edge      {}", conf_path.display());

    // 7 · Serve -----------------------------------------------------------
    // Placing is not serving, so do the part that makes it serve.
    if reload_edge() {
        println!("edge      reloaded");
    } else {
        eprintln!(
            "edge      COULD NOT RELOAD — the config is written but the edge is \
             still answering from the old one.\n          Run: systemctl reload furcate-edge"
        );
    }

    // 8 · Prune -----------------------------------------------------------
    // Last, and only here. Everything above this point can still roll back to
    // `previous`; once the edge is serving the new release the older ones stop
    // being a recovery path and become history — and history is what filled the
    // disk. Keeping KEEP_RELEASES of it leaves a rollback target and a spare.
    //
    // This never fails a deploy. The site is already serving traffic, and an
    // operator who cannot delete an old directory has a far smaller problem than
    // one whose deploy aborted after going live.
    let (pruned, freed) = release::prune(&root, name, release::KEEP_RELEASES);
    if !pruned.is_empty() {
        println!(
            "pruned    {} old release(s), {} freed — kept current + {}",
            pruned.len(),
            release::human_bytes(freed),
            release::KEEP_RELEASES
        );
    }

    // The dated copy of the source this release was built from is history too
    // once the release is live, and nothing else tidies it: the ops tool keeps
    // the newest two of each base name and anything in use. Housekeeping, so
    // like the release prune above it never fails a deploy.
    if Path::new(SOURCE_PRUNE).exists() {
        match std::process::Command::new(SOURCE_PRUNE).arg("--for").arg(&src).output() {
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout);
                if let Some(last) = out.lines().last() {
                    if !last.contains("removed 0 ") {
                        println!("pruned    {last}");
                    }
                }
            }
            Err(e) => eprintln!("prune     source copies not tidied: {e}"),
        }
    }

    println!(
        "\nplaced. Verify with:\n  furcatectl deploy verify {name} {}",
        domains[0]
    );
    record(
        OpKind::Deploy,
        principal,
        &format!("{name}@{}", release::short(&id)),
        &format!(
            "placed {files} files, {bytes} bytes, {} tier, domains {}",
            plan.tier.as_str(),
            domains.join(" ")
        ),
    );
    Ok(())
}

/// What the site itself declares about how it should be served.
///
/// `furcate-deploy.json` sits in the source tree so a redirect is versioned
/// with the pages it points at. A framework's own redirect table would be the
/// better home, except that a static export drops it — so this is where those
/// rules go to stay effective.
/// `furcatectl deploy relink NAME` — rewrite a placed site's unit from what is
/// already on disk, without rebuilding it.
///
/// The gap this closes: the platform address is decided at deploy time and
/// written into the unit's `PRAECISE_HOSTS`, because praecise refuses any Host
/// it was not told about. A site placed before the cluster had a zone — or
/// before it had the zone it has now — answers at the edge on an address its
/// own process rejects, and the only way to correct it was a full redeploy.
/// That needs the source tree, which a site placed from a directory that no
/// longer exists does not have.
///
/// So this regenerates the unit from the manifest, the existing release, and
/// the current zone. It builds nothing, fetches nothing, and allocates
/// nothing: the port and token are read back from the site directory, and the
/// run command is recovered from the unit's own ExecStart — which is already
/// absolute, so it survives the round trip through `write_unit` untouched.
pub fn relink(name: &str, principal: &str) -> Result<()> {
    if !release::valid_name(name) {
        bail!("site names are lowercase letters, digits and dashes");
    }
    let root = root();
    let sdir = PathBuf::from(release::site_dir(&root, name));
    let manifest = sdir.join("site.json");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("{name} is not a placed site on this machine"))?;
    let mut site: release::Site = serde_json::from_str(&text)
        .with_context(|| format!("{} is unreadable", manifest.display()))?;

    if site.tier != detect::Tier::Node {
        bail!("{name} is a static site: it has no unit to rewrite");
    }

    let unit_name = format!("furcate-app-{name}.service");
    let unit_path = PathBuf::from("/etc/systemd/system").join(&unit_name);
    let current = std::fs::read_to_string(&unit_path)
        .with_context(|| format!("{name} has no unit at {}", unit_path.display()))?;

    // The run command, as this site is actually being started. Recovered
    // rather than re-detected: detection reads a source tree, and the whole
    // point here is that there may not be one.
    let exec = current
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .context("the existing unit has no ExecStart to recover the run command from")?;
    let run: Vec<String> = exec.split_whitespace().map(|s| s.to_string()).collect();
    if run.is_empty() {
        bail!("the existing unit's ExecStart is empty");
    }

    // The address this site should answer on, for the zone it belongs to now.
    let before = site.domains.len();
    if let Some(z) = furcate_deploy::placed::zone_for(&root, site.framework.as_deref()) {
        let addr = furcate_deploy::placed::zone_name(name, &z);
        if !site.domains.iter().any(|d| d.eq_ignore_ascii_case(&addr)) {
            println!("address   {addr}");
            site.domains.push(addr);
        }
    }
    if site.domains.len() == before {
        println!("address   already current; rewriting the unit anyway");
    }

    let link = PathBuf::from(release::current_link(&root, name));
    let port = allocate_port(&sdir)?;
    let token = site_token(&sdir)?;
    // A site placed before the generator knew about state gets its directory
    // and its grant here, which is what retires the hand-written
    // `state-writable.conf` drop-ins: relink every site once and the unit says
    // what the drop-in used to.
    let state = ensure_state_dir(&sdir)?;
    // Likewise the memory bound, from what the last deploy placed or the
    // default, so `10-memory-bound.conf` stops being the only thing bounding a
    // site that was placed before the generator emitted it.
    let memory = placed_memory(&sdir);

    write_unit(
        name,
        &run,
        port,
        &link,
        &state,
        &site.domains.join(","),
        &token,
        &env_file(&sdir),
        &memory,
    )?;
    std::fs::write(&manifest, serde_json::to_string_pretty(&site)?)?;
    println!("hosts     {}", site.domains.join(","));
    println!("memory    high {} / max {}", memory.high, memory.max);
    println!("state     {} (FURCATE_STATE_DIR, writable by the unit)", state.display());

    systemctl(&["daemon-reload"]);
    systemctl(&["restart", &unit_name]);
    if !health_gate(port, 60, &unit_name) {
        bail!("{name} did not serve HTTP on {port} within 60s after the rewrite; \
               the unit is in place and systemd reports its own state");
    }
    println!("health    serving HTTP on 127.0.0.1:{port}");
    report_state_writable(&unit_name, &state);

    record(OpKind::Deploy, principal, "deploy relink",
           &format!("{name}: unit rewritten, {} name(s)", site.domains.len()));
    render_edge()
}

/// The memory bound a source tree declares, if it declares one.
///
/// `Ok(None)` is a tree that says nothing about memory, which means the
/// default. Checked when the deploy starts, so a bound that cannot be honoured
/// costs a second rather than a build.
fn site_memory(src: &Path) -> Result<Option<release::MemoryBound>> {
    let p = src.join("furcate-deploy.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(None);
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", p.display()))?;
    let Some(m) = v.get("memory") else {
        return Ok(None);
    };
    let m: release::MemoryBound = serde_json::from_value(m.clone()).with_context(|| {
        format!(
            "`memory` in {} must look like {{\"high\": \"6G\", \"max\": \"10G\"}}",
            p.display()
        )
    })?;
    m.check().map_err(|e| anyhow::anyhow!("{e} (in {})", p.display()))?;
    Ok(Some(m))
}

/// Whether a source tree declares itself `local` in `furcate-deploy.json`.
fn site_local(src: &Path) -> Result<bool> {
    let p = src.join("furcate-deploy.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(false);
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", p.display()))?;
    match v.get("local") {
        None => Ok(false),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(_) => bail!("`local` in {} must be true or false", p.display()),
    }
}

/// The devices a source tree declares in `furcate-deploy.json`, or none.
fn site_devices(src: &Path) -> Result<Vec<release::Device>> {
    let p = src.join("furcate-deploy.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(Vec::new());
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", p.display()))?;
    let Some(d) = v.get("devices") else {
        return Ok(Vec::new());
    };
    release::Device::parse_list(d).map_err(|e| anyhow::anyhow!("{e} (in {})", p.display()))
}

/// The program a native site starts, inside the release that carries it.
///
/// Refused unless it is `./`-relative, stays inside the release and is there:
/// a bare name would be looked up on PATH and run something the tree did not
/// ship, and an absolute path is a program this deploy did not place.
fn native_program(run: &[String], release: &Path) -> Result<PathBuf> {
    let prog = run.first().context("a native site with no start command")?;
    let Some(rel) = prog.strip_prefix("./") else {
        bail!(
            "a native site starts a program it carries, as `./path/in/tree`; `{prog}` is not \
             one. Ship the binary in the tree and declare it relative to the root"
        );
    };
    if rel.split('/').any(|c| c == ".." || c.is_empty()) {
        bail!("`{prog}` leaves the release; a native program must be inside the tree");
    }
    let path = release.join(rel);
    if !path.is_file() {
        bail!("`{prog}` is not in the release; build it before deploying, or declare `build`");
    }
    Ok(path)
}

/// Response headers a source tree declares for the edge to set.
fn site_headers(src: &Path) -> Result<Vec<release::Header>> {
    let p = src.join("furcate-deploy.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(vec![]);
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", p.display()))?;
    let Some(list) = v.get("headers") else {
        return Ok(vec![]);
    };
    let headers: Vec<release::Header> = serde_json::from_value(list.clone()).with_context(|| {
        format!(
            "`headers` in {} must look like [{{\"name\": \"Cache-Control\", \"value\": \"no-cache\"}}]",
            p.display()
        )
    })?;
    for h in &headers {
        h.check().map_err(|e| anyhow::anyhow!("{e} (in {})", p.display()))?;
    }
    Ok(headers)
}

/// The headers placed for a site, each re-checked on the way in.
///
/// A refused entry is dropped out loud and the rest are kept, like a refused
/// upstream: one bad line in one site's file must not take the whole edge
/// render down with it.
fn placed_headers(site_dir: &Path) -> Vec<release::Header> {
    let file = site_dir.join("headers.json");
    let Ok(text) = std::fs::read_to_string(&file) else {
        return vec![];
    };
    let Ok(all) = serde_json::from_str::<Vec<release::Header>>(&text) else {
        eprintln!("deploy: {} is unreadable; that site's headers are not set", file.display());
        return vec![];
    };
    all.into_iter()
        .filter(|h| match h.check() {
            Ok(()) => true,
            Err(e) => {
                eprintln!("deploy: a header in {} was refused ({e})", file.display());
                false
            }
        })
        .collect()
}

fn site_routes(src: &Path) -> Result<Vec<release::Route>> {
    let p = src.join("furcate-deploy.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(vec![]);
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", p.display()))?;
    let Some(list) = v.get("routes") else {
        return Ok(vec![]);
    };
    // Deserialising is where an upstream is checked: `Upstream` has no
    // constructor that skips it, so a control surface in this file is refused
    // here rather than written into a config.
    let routes: Vec<release::Route> = serde_json::from_value(list.clone())
        .with_context(|| format!("a route in {} was refused", p.display()))?;
    for r in &routes {
        if !release::valid_path(&r.path) {
            bail!("`{}` is not a usable route path; it must start with `/`", r.path);
        }
    }
    Ok(routes)
}

fn site_redirects(src: &Path) -> Result<Vec<release::Redirect>> {
    let p = src.join("furcate-deploy.json");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Ok(vec![]);
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", p.display()))?;
    let Some(list) = v.get("redirects") else {
        return Ok(vec![]);
    };
    let redirects: Vec<release::Redirect> = serde_json::from_value(list.clone())
        .with_context(|| format!("the `redirects` in {} are not in the expected shape", p.display()))?;
    for r in &redirects {
        // A redirect target is written into the server configuration, so the
        // same care the domains get applies here.
        if !r.from.starts_with('/') || !r.to.starts_with('/') {
            bail!("redirect {} → {} must use absolute paths", r.from, r.to);
        }
        if r.from.contains(char::is_whitespace) || r.to.contains(char::is_whitespace) {
            bail!("redirect {} → {} contains whitespace", r.from, r.to);
        }
    }
    Ok(redirects)
}

/// How this machine's edge is configured.
///
/// One constructor, because placing a site and withdrawing one both render the
/// whole file and must not disagree about how. Two copies of this would drift
/// the first time an option was added to one of them.
fn edge_config(root: &str) -> edge::Edge {
    edge::Edge {
        bind: std::env::var("FURCATE_EDGE_PORT").unwrap_or_else(|_| "8443".into()),
        tls: std::env::var("FURCATE_EDGE_TLS").is_ok_and(|v| v == "1"),
        data_dir: format!("{root}/edge"),
        // Where the edge asks whether a name may have a certificate. Points at
        // the node beside it, which knows what this machine serves — so the
        // answer is "is this ours", not a list somebody maintains by hand.
        ask: std::env::var("FURCATE_EDGE_ASK")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| {
                std::env::var("FURCATE_SITE")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|site| format!("http://{site}/tls/allow"))
            }),
        // Where external :80 is forwarded to, for certificate challenges.
        challenge_port: std::env::var("FURCATE_EDGE_CHALLENGE_PORT")
            .ok()
            .filter(|v| !v.is_empty()),
        wildcards: load_wildcards(&format!("{root}/edge/wildcards")),
        // The front door's addresses, when it passes the client's address in a
        // PROXY protocol header: comma-separated CIDRs.
        trusted_proxies: std::env::var("FURCATE_EDGE_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        // Set to 1 only when the front door forwards UDP to this edge.
        http3: std::env::var("FURCATE_EDGE_HTTP3").is_ok_and(|v| v == "1"),
    }
}

/// Wildcard certificates placed for this edge, one directory per zone.
///
/// `<edge>/wildcards/<zone>/fullchain.pem` and `privkey.pem`, put there by
/// whatever obtains them (a scheduled ACME client answering a DNS challenge —
/// see `edge::Wildcard` for why the edge cannot do that itself). A directory
/// missing either file is not a wildcard; it is ignored rather than rendered
/// into a `tls` line Caddy would refuse to load, which would take every site
/// on the edge down for one zone's half-finished renewal. No directory at all
/// is the normal case on a machine that has never needed one.
fn load_wildcards(dir: &str) -> Vec<edge::Wildcard> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<edge::Wildcard> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let zone = e.file_name().to_string_lossy().trim_start_matches("*.").to_string();
            let cert = e.path().join("fullchain.pem");
            let key = e.path().join("privkey.pem");
            (!zone.is_empty() && cert.is_file() && key.is_file()).then(|| edge::Wildcard {
                zone,
                cert: cert.to_string_lossy().into_owned(),
                key: key.to_string_lossy().into_owned(),
            })
        })
        .collect();
    // Deterministic output: the Caddyfile is diffed by humans.
    out.sort_by(|a, b| a.zone.cmp(&b.zone));
    out
}

/// Re-render the edge from the sites already placed, and reload it.
///
/// `furcatectl edge render`. Placing or withdrawing a site renders the edge
/// as a side effect; this is the same rendering with no site touched, for
/// when the *inputs* to rendering changed without a deploy — a wildcard
/// certificate arriving under `edge/wildcards/<zone>/` is the case that
/// exists. Without this, picking that certificate up meant redeploying some
/// site to trigger a render, and `deploy` does far more than render: it
/// reinstalls the release's dependencies and rewrites its launcher.
pub fn render_edge() -> Result<()> {
    let root = root();
    let hosts = load_sites(&root)?;
    let e = edge_config(&root);
    for w in &e.wildcards {
        println!("wildcard  *.{} ({})", w.zone, w.cert);
    }
    let conf_path = PathBuf::from(&root).join("Caddyfile");
    std::fs::create_dir_all(format!("{root}/edge"))?;
    std::fs::write(&conf_path, edge::render(&e, &hosts))?;
    println!("edge      {} ({} site(s))", conf_path.display(), hosts.len());
    if reload_edge() {
        println!("edge      reloaded");
        Ok(())
    } else {
        bail!("the config is written but the edge could not be reloaded; run: systemctl reload furcate-edge")
    }
}

/// Every site placed under this root, for rendering the edge whole.
fn load_sites(root: &str) -> Result<Vec<edge::Vhost>> {
    let sites_dir = PathBuf::from(root).join("sites");
    let mut out = Vec::new();
    if !sites_dir.is_dir() {
        return Ok(out);
    }
    let mut dirs: Vec<_> = std::fs::read_dir(&sites_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        // A dotted entry is never a site. Belt and braces: withdrawn sites now
        // move out of this directory entirely, and a stray one left here must
        // still not be served.
        .filter(|p| {
            p.file_name()
                .map(|n| !n.to_string_lossy().starts_with('.'))
                .unwrap_or(false)
        })
        .collect();
    // Sorted so the rendered configuration is stable between runs and a diff
    // of it shows what changed rather than what moved.
    dirs.sort();
    for d in dirs {
        let manifest = d.join("site.json");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(site) = serde_json::from_str::<release::Site>(&text) else {
            eprintln!("deploy: {} is unreadable; that site is not being served", manifest.display());
            continue;
        };
        let redirects: Vec<release::Redirect> = std::fs::read_to_string(d.join("redirects.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let routes: Vec<release::Route> = std::fs::read_to_string(d.join("routes.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let headers = placed_headers(&d);
        // A site may be a process rather than a directory. `upstream.json`
        // holds one address, and its presence is what makes this site proxied
        // instead of served from disk — a sibling file like redirects.json and
        // routes.json, rather than a new field on Site, because Site is
        // serialised elsewhere and adding to it would change those records too.
        //
        // Deserialising straight into `edge::Upstream` is deliberate: that type
        // only constructs through a check that refuses control-plane ports and
        // anything that could terminate a token in the rendered config. A bad
        // value therefore fails here, at load, rather than becoming a line in a
        // Caddyfile that routes traffic somewhere it should never go.
        let upstream: Option<edge::Upstream> = std::fs::read_to_string(d.join("upstream.json"))
            .ok()
            .and_then(|t| match serde_json::from_str::<edge::Upstream>(&t) {
                Ok(u) => Some(u),
                Err(e) => {
                    eprintln!(
                        "deploy: {} declares an upstream that was refused ({e}); \
                         that site is being served from disk instead",
                        d.join("upstream.json").display()
                    );
                    None
                }
            });

        let name = site.name.clone();
        let serve = match upstream {
            Some(upstream) => edge::Serve::Proxy { upstream },
            None => edge::Serve::Files {
                root: release::current_link(root, &name),
            },
        };
        // A local site has no place on the edge at all: not its domains (it
        // has none) and not the platform address either.
        if site.local {
            continue;
        }
        // The platform address: `NAME.<zone>`, its own block so the zone's
        // wildcard covers it whatever else the site answers on. A site whose
        // manifest already names it (deployed with FURCATE_DEPLOY_ZONE) is
        // left alone rather than rendered twice.
        // Per site, not once for the whole render: the zone depends on what
        // this site is, and the manifest is what says so.
        let zone = furcate_deploy::placed::zone_for(root, site.framework.as_deref());
        if let Some(z) = &zone {
            let addr = furcate_deploy::placed::zone_name(&name, z);
            if !site.domains.iter().any(|d| d.eq_ignore_ascii_case(&addr)) {
                out.push(edge::Vhost {
                    site: release::Site {
                        name: name.clone(),
                        domains: vec![addr],
                        tier: site.tier,
                        framework: site.framework.clone(),
                        local: false,
                    },
                    serve: serve.clone(),
                    redirects: redirects.clone(),
                    routes: routes.clone(),
                    // The platform address is the same site, so it carries
                    // the same headers; otherwise a page would cache one way
                    // under its own name and another under NAME.<zone>.
                    headers: headers.clone(),
                });
            }
        }
        out.push(edge::Vhost { site, serve, redirects, routes, headers });
    }
    Ok(out)
}

/// `furcatectl edge zone [ZONE]` — the platform zone every placed site answers on.
///
/// With no argument, says what it is. With one, records it and re-renders, so
/// `NAME.<zone>` starts answering for every site at once — but only once the
/// zone's wildcard certificate is on disk, because a zone without one would
/// turn the next render into sixty certificate requests against one registered
/// domain, which a public CA refuses after fifty.
pub fn edge_zone(zone: Option<&str>) -> Result<()> {
    let root = root();
    let file = PathBuf::from(&root).join("edge").join("zone");
    match zone {
        None => {
            match furcate_deploy::placed::zone(&root) {
                Some(z) => println!(
                    "zone      {z} ({})",
                    if furcate_deploy::placed::zone_has_wildcard(&root, &z) { "wildcard on disk" } else { "NO wildcard yet - not rendered" }
                ),
                None => println!("zone      none"),
            }
            Ok(())
        }
        Some(z) => {
            let z = z.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
            if !release::valid_domain(&z) {
                bail!("`{z}` is not a usable zone");
            }
            if !furcate_deploy::placed::zone_has_wildcard(&root, &z) {
                bail!(
                    "no wildcard certificate for *.{z} under {root}/edge/wildcards/{z}/ - obtain it first \
                     (furcate-wildcard-renew {z}); a zone is not rendered without one"
                );
            }
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(&file, format!("{z}\n"))?;
            println!("zone      {z} -> every placed site answers on NAME.{z}");
            record(OpKind::Deploy, "operator", "edge zone", &format!("platform zone set to {z}"));
            render_edge()
        }
    }
}

/// `furcatectl edge zone-mcp [ZONE]` — the zone agent applications answer on.
///
/// The sibling of `edge zone`. An agent application is called by other
/// software rather than opened in a browser, and the address is where that
/// distinction becomes visible to whoever is integrating: `NAME.mcp.example`
/// says what is there in a way `NAME.app.example` does not.
///
/// Same refusal as the platform zone, for the same reason: a zone with no
/// wildcard on disk turns the next render into one certificate request per
/// name against a single registered domain, which a public CA stops honouring
/// after fifty in a week.
pub fn edge_zone_mcp(zone: Option<&str>) -> Result<()> {
    let root = root();
    let file = PathBuf::from(&root).join("edge").join("zone-mcp");
    match zone {
        None => {
            match furcate_deploy::placed::zone_mcp(&root) {
                Some(z) => println!(
                    "zone-mcp  {z} ({})",
                    if furcate_deploy::placed::zone_has_wildcard(&root, &z) { "wildcard on disk" } else { "NO wildcard yet - not rendered" }
                ),
                None => println!("zone-mcp  none"),
            }
            Ok(())
        }
        Some(z) => {
            let z = z.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
            if !release::valid_domain(&z) {
                bail!("`{z}` is not a usable zone");
            }
            if !furcate_deploy::placed::zone_has_wildcard(&root, &z) {
                bail!(
                    "no wildcard certificate for *.{z} under {root}/edge/wildcards/{z}/ - obtain it first \
                     (furcate-wildcard-renew {z}); a zone is not rendered without one"
                );
            }
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(&file, format!("{z}\n"))?;
            println!("zone-mcp  {z} -> every placed agent app answers on NAME.{z}");
            record(OpKind::Deploy, "operator", "edge zone-mcp", &format!("agent zone set to {z}"));
            render_edge()
        }
    }
}

/// Stop serving a site, and re-render the edge so it stops immediately.
///
/// The gap this closes: deleting a site directory by hand left the rendered
/// configuration still advertising its hostnames. "Render the whole file"
/// prevents drift only while something triggers the render, and removal
/// triggered nothing — so the edge went on serving vhosts for a site that no
/// longer existed, and the operator had to redeploy something else to notice.
///
/// The releases are **kept**, moved aside rather than deleted. A site is
/// removed far more often by mistake than by decision, and the bytes are the
/// one part that cannot be reconstructed from a command line.
/// `furcatectl deploy rollback NAME RELEASE` — serve a release that is already
/// on disk.
///
/// Nothing is built and nothing is copied. Every deploy leaves its release under
/// `releases/` and points `current` at the new one; a rollback is the decision
/// to point it at an older one instead, taken the same way a deploy takes it:
/// the pointer moves atomically, the unit restarts, and the same health gate
/// decides whether the move stands. If the older release does not answer, the
/// pointer goes back to where it was — a rollback that leaves a site down is
/// worse than the release it was fleeing.
///
/// Recorded in the ledger like a placement, because that is what it is.
pub fn rollback(name: &str, release_id: &str, principal: &str) -> Result<()> {
    if !release::valid_name(name) {
        bail!("site names are lowercase letters, digits and dashes");
    }
    if release_id.is_empty()
        || !release_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("a release id is the directory name under releases/");
    }
    let root = root();
    let sdir = PathBuf::from(release::site_dir(&root, name));
    if !sdir.join("site.json").is_file() {
        bail!("{name} is not a placed site on this machine");
    }
    let target = PathBuf::from(release::release_dir(&root, name, release_id));
    if !target.is_dir() {
        let mut kept: Vec<String> = std::fs::read_dir(sdir.join("releases"))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        kept.sort();
        bail!(
            "{name} has no release {release_id} on disk. Kept:
  {}",
            if kept.is_empty() { "(none)".to_string() } else { kept.join("
  ") }
        );
    }
    let link = PathBuf::from(release::current_link(&root, name));
    let previous = std::fs::read_link(&link).ok();
    if previous.as_deref() == Some(target.as_path()) {
        bail!("{name} already serves {release_id}");
    }
    let from = previous
        .as_ref()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "nothing".to_string());

    point_current(&link, &target)?;
    println!("current   → {}", target.display());

    // A supervised site has a port file; a static one is served straight from
    // `current` by the edge and has nothing to restart.
    let port = std::fs::read_to_string(sdir.join("port"))
        .ok()
        .and_then(|t| t.trim().parse::<u16>().ok());
    match port {
        Some(port) => {
            let unit = format!("furcate-app-{name}.service");
            systemctl(&["restart", &unit]);
            if !health_gate(port, 90, &unit) {
                eprintln!("health    {port} did not serve HTTP within 90s — undoing the rollback");
                if let Some(prev) = &previous {
                    let _ = point_current(&link, prev);
                    systemctl(&["restart", &unit]);
                    let recovered = health_gate(port, 45, &unit);
                    eprintln!(
                        "undone    → {} ({})",
                        prev.display(),
                        if recovered { "serving again" } else { "NOT answering — the site is down" }
                    );
                }
                record(
                    OpKind::Deploy,
                    principal,
                    &format!("{name}@{}", release::short(release_id)),
                    &format!("rollback from {from} refused: {release_id} did not answer; {from} restored"),
                );
                bail!(
                    "{name} did not answer on 127.0.0.1:{port} within 90s after rolling back to {release_id};                      {from} was put back. Inspect with:
  journalctl -u furcate-app-{name} -n 50"
                );
            }
            println!("health    serving HTTP on 127.0.0.1:{port}");
        }
        None => println!("static    the edge serves `current`; nothing to restart"),
    }

    println!("
rolled back {name}: {from} → {release_id}. Verify with:
  furcatectl deploy verify {name} HOST");
    record(
        OpKind::Deploy,
        principal,
        &format!("{name}@{}", release::short(release_id)),
        &format!("rolled back from {from} to {release_id}"),
    );
    Ok(())
}

pub fn remove(name: &str, principal: &str) -> Result<()> {
    if !release::valid_name(name) {
        bail!("`{name}` is not a site name");
    }
    let root = root();
    let dir = PathBuf::from(release::site_dir(&root, name));
    if !dir.exists() {
        bail!("no site named `{name}` is placed here");
    }

    // Removing a site is an action on that site, gated exactly as placing one
    // is. An operator permitted to deploy a site may withdraw it; one who is
    // not, may not.
    let req = furcate_policy::Request {
        principal: principal.to_string(),
        action: furcate_deploy::ACTION.to_string(),
        resource: furcate_deploy::request(principal, name),
        // This path runs from the CLI against the local policy file and has no
        // proved caller to carry roles from, so a rule naming a role does not
        // apply here. Stated rather than defaulted, so the next reader knows it
        // is a decision.
        roles: Vec::new(),
    };
    let decision = policy()?.evaluate(&req, now());
    if !decision.allowed {
        record(OpKind::Deploy, principal, &format!("{name} remove"),
               &format!("refused: {}", decision.because));
        bail!("policy refused this removal: {}", decision.because);
    }

    // Outside `sites/`, not hidden inside it. A dot-prefixed directory kept
    // under `sites/` is still a site to anything that reads that directory —
    // the first version of this moved the site aside and the renderer picked it
    // straight back up, so the removal reported success and changed nothing.
    let stamp = now();
    let aside = PathBuf::from(format!("{}/removed/{}-{}", root.trim_end_matches('/'), name, stamp));
    if let Some(parent) = aside.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // The process before the directory it runs from. A unit that will not
    // stop fails the removal HERE, with the site still placed and still served,
    // rather than after the directory has moved and the edge has forgotten it
    // — the state in which a withdrawn site keeps working unseen.
    let unit_archive = PathBuf::from(format!("{}.unit", aside.display()));
    if let Err(e) = withdraw_unit(
        name,
        Path::new(SYSTEMD_DIR),
        Some(unit_archive.as_path()),
        &mut systemctl_output,
        std::time::Duration::from_secs(45),
    ) {
        record(OpKind::Deploy, principal, &format!("{name} remove"),
               &format!("failed before anything moved: {e}"));
        return Err(e.context(format!("{name} was not removed")));
    }

    std::fs::rename(&dir, &aside)
        .with_context(|| format!("moving {} aside", dir.display()))?;
    println!("removed   {name} (releases kept at {})", aside.display());

    // The whole point: re-render now, from the sites that remain.
    let hosts = load_sites(&root)?;
    let e = edge_config(&root);
    let conf_path = PathBuf::from(&root).join("Caddyfile");
    std::fs::write(&conf_path, edge::render(&e, &hosts))?;
    println!("edge      re-rendered, {} site(s) remain", hosts.len());
    if reload_edge() {
        println!("edge      reloaded — the site no longer answers");
    } else {
        eprintln!(
            "edge      COULD NOT RELOAD — the removed site is STILL being served.\n\
             \x20         Run: systemctl reload furcate-edge"
        );
    }

    record(OpKind::Deploy, principal, &format!("{name} remove"),
           &format!("withdrawn; unit stopped and removed; {} site(s) remain; releases kept", hosts.len()));
    Ok(())
}

/// The zones a site's derived addresses can have been assigned under.
///
/// Both zone files as they are now, whether or not their wildcard is on disk
/// (an address written into a manifest while it was is still derived), the
/// FURCATE_DEPLOY_ZONE override, and `local`. That last is not a zone this
/// cluster has: it is the one the earliest sites were deployed under, and
/// manifests on node-a still carry `NAME.local` in their names and their
/// PRAECISE_HOSTS. Nobody types a `.local` name as a custom domain.
fn derived_zones(root: &str) -> Vec<String> {
    let mut z: Vec<String> = [
        furcate_deploy::placed::zone(root),
        furcate_deploy::placed::zone_mcp(root),
        std::env::var("FURCATE_DEPLOY_ZONE").ok().filter(|v| !v.is_empty()),
        Some("local".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    z.dedup();
    z
}

/// `path` moved from under `from` to under `to`, if it was under `from`.
///
/// By component, so `sites/app` does not claim `sites/app-web/...`.
fn rebase(path: &str, from: &Path, to: &Path) -> Option<String> {
    Path::new(path)
        .strip_prefix(from)
        .ok()
        .map(|rest| if rest.as_os_str().is_empty() { to.to_path_buf() } else { to.join(rest) })
        .map(|p| p.display().to_string())
}

/// A site's env file with every path into its old directory pointed at the new
/// one, and the names of the variables that changed.
///
/// Applications point their own variables at the site directory — shop-rs has
/// `RS_STATE_DIR=<site>/state` — and after a move those would name a directory
/// that no longer exists, which fails as ENOENT at the first write rather than
/// at start. Only whole path prefixes are rewritten (`<old>/` or the directory
/// itself), so a value that merely contains the name is left alone.
fn rebase_env(text: &str, from: &Path, to: &Path) -> (String, Vec<String>) {
    let from_s = from.display().to_string();
    let to_s = to.display().to_string();
    let mut changed = Vec::new();
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let Some((k, v)) = line.split_once('=') else {
                return line.to_string();
            };
            let nv = if v == from_s {
                to_s.clone()
            } else {
                v.replace(&format!("{from_s}/"), &format!("{to_s}/"))
            };
            if nv != v {
                changed.push(k.trim().to_string());
            }
            format!("{k}={nv}")
        })
        .collect();
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    (out, changed)
}

/// The repositories furcate-gitdeploy would deploy to `site`, from its config.
///
/// Read, never written: that file holds the webhook secret and is the
/// operator's to edit. But a rename that leaves a repository mapped to the old
/// name is a push away from placing the old site again, so it has to be said.
fn gitdeploy_repos_for(cfg: &serde_json::Value, site: &str) -> Vec<String> {
    let mut out: Vec<String> = cfg
        .get("repos")
        .and_then(|r| r.as_object())
        .map(|repos| {
            repos
                .iter()
                .filter(|(_, e)| e.get("site").and_then(|s| s.as_str()) == Some(site))
                .map(|(r, _)| r.clone())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// `furcatectl deploy rename OLD NEW` — give a placed site a new name, and drop
/// the old one completely.
///
/// There was no way to do this, so a rename was a fresh deploy under the new
/// name followed by a removal, which needs the source, loses the state, and
/// has a window in which both names claim the same hosts.
///
/// **Nothing of the old name survives.** No alias, no redirect, no forwarding
/// block: a bridge keeps the old name alive as one more place to look, and
/// that is the confusion a rename is done to end. Domains derived from the
/// name (`OLD.<zone>`, `OLD.<zone-mcp>`) become `NEW.<zone>`; custom domains are
/// kept, and any that still begin with the old name are named in the output.
///
/// **The token rotates.** It is the bearer this site's `/mcp` and `/api`
/// require, handed to whatever integrates with the site under its old name.
/// Keeping it would keep every one of those integrations authenticated against
/// the new name without anybody having decided they should be. The old token is
/// moved into the archive (never deleted: a credential is moved, not destroyed),
/// a new one is minted, and the path — never the value — is printed.
///
/// **In this order**, so no moment has two sites claiming one host and no
/// moment has a process running from a directory that moved: every refusal is
/// decided before anything changes; the old unit is stopped and withdrawn
/// (`withdraw_unit`, which fails with nothing removed if it will not stop); the
/// directory is moved, carrying env, state, releases, port and redirects; the
/// `current` link, the env file's paths and the manifest are pointed at the new
/// name; the new unit is written and started; and the edge is rendered exactly
/// once, from a set of sites in which only the new name exists.
pub fn rename(old: &str, new: &str, principal: &str) -> Result<()> {
    for n in [old, new] {
        if !release::valid_name(n) {
            bail!("`{n}` is not a usable site name: lowercase letters, digits and dashes");
        }
    }
    if old == new {
        bail!("`{old}` is already called that");
    }
    let root = root();
    let odir = PathBuf::from(release::site_dir(&root, old));
    let ndir = PathBuf::from(release::site_dir(&root, new));
    let manifest_text = std::fs::read_to_string(odir.join("site.json"))
        .with_context(|| format!("{old} is not a placed site on this machine"))?;
    let mut site: release::Site = serde_json::from_str(&manifest_text)
        .with_context(|| format!("{}/site.json is unreadable", odir.display()))?;

    // ── Every refusal, before anything changes ──────────────────────────────
    //
    // `symlink_metadata`, not `exists`: a dangling link named NEW is still a
    // name somebody used.
    if std::fs::symlink_metadata(&ndir).is_ok() {
        bail!("`{new}` already exists at {}; a rename never merges two sites", ndir.display());
    }
    let new_unit = unit_path(new);
    let new_dropins = PathBuf::from(format!("{}.d", new_unit.display()));
    if new_unit.exists() || new_dropins.exists() {
        bail!(
            "a unit for `{new}` is already in {SYSTEMD_DIR} with no site behind it; \
             remove it before taking the name"
        );
    }

    // A Python release's virtualenv records its own absolute path in every
    // script it installed (the `#!` line of uvicorn, gunicorn, and the rest),
    // so moving the directory leaves each of them naming an interpreter that is
    // not there, and the unit fails 203/EXEC naming the script. Refused rather
    // than patched: rewriting installed files would make the release something
    // other than what was placed.
    if odir.join("current").join(".venv").exists() {
        bail!(
            "{old} runs from a Python virtualenv, which records its absolute path in every \
             script it installed, so its releases cannot be moved. Deploy the source as \
             `{new}`, then `furcatectl deploy remove {old}`"
        );
    }

    for n in [old, new] {
        let req = furcate_policy::Request {
            principal: principal.to_string(),
            action: furcate_deploy::ACTION.to_string(),
            resource: furcate_deploy::request(principal, n),
            // As for deploy and remove: no proved caller to carry roles from.
            roles: Vec::new(),
        };
        let decision = policy()?.evaluate(&req, now());
        if !decision.allowed {
            record(OpKind::Deploy, principal, &format!("{old} rename {new}"),
                   &format!("refused on {n}: {}", decision.because));
            bail!("policy refused this rename on `{n}`: {}", decision.because);
        }
    }

    let (domains, still_old) = release::renamed_domains(&site.domains, old, new, &derived_zones(&root));
    for d in &domains {
        if !release::valid_domain(d) {
            bail!("`{d}` would not be a usable domain; nothing was changed");
        }
    }
    // No other site may already answer on a name this one is about to take.
    // The edge would render both, and which one a visitor reached would be up
    // to the order of blocks in a file.
    if let Ok(rd) = std::fs::read_dir(PathBuf::from(&root).join("sites")) {
        for e in rd.flatten() {
            if e.path() == odir {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(e.path().join("site.json")) else { continue };
            let Ok(other) = serde_json::from_str::<release::Site>(&text) else { continue };
            if let Some(d) = domains.iter().find(|d| other.domains.iter().any(|o| o.eq_ignore_ascii_case(d))) {
                bail!("`{d}` is already served by `{}`; nothing was changed", other.name);
            }
        }
    }

    // The start command, recovered from the unit before the unit goes, with
    // any absolute path into the old directory rebased. Refused now, not after
    // the old unit is withdrawn, if a supervised site has none to recover.
    let port = std::fs::read_to_string(odir.join("port"))
        .ok()
        .and_then(|t| t.trim().parse::<u16>().ok());
    let run: Option<Vec<String>> = match (site.tier, std::fs::read_to_string(unit_path(old))) {
        (detect::Tier::Static, _) => None,
        (_, Ok(text)) => {
            let exec = text
                .lines()
                .find_map(|l| l.strip_prefix("ExecStart="))
                .context("the existing unit has no ExecStart to recover the run command from")?;
            Some(
                exec.split_whitespace()
                    .map(|a| rebase(a, &odir, &ndir).unwrap_or_else(|| a.to_string()))
                    .collect(),
            )
        }
        (_, Err(_)) => bail!(
            "{old} is supervised but has no unit at {} to recover its start command from; \
             `furcatectl deploy relink {old}` first. Nothing was changed",
            unit_path(old).display()
        ),
    };
    if site.tier != detect::Tier::Static && port.is_none() {
        bail!("{old} is supervised but has no port file; nothing was changed");
    }

    // ── From here, things change ────────────────────────────────────────────
    let stamp = now();
    let archive = PathBuf::from(format!(
        "{}/removed/{old}-renamed-{new}-{stamp}",
        root.trim_end_matches('/')
    ));
    std::fs::create_dir_all(&archive)?;
    let _ = std::fs::set_permissions(&archive, std::os::unix::fs::PermissionsExt::from_mode(0o700));

    withdraw_unit(
        old,
        Path::new(SYSTEMD_DIR),
        Some(archive.join("unit").as_path()),
        &mut systemctl_output,
        std::time::Duration::from_secs(45),
    )
    .map_err(|e| {
        record(OpKind::Deploy, principal, &format!("{old} rename {new}"),
               &format!("failed before anything moved: {e}"));
        e.context(format!("{old} was not renamed"))
    })?;

    // The old credential goes to the archive with the old unit. Moved before
    // the directory, so the directory arrives under the new name without it.
    let old_token = odir.join("token");
    if old_token.exists() {
        std::fs::rename(&old_token, archive.join("token"))
            .with_context(|| format!("archiving {}", old_token.display()))?;
        println!("token     {old}'s token archived; it no longer authenticates anything here");
    }

    std::fs::rename(&odir, &ndir).with_context(|| {
        format!(
            "moving {} to {}. The old unit is already withdrawn and archived at {}; \
             copy it back to {SYSTEMD_DIR} and start it to undo",
            odir.display(),
            ndir.display(),
            archive.display()
        )
    })?;
    println!("moved     {} → {}", odir.display(), ndir.display());

    // `current` is an absolute link, so it still names the old directory.
    let link = PathBuf::from(release::current_link(&root, new));
    if let Ok(target) = std::fs::read_link(&link) {
        if let Some(t) = rebase(&target.display().to_string(), &odir, &ndir) {
            point_current(&link, Path::new(&t))?;
            println!("current   → {t}");
        }
    }

    let env = env_file(&ndir);
    if let Ok(text) = std::fs::read_to_string(&env) {
        let (rebased, changed) = rebase_env(&text, &odir, &ndir);
        if !changed.is_empty() {
            write_private(&env, &rebased)?;
            println!("env       {} now name {}", changed.join(", "), ndir.display());
        }
    }

    site.name = new.to_string();
    site.domains = domains.clone();
    std::fs::write(ndir.join("site.json"), serde_json::to_string_pretty(&site)?)?;
    println!("hosts     {}", domains.join(","));
    for d in &still_old {
        eprintln!(
            "hosts     {d} still begins with the old name and was KEPT, because it is not an address \
             this platform derived. If it should go too: furcatectl deploy SRC {new} DOMAINS"
        );
    }

    // ── The new unit ────────────────────────────────────────────────────────
    let mut healthy = true;
    if let (Some(run), Some(port)) = (&run, port) {
        let token = site_token(&ndir)?;
        let state = ensure_state_dir(&ndir)?;
        let memory = placed_memory(&ndir);
        write_unit(new, run, port, &link, &state, &domains.join(","), &token, &env, &memory)?;
        let unit = format!("furcate-app-{new}.service");
        systemctl(&["enable", &unit]);
        systemctl(&["restart", &unit]);
        println!("token     {}/token (0600), newly minted", ndir.display());
        healthy = health_gate(port, 90, &unit);
        if healthy {
            println!("health    serving HTTP on 127.0.0.1:{port}");
            report_state_writable(&unit, &state);
        } else {
            eprintln!("health    {port} did not serve HTTP within 90s");
        }
    }

    // ── The edge, once ──────────────────────────────────────────────────────
    //
    // Rendered even when the new unit is unhealthy: the old name is already
    // gone from disk, and leaving the edge on its previous config would keep
    // routing the old hosts to this site's port — the bridge, by accident.
    let hosts = load_sites(&root)?;
    let e = edge_config(&root);
    let conf_path = PathBuf::from(&root).join("Caddyfile");
    std::fs::write(&conf_path, edge::render(&e, &hosts))?;
    let reloaded = reload_edge();
    if reloaded {
        println!("edge      rendered once and reloaded — {old} no longer answers anywhere");
    } else {
        eprintln!("edge      COULD NOT RELOAD — the old names are still served. Run: systemctl reload furcate-edge");
    }

    if let Ok(text) = std::fs::read_to_string("/etc/furcate/gitdeploy.json") {
        if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&text) {
            for repo in gitdeploy_repos_for(&cfg, old) {
                eprintln!(
                    "gitdeploy {repo} still deploys to `{old}`; a push would place it again. \
                     Point it at `{new}` in /etc/furcate/gitdeploy.json"
                );
            }
        }
    }
    if std::fs::read_to_string(&env).is_ok_and(|t| t.lines().any(|l| l.starts_with("DATABASE_URL="))) {
        println!(
            "database  DATABASE_URL is unchanged: a tenant's name is part of its credential, not \
             an address, and renaming it would rotate the password out from under the site"
        );
    }

    record(
        OpKind::Deploy,
        principal,
        &format!("{old} rename {new}"),
        &format!(
            "renamed; domains {}; old unit and token archived at {}; {}",
            domains.join(" "),
            archive.display(),
            if healthy { "serving" } else { "NOT serving" }
        ),
    );
    if !healthy {
        bail!(
            "{new} is placed under its new name and the edge routes to it, but it did not answer \
             within 90s. Inspect with:\n  journalctl -u furcate-app-{new} -n 50"
        );
    }
    if !reloaded {
        bail!("the edge could not be reloaded; run: systemctl reload furcate-edge");
    }
    println!(
        "\nrenamed {old} → {new}. Verify with:\n  furcatectl deploy verify {new} {}",
        domains.first().map(String::as_str).unwrap_or("HOST")
    );
    Ok(())
}

/// Ask the edge for a page and compare it with what was placed.
pub fn verify_cmd(name: &str, authority: &str) -> Result<()> {
    let root = root();
    let link = PathBuf::from(release::current_link(&root, name));

    // What "verified" can mean depends on what the site is.
    //
    // A static site is bytes on disk, so the strong check is available: fetch
    // what the edge serves and compare it with the file that was approved.
    //
    // A supervised site generates its response, and comparing it to anything on
    // disk is meaningless — the first version of this read `index.html`
    // unconditionally and failed every node and python site with
    // "no index.html", which reads as a broken deployment rather than as the
    // wrong question. For those, the honest check is the one that can be made:
    // the release the edge is serving is the release `current` points at, and
    // the site answers through the edge under its own name.
    let index = link.join("index.html");
    let placed = match std::fs::read(&index) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", index.display())),
    };

    let port = std::env::var("FURCATE_EDGE_PORT").unwrap_or_else(|_| "8443".into());
    let tls = std::env::var("FURCATE_EDGE_TLS").is_ok_and(|v| v == "1");

    // On a TLS edge the name has to arrive in the handshake, not only in a
    // header: the server selects both the certificate and the site from SNI,
    // and a `Host:` header on a plain-HTTP request to a TLS port is answered
    // 400 before any of it is consulted. The first version of this did exactly
    // that and reported every correctly-served site as broken — a check that
    // cannot pass is worse than no check, because it is read as a real failure.
    //
    // `--resolve` rather than DNS on purpose: this asks whether *this machine's*
    // edge serves what was placed. Whether the name points here is a separate
    // question, and answering both at once makes neither answer conclusive.
    let mut args: Vec<String> = vec![
        "-s".into(),
        "-o".into(),
        "-".into(),
        "-w".into(),
        "\n%{http_code}".into(),
        "--max-time".into(),
        "10".into(),
    ];
    let url = if tls {
        args.push("--resolve".into());
        args.push(format!("{authority}:{port}:127.0.0.1"));
        format!("https://{authority}:{port}/")
    } else {
        args.push("-H".into());
        args.push(format!("Host: {authority}"));
        format!("http://127.0.0.1:{port}/")
    };
    args.push(url);
    let out = Command::new("curl")
        .args(&args)
        .output()
        .context("running curl")?;
    let body = String::from_utf8_lossy(&out.stdout);
    let (body, status) = body.rsplit_once('\n').unwrap_or(("", "0"));
    let fetched = verify::Fetched {
        status: status.trim().parse().unwrap_or(0),
        body: body.as_bytes().to_vec(),
    };

    let (ok, description) = match &placed {
        Some(bytes) => {
            let verdict = verify::check(&fetched, bytes);
            (verdict.ok(), verdict.describe())
        }
        None => {
            // Generated responses: report what can actually be established.
            let release = std::fs::read_link(&link)
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "unknown".into());
            let answering = (200..500).contains(&fetched.status);
            (
                answering,
                if answering {
                    format!(
                        "the edge answers {} for {authority} from release {release}; \
                         a generated response cannot be compared with a file, so the bytes are not checked",
                        fetched.status
                    )
                } else {
                    format!("the edge answered {} for {authority} (release {release})", fetched.status)
                },
            )
        }
    };
    println!("{description}");
    record(OpKind::Deploy, "operator", &format!("{name} verify"), &description);
    if !ok {
        bail!(match placed {
            Some(_) => "the site is not serving what was placed".to_string(),
            None => format!("{name} is not answering through the edge"),
        });
    }
    Ok(())
}

/// Where the platform's provisioning tool lives, when there is one.
const PROVISIONER: &str = "/opt/ops/bin/furcate-db";
/// Removes older dated copies of a deploy source (`scripts/ops/furcate-source-prune`).
const SOURCE_PRUNE: &str = "/opt/ops/bin/furcate-source-prune";

/// Read the variables a site already has, by name.
fn env_keys(site_dir: &Path) -> Vec<String> {
    std::fs::read_to_string(env_file(site_dir))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim().to_string()))
        .collect()
}

/// Append variables to a site's env, leaving anything already there alone.
fn add_env(site_dir: &Path, pairs: &[(String, String)]) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let file = env_file(site_dir);
    let mut lines: Vec<String> = std::fs::read_to_string(&file)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();
    for (k, v) in pairs {
        if lines.iter().any(|l| l.starts_with(&format!("{k}="))) {
            continue;
        }
        lines.push(format!("{k}={v}"));
    }
    std::fs::create_dir_all(site_dir)?;
    std::fs::write(&file, format!("{}\n", lines.join("\n")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The MCP services this machine is running, as conventional URLs.
///
/// Read from the units themselves rather than a list kept here, so a service
/// added to the platform appears without this file being edited, and one that is
/// stopped does not get advertised to an application that would then fail
/// calling it.
fn mcp_services() -> Vec<(String, String)> {
    let out = Command::new("systemctl")
        .args(["list-units", "furcate-*-mcp.service", "--state=running", "--no-legend", "--plain"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    let mut found = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(unit) = line.split_whitespace().next() else { continue };
        let short = unit.trim_end_matches(".service");
        // furcate-<name>-mcp -> NAME
        let Some(mid) = short.strip_prefix("furcate-").and_then(|s| s.strip_suffix("-mcp")) else {
            continue;
        };
        let port = Command::new("systemctl")
            .args(["show", unit, "-p", "Environment", "--value"])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .find_map(|kv| kv.strip_prefix("PORT=").map(String::from))
            });
        if let Some(port) = port {
            let key = format!("FURCATE_{}_MCP_URL", mid.to_uppercase().replace('-', "_"));
            found.push((key, format!("http://127.0.0.1:{port}/mcp")));
        }
    }
    found
}

/// Give an agent app the backing services it needs, without being asked.
///
/// This is what makes Furcate somewhere to deploy rather than somewhere a
/// process happens to run. An agent app wants a database and a model; on this
/// platform both already exist, so it gets them under conventional names — the
/// same way any managed platform hands an application a `DATABASE_URL`.
///
/// Two rules stop that becoming a cage:
///
/// * **Anything already set is left alone.** A value in the site's env is a
///   decision somebody made, and a platform that overwrote it would make
///   "bring your own backend" impossible.
/// * **None of it is required.** The provisioner may not be there — an open
///   build, or somebody else's infrastructure — and the deploy still succeeds.
///   The application then needs the variables supplied by hand, which is
///   exactly what it would need anywhere else.
///
/// The application never names Furcate. It declares `credential: "DATABASE_URL"`
/// like anything else, and moving it to another database is one variable.
fn provision_backends(name: &str, site_dir: &Path) -> Result<()> {
    let have = env_keys(site_dir);
    let mut add: Vec<(String, String)> = Vec::new();

    // --- database + cache ---------------------------------------------------
    if have.iter().any(|k| k == "DATABASE_URL") {
        println!("backing   DATABASE_URL already set — left alone");
    } else if !Path::new(PROVISIONER).is_file() {
        println!("backing   no provisioner here; set DATABASE_URL yourself if the app needs one");
    } else {
        // `provision` refuses a tenant that exists, and the password is not
        // recoverable afterwards. So a tenant with no recorded URL is a state
        // to report rather than to resolve by re-provisioning, which would
        // rotate the password out from under whatever is already using it.
        // A site name and a tenant name obey different rules, and until now this handed one
        // straight to the other. Sites take dashes; `furcate-db` takes underscores and refuses
        // anything else. So EVERY hyphenated site was refused a database — and the refusal went to
        // stderr while this read only stdout, so the deploy reported "created nothing:" with an
        // empty reason and carried on. Twelve sites came up healthy with no database and said so
        // nowhere.
        //
        // The mapping is mechanical, so it belongs here rather than in the operator's head:
        // `blog-rs` is tenant `blog_rs`. Existing single-word sites are unaffected, since a name
        // with no dash maps to itself.
        let tenant = name.replace('-', "_");
        let exists = Command::new(PROVISIONER)
            .args(["show", &tenant])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("database"))
            .unwrap_or(false);
        if exists {
            println!(
                "backing   a database for `{tenant}` exists but this site has no DATABASE_URL.\n\
                 \x20         Its password cannot be read back. Set DATABASE_URL by hand, or\n\
                 \x20         `furcate-db deprovision {tenant} --yes` and deploy again."
            );
        } else {
            let out = Command::new(PROVISIONER)
                .args(["provision", &tenant])
                .output()
                .context("running the database provisioner")?;
            let text = String::from_utf8_lossy(&out.stdout);
            // The provisioner writes its refusals to stderr. Reading only stdout turned every
            // refusal into a blank line after a colon, which is indistinguishable from success
            // for anyone skimming a deploy log.
            let why = String::from_utf8_lossy(&out.stderr);
            // The tool exits 0 even when it refuses, so the output is the only
            // honest signal about whether anything was created.
            if let Some(url) = text.split_whitespace().find(|w| w.starts_with("postgresql://")) {
                add.push(("DATABASE_URL".into(), url.to_string()));
                println!("backing   provisioned postgres for `{tenant}`");
                // Valkey is printed as a block rather than a url; build one.
                let port = text
                    .lines()
                    .skip_while(|l| !l.contains("Valkey"))
                    .find_map(|l| l.split_whitespace().nth(1).filter(|_| l.contains("port")));
                let pass = text
                    .lines()
                    .skip_while(|l| !l.contains("Valkey"))
                    .find_map(|l| l.split_whitespace().nth(1).filter(|_| l.contains("password")));
                if let (Some(port), Some(pass)) = (port, pass) {
                    let host = url
                        .split('@')
                        .nth(1)
                        .and_then(|h| h.split(':').next())
                        .unwrap_or("127.0.0.1");
                    add.push(("VALKEY_URL".into(), format!("redis://:{pass}@{host}:{port}")));
                    println!("backing   provisioned valkey for `{tenant}`");
                }
            } else {
                // Prefer stderr: that is where the reason is. Falling back to stdout keeps this
                // honest if the tool ever changes which stream it explains itself on.
                let said = why
                    .trim()
                    .lines()
                    .next()
                    .filter(|l| !l.is_empty())
                    .or_else(|| text.trim().lines().next())
                    .unwrap_or("it said nothing");
                println!("backing   no database for `{tenant}`: {said}");
                println!("backing   the site will start without DATABASE_URL — a store that needs one will fail at use");
            }
        }
    }

    // --- a model, if this node is serving one -------------------------------
    if have.iter().any(|k| k == "FURCATE_MODEL_URL") {
        println!("backing   FURCATE_MODEL_URL already set — left alone");
    } else if let Ok(text) = std::fs::read_to_string("/var/lib/furcate/models/endpoints.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(m) = v["models"].as_array().and_then(|l| l.first()) {
                if let (Some(url), Some(id)) = (m["base_url"].as_str(), m["id"].as_str()) {
                    let tok = m["credential_file"]
                        .as_str()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .map(|t| t.trim().to_string());
                    add.push(("FURCATE_MODEL_URL".into(), url.to_string()));
                    add.push(("FURCATE_MODEL_ID".into(), id.to_string()));
                    if let Some(tok) = tok {
                        add.push(("FURCATE_MODEL_KEY".into(), tok));
                    }
                    println!("backing   model `{id}` served here — endpoint injected");
                }
            }
        }
    }

    // --- this machine's own MCP services ------------------------------------
    for (k, v) in mcp_services() {
        if !have.contains(&k) {
            println!("backing   {k}");
            add.push((k, v));
        }
    }

    add_env(site_dir, &add)
}

/// Give a site a secret, or replace one it already has.
///
/// `furcatectl deploy env NAME KEY=VALUE [KEY=VALUE...]`
///
/// Written where systemd can read it and nothing else can, and never into the
/// release. Redeploying does not disturb it: a credential belongs to the site,
/// not to the build that happened to be running when it was set.
pub fn set_env(name: &str, pairs: &[&str]) -> Result<()> {
    let parsed = pairs
        .iter()
        .enumerate()
        .map(|(i, p)| parse_env_pair(p, &format!("argument {}", i + 1)))
        .collect::<Result<Vec<_>>>()?;
    // Said, not refused: the form still works and scripts depend on it. But a
    // value on a command line is in `ps` for as long as this runs, in the
    // journal of whatever unit ran it, and in shell history, and whoever typed
    // it should know there is a form that is in none of those.
    eprintln!(
        "note      values given as arguments are visible to `ps`, the journal and shell history;\n\
         \x20         `furcatectl deploy env {name} --stdin` reads KEY=VALUE lines without that"
    );
    store_env(name, &parsed)
}

/// `furcatectl deploy env NAME --stdin` — the same, with the pairs read from
/// standard input, one `KEY=VALUE` per line.
///
/// The gap this closes: the only way to hand a site a credential was to put the
/// value in argv, where every process on the machine can read it from `/proc`
/// while the command runs and where a unit that shells out to it leaves it in
/// the journal. Nothing read from stdin is echoed back: the names are printed,
/// as `show_env` prints them, and a malformed line is refused by its number.
pub fn set_env_stdin(name: &str) -> Result<()> {
    use std::io::{IsTerminal, Read};
    // Before reading: a malformed name should not cost somebody a paste. A
    // site that does not exist yet is allowed -- secrets may precede the first
    // deploy -- and store_env says so when it creates the directory.
    if !release::valid_name(name) {
        bail!("`{name}` is not a usable site name: lowercase letters, digits and dashes");
    }
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!("reading KEY=VALUE lines for {name}; end with Ctrl-D (input is not echoed back afterwards)");
    }
    let mut text = String::new();
    stdin
        .read_to_string(&mut text)
        .context("reading KEY=VALUE lines from stdin")?;
    let pairs = parse_env_lines(&text)?;
    if pairs.is_empty() {
        bail!("no KEY=VALUE lines on stdin; nothing was changed");
    }
    store_env(name, &pairs)
}

/// One `KEY=VALUE`, checked the way systemd will read it.
///
/// `what` names the pair in a refusal — "argument 2", "line 7" — rather than
/// quoting it. The text of a malformed pair is very often a secret pasted
/// without its key, and a base64 value can contain `=`, so even the part
/// before the first `=` is not safe to repeat.
fn parse_env_pair(pair: &str, what: &str) -> Result<(String, String)> {
    let (k, v) = pair
        .split_once('=')
        .with_context(|| format!("{what} is not KEY=VALUE"))?;
    let k = k.trim();
    if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("{what} does not start with a usable variable name");
    }
    // systemd reads this file line by line and does not understand a value
    // that spans lines. Refusing is better than writing a file that parses
    // as something other than what was asked for.
    if v.contains(['\n', '\r']) {
        bail!("the value for `{k}` contains a line break, which systemd cannot read");
    }
    Ok((k.to_string(), v.to_string()))
}

/// Pairs from text: one per line, blank lines and `#` comments skipped, so the
/// same file an operator keeps for a site can be piped in as it is.
fn parse_env_lines(text: &str) -> Result<Vec<(String, String)>> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .map(|(i, l)| parse_env_pair(l, &format!("line {}", i + 1)))
        .collect()
}

/// A site's env file after setting `pairs`: a key set again replaces its line,
/// every other line is kept where it was.
fn merge_env(existing: &str, pairs: &[(String, String)]) -> String {
    let mut kept: Vec<String> = existing
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();
    for (k, v) in pairs {
        kept.retain(|l| !l.starts_with(&format!("{k}=")));
        kept.push(format!("{k}={v}"));
    }
    format!("{}\n", kept.join("\n"))
}

/// Replace a file holding secrets.
///
/// 0600 from the moment the file exists, and swapped in by rename. Writing and
/// then chmod-ing leaves the secrets readable under the caller's umask for as
/// long as that takes, and a unit starting mid-write would read half a file.
fn write_private(file: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = file.with_extension("writing");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, file).with_context(|| format!("replacing {}", file.display()))?;
    Ok(())
}

fn store_env(name: &str, pairs: &[(String, String)]) -> Result<()> {
    let root = root();
    let sdir = PathBuf::from(release::site_dir(&root, name));
    if !release::valid_name(name) {
        bail!("`{name}` is not a usable site name: lowercase letters, digits and dashes");
    }
    // Secrets may be given before the first deploy. A service that cannot start
    // without them -- a signing authority that needs its database -- would
    // otherwise fail its first health gate, and this refused until a deploy had
    // succeeded: neither could go first. A directory holding only an env file
    // is not a site; the edge renders nothing without a site.json.
    if !sdir.exists() {
        std::fs::create_dir_all(&sdir)?;
        std::fs::set_permissions(&sdir, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        println!("note      no site `{name}` yet; its secrets are kept for its first deploy");
    }
    let file = env_file(&sdir);
    let merged = merge_env(&std::fs::read_to_string(&file).unwrap_or_default(), pairs);
    write_private(&file, &merged)?;

    for (k, _) in pairs {
        println!("set       {k}");
    }
    println!("stored    {}", file.display());
    println!("\nRestart the site to pick it up:  systemctl restart furcate-app-{name}");
    Ok(())
}

/// What secrets a site has — the names, never the values.
///
/// Printing a credential to a terminal writes it into a scrollback buffer and
/// very often a log. The names are enough to answer "is it configured", which
/// is the question being asked.
pub fn show_env(name: &str) -> Result<()> {
    let root = root();
    let sdir = PathBuf::from(release::site_dir(&root, name));
    let file = env_file(&sdir);
    let Ok(text) = std::fs::read_to_string(&file) else {
        println!("`{name}` has no secrets configured");
        return Ok(());
    };
    println!("{}", file.display());
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            println!("  {:<28} set ({} bytes)", k.trim(), v.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod upstream_tests {
    use super::*;

    /// Build a minimal placed-site tree under a temporary root.
    fn site(root: &std::path::Path, name: &str, upstream: Option<&str>) {
        let d = root.join("sites").join(name);
        std::fs::create_dir_all(&d).unwrap();
        // `tier` is required: Site carries it, and a manifest without it is
        // skipped entirely rather than defaulted. Node is the tier the enum
        // already describes as "a long-lived process the machine supervises,
        // reverse-proxied" — which is exactly what an upstream is.
        let tier = if upstream.is_some() { "node" } else { "static" };
        std::fs::write(
            d.join("site.json"),
            format!(r#"{{"name":"{name}","domains":["{name}.example.com"],"tier":"{tier}"}}"#),
        )
        .unwrap();
        if let Some(u) = upstream {
            std::fs::write(d.join("upstream.json"), format!("\"{u}\"")).unwrap();
        }
    }

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "furcate-upstream-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_local_site_is_never_on_the_edge() {
        let root = tmp();
        site(&root, "public", Some("127.0.0.1:8601"));
        let d = root.join("sites").join("issuer");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("site.json"),
            r#"{"name":"issuer","domains":[],"tier":"node","local":true}"#,
        )
        .unwrap();
        std::fs::write(d.join("upstream.json"), "\"127.0.0.1:8602\"").unwrap();
        let hosts = load_sites(root.to_str().unwrap()).unwrap();
        // Not its own domains (it has none) and not the platform address.
        assert!(hosts.iter().all(|h| h.site.name != "issuer"), "{:?}", hosts.iter().map(|h| &h.site.name).collect::<Vec<_>>());
        assert!(hosts.iter().any(|h| h.site.name == "public"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_ordinary_manifest_is_unchanged_by_the_local_flag() {
        // `local: false` is never written, so every existing site.json keeps
        // the bytes it has; and a manifest without it reads as not local.
        let s: release::Site =
            serde_json::from_str(r#"{"name":"a","domains":["a.example.com"],"tier":"static"}"#).unwrap();
        assert!(!s.local);
        assert!(!serde_json::to_string(&s).unwrap().contains("local"));
    }

    #[test]
    fn local_must_be_a_boolean() {
        let src = tmp();
        std::fs::write(src.join("furcate-deploy.json"), r#"{"local":"yes"}"#).unwrap();
        assert!(site_local(&src).is_err());
        std::fs::write(src.join("furcate-deploy.json"), r#"{"local":true}"#).unwrap();
        assert!(site_local(&src).unwrap());
        std::fs::write(src.join("furcate-deploy.json"), r#"{"start":["./bin/x"]}"#).unwrap();
        assert!(!site_local(&src).unwrap());
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn a_site_without_an_upstream_is_still_served_from_disk() {
        let root = tmp();
        site(&root, "static", None);
        let hosts = load_sites(root.to_str().unwrap()).unwrap();
        assert_eq!(hosts.len(), 1);
        assert!(
            matches!(hosts[0].serve, edge::Serve::Files { .. }),
            "adding upstream support must not change what every existing site does"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn declaring_an_upstream_makes_the_site_a_proxy() {
        let root = tmp();
        site(&root, "app", Some("127.0.0.1:9100"));
        let hosts = load_sites(root.to_str().unwrap()).unwrap();
        assert_eq!(hosts.len(), 1);
        match &hosts[0].serve {
            edge::Serve::Proxy { upstream } => assert_eq!(upstream.as_str(), "127.0.0.1:9100"),
            other => panic!("expected a proxy, got {other:?}"),
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_upstream_pointing_at_a_control_port_is_refused_and_the_site_falls_back() {
        // The whole reason upstream.json deserialises into `edge::Upstream`
        // rather than a String. A site must never be able to make the edge
        // proxy the public internet at a control surface by writing one line
        // of JSON — and the failure has to be visible and safe, not fatal:
        // refusing the upstream and serving from disk keeps the other sites
        // in this render alive.
        let root = tmp();
        site(&root, "sneaky", Some("127.0.0.1:7616"));
        let hosts = load_sites(root.to_str().unwrap()).unwrap();
        assert_eq!(hosts.len(), 1);
        assert!(
            matches!(hosts[0].serve, edge::Serve::Files { .. }),
            "a refused upstream must not become a proxy"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_malformed_upstream_does_not_take_the_whole_render_down() {
        let root = tmp();
        site(&root, "broken", Some("this is not an address"));
        site(&root, "fine", None);
        let hosts = load_sites(root.to_str().unwrap()).unwrap();
        assert_eq!(hosts.len(), 2, "one bad site must not remove the others");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn placed_headers_reach_the_site_and_its_platform_address_alike() {
        let root = tmp();
        site(&root, "landing", None);
        std::fs::write(
            root.join("sites/landing/headers.json"),
            r#"[{"name":"Cache-Control","value":"no-cache"},{"name":"Bad Name","value":"x"}]"#,
        )
        .unwrap();
        // A platform zone with its wildcard on disk, so the site also gets a
        // `landing.<zone>` block.
        let w = root.join("edge/wildcards/app.example.com");
        std::fs::create_dir_all(&w).unwrap();
        std::fs::write(w.join("fullchain.pem"), "x").unwrap();
        std::fs::write(w.join("privkey.pem"), "x").unwrap();
        std::fs::write(root.join("edge/zone"), "app.example.com\n").unwrap();

        let hosts = load_sites(root.to_str().unwrap()).unwrap();
        assert_eq!(hosts.len(), 2, "the site and its platform address");
        for h in &hosts {
            assert_eq!(h.headers.len(), 1, "the refused header is dropped, the good one kept: {h:?}");
            assert_eq!(h.headers[0].name, "Cache-Control");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_manifest_declares_headers_and_a_bad_one_stops_the_deploy() {
        let src = tmp();
        assert!(site_headers(&src).unwrap().is_empty());
        std::fs::write(
            src.join("furcate-deploy.json"),
            r#"{"headers":[{"name":"Cache-Control","value":"no-cache"}]}"#,
        )
        .unwrap();
        assert_eq!(site_headers(&src).unwrap().len(), 1);
        std::fs::write(
            src.join("furcate-deploy.json"),
            r#"{"headers":[{"name":"Cache-Control","value":"{bad}"}]}"#,
        )
        .unwrap();
        assert!(site_headers(&src).is_err());
        std::fs::remove_dir_all(&src).ok();
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn spec<'a>(
        link: &'a Path,
        state: &'a Path,
        secrets: &'a Path,
        memory: &'a release::MemoryBound,
    ) -> UnitSpec<'a> {
        UnitSpec {
            name: "shop-rs",
            exec: "/usr/lib/furcate/runtimes/node/bin/node .furcate-serve.mjs",
            port: 8612,
            link,
            state,
            hosts: "shop-rs.app.example.net",
            token_env: Path::new("/var/lib/furcate/deploy/sites/shop-rs/token.env"),
            secrets,
            memory,
            devices: &[],
            user: Some("app-shop-rs"),
        }
    }

    fn render_with(memory: &release::MemoryBound) -> String {
        let sdir = Path::new("/var/lib/furcate/deploy/sites/shop-rs");
        let link = sdir.join("current");
        let state = state_dir(sdir);
        let secrets = env_file(sdir);
        render_unit(&spec(&link, &state, &secrets, memory))
    }

    fn render() -> String {
        render_with(&release::MemoryBound::default())
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "furcate-unit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn the_state_directory_is_writable_beside_current() {
        // The failure this closes: ReadWritePaths named `current` alone, so
        // every write to state/ failed EROFS under ProtectSystem=strict, after
        // the whole of a workflow had already been paid for.
        let u = render();
        assert!(
            u.contains(
                "ReadWritePaths=/var/lib/furcate/deploy/sites/shop-rs/current \
                 /var/lib/furcate/deploy/sites/shop-rs/state\n"
            ),
            "{u}"
        );
        assert!(u.contains("ProtectSystem=strict\n"), "the grant only matters under strict");
    }

    #[test]
    fn a_site_runs_as_its_own_account_with_no_capabilities() {
        let u = render();
        assert!(u.contains("\nUser=app-shop-rs\nGroup=app-shop-rs\n"), "{u}");
        assert!(u.contains("\nCapabilityBoundingSet=\n"), "{u}");
        assert!(u.contains("\nAmbientCapabilities=\n"), "{u}");
        assert!(
            u.contains(
                "ExecStartPre=+/bin/chown -hR app-shop-rs:app-shop-rs \
                 /var/lib/furcate/deploy/sites/shop-rs/current/ \
                 /var/lib/furcate/deploy/sites/shop-rs/state\n"
            ),
            "{u}"
        );
    }

    #[test]
    fn the_site_token_is_never_written_into_the_world_readable_unit() {
        let u = render();
        assert!(!u.contains("not-a-real-token") && !u.contains("PRAECISE_TOKEN="), "{u}");
        assert!(u.contains("EnvironmentFile=/var/lib/furcate/deploy/sites/shop-rs/token.env\n"), "{u}");
    }

    #[test]
    fn a_site_that_declares_no_devices_names_none() {
        let u = render();
        assert!(!u.contains("DeviceAllow"), "{u}");
        assert!(!u.contains("SupplementaryGroups"), "{u}");
    }

    #[test]
    fn a_tpm_grant_is_the_resource_manager_and_its_group_only() {
        let sdir = Path::new("/r/sites/n");
        let m = release::MemoryBound::default();
        let u = render_unit(&UnitSpec {
            name: "n",
            exec: "/r/sites/n/current/bin/server",
            port: 8602,
            link: &sdir.join("current"),
            state: &sdir.join("state"),
            hosts: "n.example.com",
            token_env: &sdir.join("token.env"),
            secrets: &sdir.join("env"),
            memory: &m,
            devices: &[release::Device::Tpm],
            user: Some("app-n"),
        });
        assert!(u.contains("\nDeviceAllow=/dev/tpmrm0 rw\n"), "{u}");
        assert!(u.contains("\nSupplementaryGroups=tss\n"), "{u}");
        // Never the raw device, which does not serialise between users.
        assert!(!u.contains("/dev/tpm0"), "{u}");
        // The grant is inside [Service], where systemd reads it.
        let service = u.split("[Install]").next().unwrap();
        assert!(service.contains("DeviceAllow="), "{u}");
        // And it changes nothing else about the sandbox.
        assert!(u.contains("\nUser=app-n\n") && u.contains("CapabilityBoundingSet=\n"), "{u}");
    }

    #[test]
    fn placed_devices_fall_back_to_none_never_to_a_guess() {
        let d = tmp("devices");
        assert!(placed_devices(&d).is_empty());
        std::fs::write(d.join("devices.json"), r#"["tpm"]"#).unwrap();
        assert_eq!(placed_devices(&d), vec![release::Device::Tpm]);
        // A name the platform does not grant refuses the whole file.
        std::fs::write(d.join("devices.json"), r#"["tpm","gpu0"]"#).unwrap();
        assert!(placed_devices(&d).is_empty());
        std::fs::write(d.join("devices.json"), "not json").unwrap();
        assert!(placed_devices(&d).is_empty());
    }

    #[test]
    fn a_native_program_must_be_carried_inside_the_release() {
        let rel = tmp("native");
        std::fs::create_dir_all(rel.join("bin")).unwrap();
        std::fs::write(rel.join("bin/server"), b"\x7fELF").unwrap();
        let ok = native_program(&["./bin/server".into(), "--flag".into()], &rel).unwrap();
        assert_eq!(ok, rel.join("bin/server"));
        for bad in ["server", "/usr/bin/true", "./../etc/passwd", "./bin//server", "./missing"] {
            assert!(native_program(&[bad.into()], &rel).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn a_container_started_site_keeps_root_and_says_why() {
        assert!(runs_privileged("/usr/bin/docker run --rm x"));
        assert!(!runs_privileged("/usr/lib/furcate/runtimes/node/bin/npm run start"));
        let sdir = Path::new("/r/sites/b");
        let m = release::MemoryBound::default();
        let u = render_unit(&UnitSpec {
            name: "b",
            exec: "/usr/bin/docker run --rm x",
            port: 8601,
            link: &sdir.join("current"),
            state: &sdir.join("state"),
            hosts: "b.example.com",
            token_env: &sdir.join("token.env"),
            secrets: &sdir.join("env"),
            memory: &m,
            devices: &[],
            user: None,
        });
        assert!(!u.contains("\nUser="), "{u}");
        assert!(u.contains("root-equivalent"), "{u}");
    }

    #[test]
    fn a_user_name_fits_the_31_characters_systemd_accepts() {
        assert_eq!(site_user("exampleworkshop-platform-runtime"), "app-exampleworkshop-platform-ru");
        assert!(site_user("exampleworkshop-platform-runtime").len() <= 31);
        assert_eq!(site_user("shop-rs"), "app-shop-rs");
    }

    #[test]
    fn the_application_is_told_where_its_state_is_under_one_name() {
        let u = render();
        assert!(u.contains("Environment=FURCATE_STATE_DIR=/var/lib/furcate/deploy/sites/shop-rs/state\n"));
    }

    #[test]
    fn state_lives_beside_the_releases_and_not_inside_one() {
        // Inside a release it would be replaced by the next deploy, which is
        // the thing it exists to survive.
        let sdir = Path::new("/r/sites/a");
        assert_eq!(state_dir(sdir), PathBuf::from("/r/sites/a/state"));
        assert!(!state_dir(sdir).starts_with(sdir.join("releases")));
        assert!(!state_dir(sdir).starts_with(sdir.join("current")));
    }

    #[test]
    fn no_line_of_the_unit_carries_the_source_files_indentation() {
        // Three comment lines once lacked their `\n\` continuation, so the
        // Rust indentation went into the unit verbatim. systemd tolerated it;
        // the next directive written that way would not be a comment.
        let u = render();
        for line in u.lines() {
            assert!(!line.starts_with(' '), "indented line in the unit: {line:?}");
        }
    }

    #[test]
    fn creating_state_is_idempotent_and_leaves_an_existing_directory_alone() {
        use std::os::unix::fs::PermissionsExt;
        let sdir = tmp("state");
        let made = ensure_state_dir(&sdir).unwrap();
        assert!(made.is_dir());
        assert_eq!(std::fs::metadata(&made).unwrap().permissions().mode() & 0o777, 0o750);

        // An operator tightened it and the application wrote into it; a
        // redeploy must change neither.
        std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(made.join("register.json"), "{}").unwrap();
        let again = ensure_state_dir(&sdir).unwrap();
        assert_eq!(again, made);
        assert_eq!(std::fs::metadata(&again).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(again.join("register.json").is_file());
        std::fs::remove_dir_all(&sdir).ok();
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "furcate-memory-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn unit(memory: &release::MemoryBound) -> String {
        let sdir = Path::new("/r/sites/a");
        render_unit(&UnitSpec {
            name: "a",
            exec: "/usr/bin/true",
            port: 8600,
            link: &sdir.join("current"),
            state: &sdir.join("state"),
            hosts: "a.example.com",
            token_env: &sdir.join("token.env"),
            secrets: &sdir.join("env"),
            memory,
            devices: &[],
            user: Some("app-a"),
        })
    }

    #[test]
    fn a_site_is_born_bounded_without_anybody_remembering_a_drop_in() {
        let u = unit(&release::MemoryBound::default());
        assert!(u.contains("\nMemoryHigh=6G\n"), "{u}");
        assert!(u.contains("\nMemoryMax=10G\n"), "{u}");
        // In [Service], where systemd reads them, and not after [Install].
        let service = u.find("[Service]").unwrap();
        let install = u.find("[Install]").unwrap();
        let high = u.find("MemoryHigh=").unwrap();
        assert!(service < high && high < install);
    }

    #[test]
    fn a_declared_bound_is_the_one_the_unit_carries() {
        let m = release::MemoryBound { high: "12G".into(), max: "20G".into() };
        let u = unit(&m);
        assert!(u.contains("\nMemoryHigh=12G\n") && u.contains("\nMemoryMax=20G\n"), "{u}");
        assert!(!u.contains("MemoryMax=10G"));
    }

    #[test]
    fn a_placed_bound_is_read_back_and_a_bad_one_falls_back_to_the_default_not_to_none() {
        let sdir = tmp("placed");
        assert_eq!(placed_memory(&sdir), release::MemoryBound::default());

        std::fs::write(sdir.join("memory.json"), r#"{"high":"8G","max":"16G"}"#).unwrap();
        assert_eq!(placed_memory(&sdir).max, "16G");

        // A typo must never be the thing that unbounds a site.
        std::fs::write(sdir.join("memory.json"), r#"{"high":"16G","max":"8G"}"#).unwrap();
        assert_eq!(placed_memory(&sdir), release::MemoryBound::default());
        std::fs::write(sdir.join("memory.json"), "not json").unwrap();
        assert_eq!(placed_memory(&sdir), release::MemoryBound::default());
        std::fs::remove_dir_all(&sdir).ok();
    }

    #[test]
    fn the_manifest_declares_a_bound_or_says_nothing_and_a_bad_one_stops_the_deploy() {
        let src = tmp("src");
        assert!(site_memory(&src).unwrap().is_none(), "no manifest is no statement");

        std::fs::write(src.join("furcate-deploy.json"), r#"{"routes":[]}"#).unwrap();
        assert!(site_memory(&src).unwrap().is_none());

        std::fs::write(
            src.join("furcate-deploy.json"),
            r#"{"memory":{"high":"12G","max":"20G"}}"#,
        )
        .unwrap();
        assert_eq!(site_memory(&src).unwrap().unwrap().high, "12G");

        std::fs::write(
            src.join("furcate-deploy.json"),
            r#"{"memory":{"high":"6G","max":"infinity"}}"#,
        )
        .unwrap();
        assert!(site_memory(&src).is_err());
        std::fs::remove_dir_all(&src).ok();
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    const SECRET: &str = "sk-live-0123456789abcdef==";

    #[test]
    fn lines_on_stdin_are_pairs_and_blank_lines_and_comments_are_skipped() {
        let text = format!("# model credentials\n\nMODEL_API_KEY={SECRET}\r\nDATABASE_URL=postgresql://u:p@h/db\nEMPTY=\n");
        let pairs = parse_env_lines(&text).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("MODEL_API_KEY".to_string(), SECRET.to_string()),
                ("DATABASE_URL".to_string(), "postgresql://u:p@h/db".to_string()),
                // Setting a key to nothing is how a console clears one.
                ("EMPTY".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn a_refusal_names_the_line_and_never_repeats_what_was_on_it() {
        // A secret pasted without its key, and one whose base64 padding puts
        // an `=` inside it: neither may come back in an error message, which
        // ends up in a terminal, a log, or a console's HTTP reply.
        for text in [format!("OK=1\n{SECRET_NO_EQ}\n"), format!("OK=1\nsk-live {SECRET}\n")] {
            let e = parse_env_lines(&text).unwrap_err().to_string();
            assert!(e.contains("line 2"), "{e}");
            assert!(!e.contains("sk-live"), "the refusal repeated the secret: {e}");
        }
        let e = parse_env_pair(&format!("sk-live {SECRET}"), "argument 1").unwrap_err().to_string();
        assert!(e.contains("argument 1") && !e.contains("sk-live"), "{e}");
    }

    const SECRET_NO_EQ: &str = "sk-live-0123456789abcdef";

    #[test]
    fn a_value_that_would_become_two_lines_is_refused() {
        assert!(parse_env_pair("KEY=a\rb", "line 1").is_err());
        assert!(parse_env_pair("KEY=a\nOTHER=b", "line 1").is_err());
    }

    #[test]
    fn setting_a_key_again_replaces_it_and_leaves_every_other_line_in_place() {
        let existing = "A=1\nB=2\n\nC=3\n";
        let merged = merge_env(existing, &[("B".into(), "20".into()), ("D".into(), "4".into())]);
        assert_eq!(merged, "A=1\nC=3\nB=20\nD=4\n");
        // A key that is a prefix of another is not the other.
        let merged = merge_env("AB=1\n", &[("A".into(), "2".into())]);
        assert_eq!(merged, "AB=1\nA=2\n");
    }

    #[test]
    fn the_env_file_is_private_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("furcate-env-{}", std::process::id()));
        let sdir = root.join("sites").join("envsite");
        std::fs::create_dir_all(&sdir).unwrap();
        std::env::set_var("FURCATE_DEPLOY_ROOT", &root);
        store_env("envsite", &[("MODEL_API_KEY".into(), SECRET.into())]).unwrap();
        store_env("envsite", &[("OTHER".into(), "x".into())]).unwrap();
        std::env::remove_var("FURCATE_DEPLOY_ROOT");

        let file = sdir.join("env");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("MODEL_API_KEY={SECRET}\nOTHER=x\n")
        );
        assert!(!sdir.join("env.writing").exists(), "no half-written file is left behind");
        std::fs::remove_dir_all(&root).ok();
    }
}

#[cfg(test)]
mod withdraw_tests {
    use super::*;
    use std::time::Duration;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "furcate-withdraw-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A placed unit with the two drop-ins production sites actually carry.
    fn placed_unit(dir: &Path, name: &str) {
        std::fs::write(dir.join(format!("furcate-app-{name}.service")), "[Service]\n").unwrap();
        let d = dir.join(format!("furcate-app-{name}.service.d"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("10-memory-bound.conf"), "[Service]\nMemoryMax=10G\n").unwrap();
        std::fs::write(d.join("state-writable.conf"), "[Service]\n").unwrap();
    }

    /// A systemd that reports `states` in turn for ActiveState and records
    /// every call it was given.
    fn fake(states: Vec<&'static str>, calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>)
        -> impl FnMut(&[&str]) -> Option<String> {
        let mut states = states.into_iter();
        let mut last = "inactive";
        move |args: &[&str]| {
            calls.borrow_mut().push(args.join(" "));
            if args.first() == Some(&"show") {
                if let Some(s) = states.next() {
                    last = s;
                }
                return Some(last.to_string());
            }
            Some(String::new())
        }
    }

    #[test]
    fn a_running_unit_is_stopped_then_disabled_then_its_files_go_then_systemd_forgets_it() {
        let sd = tmp("sd");
        let archive = tmp("archive").join("unit");
        placed_unit(&sd, "gone");
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut ctl = fake(vec!["active", "deactivating", "inactive"], calls.clone());

        withdraw_unit("gone", &sd, Some(archive.as_path()), &mut ctl, Duration::from_secs(10)).unwrap();

        let calls = calls.borrow();
        let pos = |needle: &str| calls.iter().position(|c| c.starts_with(needle)).unwrap_or_else(|| panic!("no `{needle}` in {calls:?}"));
        assert!(pos("stop --no-block furcate-app-gone.service") < pos("disable furcate-app-gone.service"));
        assert!(pos("disable") < pos("daemon-reload"));
        // It waited for the stop to finish, not merely for it to be accepted.
        assert_eq!(calls.iter().filter(|c| c.starts_with("show")).count(), 3);

        assert!(!sd.join("furcate-app-gone.service").exists());
        assert!(!sd.join("furcate-app-gone.service.d").exists());
        // Hand-written drop-ins are archived before they are deleted.
        assert!(archive.join("furcate-app-gone.service").is_file());
        assert!(archive.join("furcate-app-gone.service.d/10-memory-bound.conf").is_file());
        assert!(archive.join("furcate-app-gone.service.d/state-writable.conf").is_file());
        std::fs::remove_dir_all(&sd).ok();
        std::fs::remove_dir_all(archive.parent().unwrap()).ok();
    }

    #[test]
    fn a_unit_that_will_not_stop_fails_loudly_and_nothing_is_removed() {
        let sd = tmp("stuck");
        placed_unit(&sd, "stuck");
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut ctl = fake(vec!["active"], calls.clone());

        let e = withdraw_unit("stuck", &sd, None, &mut ctl, Duration::ZERO).unwrap_err();
        assert!(e.to_string().contains("nothing was removed"), "{e}");

        assert!(sd.join("furcate-app-stuck.service").is_file());
        assert!(sd.join("furcate-app-stuck.service.d/10-memory-bound.conf").is_file());
        assert!(!calls.borrow().iter().any(|c| c.starts_with("disable") || c == "daemon-reload"));
        std::fs::remove_dir_all(&sd).ok();
    }

    #[test]
    fn a_unit_whose_state_cannot_be_read_is_not_deleted() {
        let sd = tmp("blind");
        placed_unit(&sd, "blind");
        let mut ctl = |_: &[&str]| -> Option<String> { None };
        assert!(withdraw_unit("blind", &sd, None, &mut ctl, Duration::ZERO).is_err());
        assert!(sd.join("furcate-app-blind.service").is_file());
        std::fs::remove_dir_all(&sd).ok();
    }

    #[test]
    fn a_unit_that_stopped_but_would_not_disable_keeps_its_files() {
        let sd = tmp("nodisable");
        placed_unit(&sd, "nd");
        let mut ctl = |args: &[&str]| -> Option<String> {
            match args.first().copied() {
                Some("show") => Some("inactive".into()),
                Some("disable") => None,
                _ => Some(String::new()),
            }
        };
        assert!(withdraw_unit("nd", &sd, None, &mut ctl, Duration::ZERO).is_err());
        assert!(sd.join("furcate-app-nd.service").is_file());
        std::fs::remove_dir_all(&sd).ok();
    }

    #[test]
    fn a_static_site_has_no_unit_and_systemd_is_only_asked() {
        let sd = tmp("static");
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut ctl = fake(vec!["inactive"], calls.clone());
        withdraw_unit("landing", &sd, None, &mut ctl, Duration::ZERO).unwrap();
        assert!(calls.borrow().iter().all(|c| c.starts_with("show")), "{:?}", calls.borrow());
        std::fs::remove_dir_all(&sd).ok();
    }

    #[test]
    fn a_unit_that_exited_badly_on_sigterm_counts_as_stopped() {
        assert!(is_stopped("inactive"));
        assert!(is_stopped("failed"));
        for s in ["active", "activating", "deactivating", "reloading", ""] {
            assert!(!is_stopped(s), "{s:?}");
        }
    }
}

#[cfg(test)]
mod rename_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_path_is_rebased_by_component_and_only_when_it_was_under_the_old_directory() {
        let from = Path::new("/var/lib/furcate/deploy/sites/shop-rs");
        let to = Path::new("/var/lib/furcate/deploy/sites/shop");
        assert_eq!(
            rebase("/var/lib/furcate/deploy/sites/shop-rs/releases/abc", from, to).as_deref(),
            Some("/var/lib/furcate/deploy/sites/shop/releases/abc")
        );
        assert_eq!(
            rebase("/var/lib/furcate/deploy/sites/shop-rs", from, to).as_deref(),
            Some("/var/lib/furcate/deploy/sites/shop")
        );
        // Another site whose name begins with this one's is not this one.
        assert_eq!(rebase("/var/lib/furcate/deploy/sites/shop-rs-web/current", from, to), None);
        assert_eq!(rebase("/usr/lib/furcate/runtimes/node/bin/node", from, to), None);
        assert_eq!(rebase(".furcate-serve.mjs", from, to), None);
    }

    #[test]
    fn env_paths_into_the_old_directory_follow_it_and_nothing_else_changes() {
        let from = Path::new("/r/sites/shop-rs");
        let to = Path::new("/r/sites/shop");
        let text = "RS_STATE_DIR=/r/sites/shop-rs/state\n\
                    MODEL_API_KEY=sk-shop-rs-secret\n\
                    OTHER_SITE=/r/sites/shop-rs-web/state\n\
                    HOME_DIR=/r/sites/shop-rs\n\
                    DATABASE_URL=postgresql://t_shop_rs:pw@h:5432/t_shop_rs\n";
        let (out, changed) = rebase_env(text, from, to);
        assert_eq!(
            out,
            "RS_STATE_DIR=/r/sites/shop/state\n\
             MODEL_API_KEY=sk-shop-rs-secret\n\
             OTHER_SITE=/r/sites/shop-rs-web/state\n\
             HOME_DIR=/r/sites/shop\n\
             DATABASE_URL=postgresql://t_shop_rs:pw@h:5432/t_shop_rs\n"
        );
        assert_eq!(changed, vec!["RS_STATE_DIR", "HOME_DIR"]);
    }

    #[test]
    fn a_repository_still_mapped_to_the_old_name_is_found_without_reading_the_secret() {
        let cfg = json!({
            "secret": "whsec-not-printed",
            "repos": {
                "alice/shop": {"site": "shop-rs", "domains": ["shop.example.com"]},
                "alice/other": {"site": "other", "domains": ["o.example.com"]},
                "alice/shop-web": {"site": "shop-rs", "domains": ["w.example.com"]}
            }
        });
        assert_eq!(gitdeploy_repos_for(&cfg, "shop-rs"), vec!["alice/shop", "alice/shop-web"]);
        assert!(gitdeploy_repos_for(&cfg, "shop").is_empty());
        assert!(gitdeploy_repos_for(&json!({}), "shop-rs").is_empty());
    }

    #[test]
    fn derived_addresses_are_recognised_under_both_zones_and_the_old_local_one() {
        let root = std::env::temp_dir().join(format!("furcate-zones-{}", std::process::id()));
        std::fs::create_dir_all(root.join("edge")).unwrap();
        std::fs::write(root.join("edge/zone"), "app.example.net\n").unwrap();
        std::fs::write(root.join("edge/zone-mcp"), "mcp.example.net\n").unwrap();
        // No wildcard on disk: an address already written into a manifest was
        // still derived from the name, whatever the certificate state is today.
        let z = derived_zones(root.to_str().unwrap());
        for want in ["app.example.net", "mcp.example.net", "local"] {
            assert!(z.iter().any(|x| x == want), "{want} missing from {z:?}");
        }
        std::fs::remove_dir_all(&root).ok();
    }
}

#[cfg(test)]
mod state_probe_tests {
    use super::*;

    #[test]
    fn the_probe_joins_the_units_mount_namespace_and_nothing_else() {
        let cmd = state_probe(4242, Path::new("/r/sites/a/state"));
        assert_eq!(&cmd[..5], &["nsenter", "-t", "4242", "-m", "--"]);
        // Not -a, -p or -U: the question is what the unit's mounts allow, and
        // joining more than that would answer a different one.
        assert!(!cmd.iter().any(|a| a == "-a" || a == "-p" || a == "-U"));
    }

    #[test]
    fn the_path_is_an_argument_and_never_part_of_the_script() {
        let odd = Path::new("/r/sites/a/state\"; rm -rf /; \"");
        let cmd = state_probe(1, odd);
        assert_eq!(cmd.last().unwrap(), &odd.display().to_string());
        let script = &cmd[7];
        assert!(!script.contains("/r/sites"), "{script}");
    }

    #[test]
    fn the_script_itself_writes_removes_and_reports_honestly() {
        // Run without nsenter: the script is the part that can be exercised
        // anywhere, and a script that "succeeds" on a directory it could not
        // write would make the whole probe decorative.
        let cmd = state_probe(1, Path::new("/unused"));
        let script = cmd[7].as_str();
        let dir = std::env::temp_dir().join(format!("furcate-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = Command::new("/bin/sh")
            .args(["-c", script, "furcate-state-probe"])
            .arg(&dir)
            .status()
            .unwrap();
        assert!(ok.success());
        assert!(!dir.join(".furcate-write-probe").exists(), "the probe left its file behind");

        let missing = dir.join("does-not-exist");
        let bad = Command::new("/bin/sh")
            .args(["-c", script, "furcate-state-probe"])
            .arg(&missing)
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!bad.success(), "a directory that cannot be written must not pass");
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod launcher_tests {
    use super::*;

    #[test]
    fn the_launcher_imports_from_the_package_it_was_given() {
        let l = praecise_launcher(detect::PRAECISE_PACKAGE);
        assert!(l.contains("\nimport { App, serve } from \"@praecise/harness\";\n"), "{l}");
        assert!(!l.contains("from \"praecise\""));
    }

    #[test]
    fn an_app_not_yet_migrated_gets_exactly_the_launcher_it_had() {
        // Byte for byte the file every deployed agent app runs today, so a
        // redeploy of one that still depends on `praecise` changes nothing.
        let l = praecise_launcher(detect::PRAECISE_PACKAGE_LEGACY);
        assert!(l.starts_with("#!/usr/bin/env node\n// Written by `furcatectl deploy`."));
        assert!(l.contains("\nimport { App, serve } from \"praecise\";\n"));
        assert!(l.contains("\nawait serve({\n  app,\n"));
        assert!(l.contains("  ...(token ? { token } : {}),\n});\n"));
        assert!(!l.contains("{{") && !l.contains("}}"), "a format escape leaked into the file");
    }
}
