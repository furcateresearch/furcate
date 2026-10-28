//! Leave-one-subject-out evaluation of the conformal escalation gate on UCI HAR.
//!
//!     cargo run --release -p furcate-sense --example gate_eval -- "<UCI HAR Dataset dir>" [delta]
//!
//! The dataset is the public "Human Activity Recognition Using Smartphones"
//! set (CC BY 4.0), read from the directory the zip unpacks to. Nothing is
//! downloaded and no data is written.
//!
//! The leaf is a small softmax classifier on a 64-dimensional random projection
//! of the 561 standardised features; the teacher is a softmax classifier on all
//! 561. Per held-out subject the models are fitted on 25 other subjects and 4
//! further subjects calibrate the gates and baselines. Agreement means the leaf
//! label equals the teacher label. Each method sees the held-out subject's
//! windows one at a time, in file order and again in a seeded shuffle.
//!
//! Reported per method: the escalation rate (audits included), the agreement
//! among windows not escalated (1 - kept-error), the fraction of subjects whose
//! kept-error is within delta, and 95% bootstrap intervals over subjects.

use furcate_sense::cascade::escalate::{Decision, EscalationReason};
use furcate_sense::cascade::gate::{calibrate_threshold, ConformalGate, GateConfig, Mode};
use std::path::Path;

const D: usize = 561;
const C: usize = 6;
const PROJ: usize = 64;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn u(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn normal(&mut self) -> f64 {
        let (a, b) = (self.u().max(1e-12), self.u());
        (-2.0 * a.ln()).sqrt() * (2.0 * std::f64::consts::PI * b).cos()
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

fn read_lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())).lines().map(str::to_string).collect()
}

struct Data {
    x: Vec<f32>,
    y: Vec<usize>,
    subject: Vec<usize>,
}

fn load(root: &Path) -> Data {
    let (mut x, mut y, mut subject) = (Vec::new(), Vec::new(), Vec::new());
    for split in ["train", "test"] {
        for l in read_lines(&root.join(split).join(format!("X_{split}.txt"))) {
            let row: Vec<f32> = l.split_ascii_whitespace().map(|v| v.parse().expect("a number")).collect();
            assert_eq!(row.len(), D);
            x.extend(row);
        }
        y.extend(read_lines(&root.join(split).join(format!("y_{split}.txt"))).iter().map(|l| l.trim().parse::<usize>().unwrap() - 1));
        subject.extend(read_lines(&root.join(split).join(format!("subject_{split}.txt"))).iter().map(|l| l.trim().parse::<usize>().unwrap()));
    }
    assert_eq!(x.len(), y.len() * D);
    assert_eq!(y.len(), subject.len());
    Data { x, y, subject }
}

/// Softmax regression with a bias, fitted by mini-batch gradient descent.
struct Soft {
    w: Vec<f32>,
    d: usize,
}

impl Soft {
    fn logits(&self, x: &[f32]) -> [f32; C] {
        let mut out = [0f32; C];
        for (c, o) in out.iter_mut().enumerate() {
            let row = &self.w[c * (self.d + 1)..(c + 1) * (self.d + 1)];
            *o = row[self.d] + row[..self.d].iter().zip(x).map(|(a, b)| a * b).sum::<f32>();
        }
        out
    }

    fn fit(x: &[Vec<f32>], y: &[usize], d: usize, epochs: usize, lr: f32, seed: u64) -> Soft {
        let mut m = Soft { w: vec![0.0; C * (d + 1)], d };
        let mut rng = Rng(seed | 1);
        let mut order: Vec<usize> = (0..x.len()).collect();
        for e in 0..epochs {
            rng.shuffle(&mut order);
            let step = lr / (1.0 + e as f32 * 0.15);
            for batch in order.chunks(64) {
                let mut g = vec![0f32; C * (d + 1)];
                for &i in batch {
                    let z = m.logits(&x[i]);
                    let p = softmax(&z, 1.0);
                    for c in 0..C {
                        let r = p[c] - if y[i] == c { 1.0 } else { 0.0 };
                        let row = &mut g[c * (d + 1)..(c + 1) * (d + 1)];
                        for (gj, xj) in row[..d].iter_mut().zip(&x[i]) {
                            *gj += r * xj;
                        }
                        row[d] += r;
                    }
                }
                let n = batch.len() as f32;
                for (wj, gj) in m.w.iter_mut().zip(&g) {
                    *wj -= step * (gj / n + 1e-4 * *wj);
                }
            }
        }
        m
    }
}

fn softmax(z: &[f32; C], t: f32) -> [f32; C] {
    let m = z.iter().cloned().fold(f32::MIN, f32::max);
    let mut e = [0f32; C];
    let mut s = 0.0;
    for c in 0..C {
        e[c] = ((z[c] - m) / t).exp();
        s += e[c];
    }
    for v in &mut e {
        *v /= s;
    }
    e
}

fn argmax(p: &[f32; C]) -> usize {
    (0..C).max_by(|a, b| p[*a].total_cmp(&p[*b])).unwrap()
}

#[derive(Clone, Copy)]
struct Item {
    logits: [f32; C],
    leaf: usize,
    teacher: usize,
    truth: usize,
}

impl Item {
    fn agrees(&self) -> bool {
        self.leaf == self.teacher
    }
    fn msp(&self) -> f64 {
        softmax(&self.logits, 1.0)[self.leaf] as f64
    }
    fn tempered(&self, t: f32) -> f64 {
        softmax(&self.logits, t)[self.leaf] as f64
    }
    /// One minus the normalised entropy: 1 for a certain answer, 0 for uniform.
    fn sharp(&self) -> f64 {
        let p = softmax(&self.logits, 1.0);
        let h: f64 = p.iter().map(|v| if *v > 0.0 { -(*v as f64) * (*v as f64).ln() } else { 0.0 }).sum();
        1.0 - h / (C as f64).ln()
    }
}

struct Fold {
    cal: Vec<Item>,
    test: Vec<Item>,
    leaf_acc: f64,
    teacher_acc: f64,
}

fn standardise(rows: &[usize], d: &Data, mean: &[f32], sd: &[f32]) -> Vec<Vec<f32>> {
    rows.iter().map(|&i| (0..D).map(|j| (d.x[i * D + j] - mean[j]) / sd[j]).collect()).collect()
}

fn make_fold(d: &Data, subjects: &[usize], k: usize, proj: &[f32]) -> Fold {
    let held = subjects[k];
    let others: Vec<usize> = (1..subjects.len()).map(|o| subjects[(k + o) % subjects.len()]).collect();
    let cal_subjects = &others[..4];
    let rows_of = |s: &[usize]| -> Vec<usize> { (0..d.y.len()).filter(|i| s.contains(&d.subject[*i])).collect() };
    let (train, cal, test) = (rows_of(&others[4..]), rows_of(cal_subjects), rows_of(&[held]));

    let n = train.len() as f32;
    let mut mean = vec![0f32; D];
    for &i in &train {
        for (j, m) in mean.iter_mut().enumerate() {
            *m += d.x[i * D + j] / n;
        }
    }
    let mut sd = vec![0f32; D];
    for &i in &train {
        for j in 0..D {
            sd[j] += (d.x[i * D + j] - mean[j]).powi(2) / n;
        }
    }
    for v in &mut sd {
        *v = v.sqrt().max(1e-6);
    }
    let project = |x: &Vec<f32>| -> Vec<f32> { (0..PROJ).map(|p| proj[p * D..(p + 1) * D].iter().zip(x).map(|(a, b)| a * b).sum()).collect() };

    let xtr = standardise(&train, d, &mean, &sd);
    let ytr: Vec<usize> = train.iter().map(|&i| d.y[i]).collect();
    let teacher = Soft::fit(&xtr, &ytr, D, 12, 0.05, 11 + k as u64);
    let ptr: Vec<Vec<f32>> = xtr.iter().map(project).collect();
    let leaf = Soft::fit(&ptr, &ytr, PROJ, 40, 0.05, 23 + k as u64);

    let items = |rows: &[usize]| -> Vec<Item> {
        standardise(rows, d, &mean, &sd)
            .iter()
            .zip(rows)
            .map(|(x, &i)| {
                let z = leaf.logits(&project(x));
                Item { logits: z, leaf: argmax(&z), teacher: argmax(&teacher.logits(x)), truth: d.y[i] }
            })
            .collect()
    };
    let (cal, test) = (items(&cal), items(&test));
    let acc = |v: &[Item], f: fn(&Item) -> usize| v.iter().filter(|i| f(i) == i.truth).count() as f64 / v.len() as f64;
    Fold { leaf_acc: acc(&test, |i| i.leaf), teacher_acc: acc(&test, |i| i.teacher), cal, test }
}

#[derive(Clone, Copy, Default)]
struct Outcome {
    n: usize,
    escalated: usize,
    kept: usize,
    kept_err: usize,
}

impl Outcome {
    fn kept_error(&self) -> Option<f64> {
        (self.kept > 0).then(|| self.kept_err as f64 / self.kept as f64)
    }
}

fn run_static(items: &[Item], score: impl Fn(&Item) -> f64, tau: f64) -> Outcome {
    let mut o = Outcome { n: items.len(), ..Default::default() };
    for it in items {
        if score(it) < tau {
            o.escalated += 1;
        } else {
            o.kept += 1;
            o.kept_err += (!it.agrees()) as usize;
        }
    }
    o
}

fn run_gate(items: &[Item], cal: &[Item], cfg: GateConfig) -> Outcome {
    let calibration: Vec<(f64, bool)> = cal.iter().map(|i| (i.msp(), i.agrees())).collect();
    let mut g = ConformalGate::new(cfg, &calibration).unwrap();
    let mut o = Outcome { n: items.len(), ..Default::default() };
    for it in items {
        match g.decide(it.msp()) {
            Decision::Keep => {
                o.kept += 1;
                o.kept_err += (!it.agrees()) as usize;
            }
            Decision::Escalate(reason) => {
                o.escalated += 1;
                // The teacher's answer is the label the gate learns from.
                if matches!(reason, EscalationReason::LowMargin | EscalationReason::Audit) {
                    g.observe(reason, it.msp(), it.agrees());
                }
            }
        }
    }
    o
}

/// The lowest escalation rate any fixed threshold on `score` reaches with kept-error within delta, knowing the answers.
fn run_oracle(items: &[Item], score: impl Fn(&Item) -> f64, delta: f64) -> Outcome {
    let mut taus: Vec<f64> = items.iter().map(&score).collect();
    taus.sort_by(|a, b| a.total_cmp(b));
    taus.push(2.0);
    let mut best = run_static(items, &score, 2.0);
    for t in taus {
        let o = run_static(items, &score, t);
        if o.kept_error().is_none_or(|e| e <= delta) {
            best = o;
            break;
        }
    }
    best
}

fn run_random(items: &[Item], rate: f64, seed: u64) -> Outcome {
    let mut r = Rng(seed | 1);
    let mut o = Outcome { n: items.len(), ..Default::default() };
    for it in items {
        if r.u() < rate {
            o.escalated += 1;
        } else {
            o.kept += 1;
            o.kept_err += (!it.agrees()) as usize;
        }
    }
    o
}

fn fit_temperature(cal: &[Item]) -> f32 {
    let mut best = (f32::MAX, 1.0);
    let mut t = 0.4f32;
    while t <= 6.0 {
        let nll: f32 = cal.iter().map(|i| -(softmax(&i.logits, t)[i.teacher].max(1e-12)).ln()).sum();
        if nll < best.0 {
            best = (nll, t);
        }
        t += 0.1;
    }
    best.1
}

struct Summary {
    name: String,
    per_subject: Vec<Outcome>,
}

fn pooled(os: &[&Outcome]) -> (f64, f64) {
    let n: usize = os.iter().map(|o| o.n).sum();
    let e: usize = os.iter().map(|o| o.escalated).sum();
    let k: usize = os.iter().map(|o| o.kept).sum();
    let ke: usize = os.iter().map(|o| o.kept_err).sum();
    (e as f64 / n as f64, if k > 0 { ke as f64 / k as f64 } else { f64::NAN })
}

fn report(s: &Summary, delta: f64, rng: &mut Rng) {
    let all: Vec<&Outcome> = s.per_subject.iter().collect();
    let (esc, kerr) = pooled(&all);
    let within = s.per_subject.iter().filter(|o| o.kerror_ok(delta)).count() as f64 / s.per_subject.len() as f64;
    let sig = s.per_subject.iter().filter(|o| significantly_over(o, delta)).count();
    let (mut escs, mut kerrs, mut withins) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..1000 {
        let pick: Vec<&Outcome> = (0..s.per_subject.len()).map(|_| &s.per_subject[(rng.next() % s.per_subject.len() as u64) as usize]).collect();
        let (e, k) = pooled(&pick);
        escs.push(e);
        kerrs.push(k);
        withins.push(pick.iter().filter(|o| o.kerror_ok(delta)).count() as f64 / pick.len() as f64);
    }
    let ci = |v: &mut Vec<f64>| {
        v.retain(|x| x.is_finite());
        v.sort_by(|a, b| a.total_cmp(b));
        if v.is_empty() { (f64::NAN, f64::NAN) } else { (v[v.len() * 25 / 1000], v[v.len() * 975 / 1000]) }
    };
    let (ec, kc, wc) = (ci(&mut escs), ci(&mut kerrs), ci(&mut withins));
    println!(
        "{:<34} esc {:5.3} [{:5.3},{:5.3}]  agree-kept {:5.3} [{:5.3},{:5.3}]  within delta {:4.2} [{:4.2},{:4.2}]  sig. over {:2}/{}",
        s.name, esc, ec.0, ec.1, 1.0 - kerr, 1.0 - kc.1, 1.0 - kc.0, within, wc.0, wc.1, sig, s.per_subject.len()
    );
}

/// P(X >= k) for X ~ Binomial(n, p), exact.
fn binom_tail(n: usize, k: usize, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let mut lf = vec![0f64; n + 1];
    for i in 1..=n {
        lf[i] = lf[i - 1] + (i as f64).ln();
    }
    (k..=n).map(|j| (lf[n] - lf[j] - lf[n - j] + j as f64 * p.ln() + (n - j) as f64 * (1.0 - p).ln()).exp()).sum()
}

/// Whether a subject's kept-error is significantly above delta (one-sided exact, 5%).
fn significantly_over(o: &Outcome, delta: f64) -> bool {
    o.kept > 0 && binom_tail(o.kept, o.kept_err, delta) < 0.05
}

trait KeptOk {
    fn kerror_ok(&self, delta: f64) -> bool;
}

impl KeptOk for Outcome {
    fn kerror_ok(&self, delta: f64) -> bool {
        self.kept_error().is_none_or(|e| e <= delta)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = Path::new(args.get(1).expect("usage: gate_eval DIR [delta]"));
    let delta: f64 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(0.05);
    let d = load(root);
    let mut subjects: Vec<usize> = d.subject.clone();
    subjects.sort();
    subjects.dedup();
    println!("windows {}  subjects {}  delta {delta}", d.y.len(), subjects.len());

    let mut rng = Rng(0x5EED_1234_ABCD_EF01);
    let proj: Vec<f32> = (0..PROJ * D).map(|_| (rng.normal() / (D as f64).sqrt()) as f32).collect();

    let folds: Vec<Fold> = {
        let mut out: Vec<Option<Fold>> = (0..subjects.len()).map(|_| None).collect();
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8);
        std::thread::scope(|s| {
            let mut handles = Vec::new();
            for t in 0..threads {
                let (d, subjects, proj) = (&d, &subjects, &proj);
                handles.push(s.spawn(move || (t..subjects.len()).step_by(threads).map(|k| (k, make_fold(d, subjects, k, proj))).collect::<Vec<_>>()));
            }
            for h in handles {
                for (k, f) in h.join().unwrap() {
                    out[k] = Some(f);
                }
            }
        });
        out.into_iter().map(|f| f.unwrap()).collect()
    };
    let n = folds.len() as f64;
    println!(
        "leaf accuracy vs truth {:.3}  teacher accuracy vs truth {:.3}  leaf-teacher agreement {:.3}",
        folds.iter().map(|f| f.leaf_acc).sum::<f64>() / n,
        folds.iter().map(|f| f.teacher_acc).sum::<f64>() / n,
        folds.iter().map(|f| f.test.iter().filter(|i| i.agrees()).count() as f64 / f.test.len() as f64).sum::<f64>() / n
    );

    for order in ["file order", "shuffled"] {
        println!("\n== {order}, delta {delta}");
        let streams: Vec<Vec<Item>> = folds
            .iter()
            .enumerate()
            .map(|(k, f)| {
                let mut v = f.test.clone();
                if order == "shuffled" {
                    Rng(77 + k as u64).shuffle(&mut v);
                }
                v
            })
            .collect();
        let cal_pairs = |f: &Fold, s: &dyn Fn(&Item) -> f64| -> Vec<(f64, bool)> { f.cal.iter().map(|i| (s(i), i.agrees())).collect() };

        let mut summaries: Vec<Summary> = Vec::new();
        let mut add = |name: &str, per_subject: Vec<Outcome>| summaries.push(Summary { name: name.to_string(), per_subject });

        add("static max-softmax (split conf.)", folds.iter().zip(&streams).map(|(f, s)| run_static(s, Item::msp, calibrate_threshold(&cal_pairs(f, &Item::msp), delta))).collect());
        add("static entropy score", folds.iter().zip(&streams).map(|(f, s)| run_static(s, Item::sharp, calibrate_threshold(&cal_pairs(f, &Item::sharp), delta))).collect());
        add("static temperature-scaled", folds.iter().zip(&streams).map(|(f, s)| {
            let t = fit_temperature(&f.cal);
            run_static(s, |i| i.tempered(t), calibrate_threshold(&cal_pairs(f, &|i| i.tempered(t)), delta))
        }).collect());
        add("oracle fixed threshold (hindsight)", streams.iter().map(|s| run_oracle(s, Item::msp, delta)).collect());
        for (name, mode, audit) in [
            ("gate ACI step 0.05, audit 0.05", Mode::Aci { step: 0.05 }, 0.05),
            ("gate ACI step 0.05, audit 0.10", Mode::Aci { step: 0.05 }, 0.10),
            ("gate ACI step 0.20, audit 0.10", Mode::Aci { step: 0.20 }, 0.10),
            ("gate buffer 3000/25, audit 0.10", Mode::Buffer { size: 3000, every: 25 }, 0.10),
        ] {
            let outs: Vec<Outcome> = folds.iter().zip(&streams).enumerate().map(|(k, (f, s))| run_gate(s, &f.cal, GateConfig { delta, audit_rate: audit, mode, seed: 1000 + k as u64 })).collect();
            if name.contains("audit 0.10") && name.contains("0.05") {
                let rate = outs.iter().map(|o| o.escalated).sum::<usize>() as f64 / outs.iter().map(|o| o.n).sum::<usize>() as f64;
                add(&format!("fixed-rate random (rate {rate:.3})"), streams.iter().enumerate().map(|(k, s)| run_random(s, rate, 5 + k as u64)).collect());
            }
            add(name, outs);
        }
        let mut brng = Rng(99);
        for s in &summaries {
            report(s, delta, &mut brng);
        }
    }
}
