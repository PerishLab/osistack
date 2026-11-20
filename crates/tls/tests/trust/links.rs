use crate::support::*;
use tls::x509::trust::{Chain, Defect, Roots};
use tls::x509::{Certificate, Time};

const BAD: [(&str, &str); 2] = [
    ("260101000000Z", "270101000000Z"),
    ("280101000000Z", "300101000000Z"),
];

fn now() -> Time {
    Time {
        year: 2027,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    }
}

fn roots(specs: &[Spec]) -> Roots {
    let mut found = Roots::default();
    for spec in specs {
        found.add(&spec.der()).unwrap();
    }
    found
}

fn build(top: &Spec, pool: &[Spec], held: &Roots) -> Result<Chain, Defect> {
    let certs: Vec<Certificate> = pool.iter().map(|spec| spec.cert()).collect();
    Chain::build(&top.cert(), &certs, held, now())
}

#[test]
fn choice() {
    let root = Spec::new("root", "root", 1).ca(None);
    let held = roots(&[root]);
    let gone = Spec::new("inter", "root", 2)
        .ca(None)
        .window(BAD[0].0, BAD[0].1);
    let live = Spec::new("inter", "root", 4).ca(None);
    let top = Spec::new("leaf", "inter", 3);
    let chain = build(&top, &[gone.clone(), live.clone()], &held).unwrap();
    assert_eq!(chain.certs()[1].serial, live.cert().serial);
    let chain = build(&top, &[live.clone(), gone.clone()], &held).unwrap();
    assert_eq!(chain.certs()[1].serial, live.cert().serial);
    let other = Spec::new("inter", "root", 5)
        .ca(None)
        .window(BAD[1].0, BAD[1].1);
    let error = build(&top, &[gone.clone(), other], &held).unwrap_err();
    assert_eq!(error, Defect::Dated);
    let old = Spec::new("root", "root", 8)
        .ca(None)
        .window(BAD[0].0, BAD[0].1);
    let new = Spec::new("root", "root", 9).ca(None);
    for pair in [[old.clone(), new.clone()], [new.clone(), old.clone()]] {
        let chain = build(&top, std::slice::from_ref(&live), &roots(&pair)).unwrap();
        assert_eq!(chain.certs()[2].serial, new.cert().serial);
    }
}

#[test]
fn first() {
    let old = Spec::new("root", "root", 8)
        .ca(None)
        .window(BAD[0].0, BAD[0].1);
    let held = roots(&[old]);
    let mid = Spec::new("root", "root", 4);
    let top = Spec::new("leaf", "root", 3);
    assert_eq!(
        build(&top, std::slice::from_ref(&mid), &held).unwrap_err(),
        Defect::Dated
    );
    let held = roots(&[Spec::new("other", "other", 6)]);
    assert_eq!(build(&top, &[mid], &held).unwrap_err(), Defect::Authority);
    let held = roots(&[Spec::new("root", "root", 8).window(BAD[0].0, BAD[0].1)]);
    let both = [Spec::new("root", "root", 4).ca(None).usage(0x80)];
    assert_eq!(build(&top, &both, &held).unwrap_err(), Defect::Dated);
}

struct Plan {
    spec: Spec,
    flaws: Vec<Defect>,
}

impl Dice {
    fn common(&mut self, mut plan: Plan) -> Plan {
        if self.below(8) == 0 {
            let window = BAD[self.below(2)];
            plan.spec = plan.spec.clone().window(window.0, window.1);
            plan.flaws.push(Defect::Dated);
        }
        if self.below(10) == 0 {
            plan.spec = plan.spec.clone().extra(true);
            plan.flaws.push(Defect::Critical);
        } else if self.below(4) == 0 {
            plan.spec = plan.spec.clone().extra(false);
        }
        plan
    }

    fn serve(&mut self, mut plan: Plan) -> Plan {
        if self.below(4) == 0 {
            plan.spec = plan.spec.clone().serves(&[CLIENT]);
            plan.flaws.push(Defect::Purpose);
        } else if self.below(4) == 0 {
            plan.spec = plan.spec.clone().serves(&[ANY, CLIENT]);
        }
        plan
    }

    fn rule(&mut self, mut plan: Plan, at: usize, root: bool) -> Plan {
        let kind = self.below(10);
        if kind == 0 {
            plan.spec = plan.spec.clone().notca();
            plan.flaws.push(Defect::Authority);
        } else if kind == 1 && !root {
            plan.flaws.push(Defect::Authority);
        } else if kind > 1 || !root {
            let limit = self.below(5);
            let depth = (limit < 4).then_some(limit);
            plan.spec = plan.spec.clone().ca(depth.map(|max| max as u8));
            if depth.is_some_and(|max| max + 1 < at) {
                plan.flaws.push(Defect::Depth);
            }
        }
        if self.below(8) == 0 {
            plan.spec = plan.spec.clone().usage(0x80);
            plan.flaws.push(Defect::Usage);
        } else if self.below(3) == 0 {
            plan.spec = plan.spec.clone().usage(0x84);
        }
        plan
    }

    fn cert(&mut self, at: usize, last: usize) -> Plan {
        let issuer = if at == last { at } else { at + 1 };
        let spec = Spec::new(&format!("c{at}"), &format!("c{issuer}"), at as u8 + 1);
        let plan = Plan {
            spec,
            flaws: Vec::new(),
        };
        let plan = self.common(plan);
        let plan = if at < last { self.serve(plan) } else { plan };
        if at == 0 {
            plan
        } else {
            self.rule(plan, at, at == last)
        }
    }
}

#[test]
fn sweep() {
    for seed in 0..64 {
        let mut dice = Dice::new(seed);
        let count = dice.below(4);
        let last = count + 1;
        let plans: Vec<Plan> = (0..=last).map(|at| dice.cert(at, last)).collect();
        let held = roots(&[plans[last].spec.clone()]);
        let hidden = (count > 0 && dice.below(4) == 0).then(|| 1 + dice.below(count));
        let pool: Vec<Spec> = (1..=count)
            .filter(|at| Some(*at) != hidden)
            .map(|at| plans[at].spec.clone())
            .collect();
        let found = build(&plans[0].spec, &pool, &held);
        let mut flaws: Option<&[Defect]> = None;
        let mut stuck = false;
        for (at, plan) in plans.iter().enumerate() {
            if hidden == Some(at) {
                stuck = true;
                break;
            }
            if !plan.flaws.is_empty() {
                flaws = Some(&plan.flaws);
                break;
            }
        }
        match (found, flaws, stuck) {
            (Ok(chain), None, false) => assert_eq!(chain.certs().len(), last + 1),
            (Err(defect), Some(list), _) => assert!(list.contains(&defect), "{seed}"),
            (Err(Defect::Unlinked), None, true) => {}
            other => panic!("{seed} {other:?}"),
        }
    }
}

#[test]
fn known() {
    let root = Spec::new("root", "root", 1).ca(None);
    let plain = |spec: Spec| spec.usage(0x04).serves(&[SERVER]).named();
    let top = plain(Spec::new("leaf", "inter", 3)).urgent();
    let mid = plain(Spec::new("inter", "root", 2).ca(None)).urgent();
    let held = roots(&[plain(root.clone()).urgent()]);
    assert!(build(&top, std::slice::from_ref(&mid), &held).is_ok());
    let held = roots(&[root]);
    assert!(build(&top, &[mid], &held).is_ok());
}

#[test]
fn stale() {
    let root = Spec::new("root", "root", 1).ca(Some(1));
    let held = roots(&[root]);
    let dead = Spec::new("inter", "nobody", 9).ca(None);
    let live = Spec::new("inter", "root", 2).ca(None);
    let top = Spec::new("leaf", "inter", 3);
    let chain = build(&top, &[dead, live], &held).unwrap();
    assert_eq!(chain.certs().len(), 3);
}

#[test]
fn anchored() {
    let mid = Spec::new("inter", "root", 2).ca(None);
    let top = Spec::new("leaf", "inter", 3);
    let held = roots(std::slice::from_ref(&mid));
    let chain = build(&top, &[], &held).unwrap();
    assert_eq!(chain.certs().len(), 2);
}

#[test]
fn forged() {
    let lone = Spec::new("lone", "lone", 5);
    let held = roots(std::slice::from_ref(&lone));
    let fake = lone.clone().forged(9);
    assert_eq!(build(&lone, &[], &held).unwrap().certs().len(), 1);
    assert_eq!(build(&fake, &[], &held).unwrap_err(), Defect::Forged);
}
