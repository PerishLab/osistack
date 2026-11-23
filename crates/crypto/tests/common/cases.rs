use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

pub struct Case {
    pub id: u64,
    fields: BTreeMap<String, String>,
}

impl Case {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub fn bytes(&self, name: &str) -> Vec<u8> {
        super::hex(self.get(name).unwrap_or(""))
    }

    pub fn result(&self) -> &str {
        self.get("result").unwrap_or("")
    }
}

pub fn folder() -> Option<PathBuf> {
    match env::var("OSISTACK_WYCHEPROOF") {
        Ok(text) if !text.is_empty() => Some(PathBuf::from(text)),
        _ => None,
    }
}

pub fn rows(name: &str) -> Option<Vec<Case>> {
    let path = folder()?.join(name);
    let text = std::fs::read_to_string(path).ok()?;
    Some(parse(&text))
}

fn parse(text: &str) -> Vec<Case> {
    let mut out = Vec::new();
    let mut fields = BTreeMap::new();
    let mut id = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            store(&mut out, &mut fields, &mut id);
            continue;
        }
        if let Some(rest) = line.strip_prefix("# tcId = ") {
            store(&mut out, &mut fields, &mut id);
            id = rest.trim().parse().unwrap_or(0);
            continue;
        }
        if line.starts_with('#') || (line.starts_with('[') && line.ends_with(']')) {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            fields.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    store(&mut out, &mut fields, &mut id);
    out
}

fn store(out: &mut Vec<Case>, fields: &mut BTreeMap<String, String>, id: &mut u64) {
    if fields.is_empty() {
        return;
    }
    out.push(Case {
        id: *id,
        fields: std::mem::take(fields),
    });
    *id = 0;
}
