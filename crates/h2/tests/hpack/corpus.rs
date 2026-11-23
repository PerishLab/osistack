use h2::Decoder;
use std::env;
use std::fs;
use std::path::Path;

#[test]
#[ignore = "corpus"]
fn walking() {
    let Ok(root) = env::var("OSISTACK_CORPUS") else {
        return;
    };
    if root.is_empty() {
        return;
    }
    let path = Path::new(&root);
    if !path.is_dir() {
        return;
    }
    visit(path);
}

fn visit(path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path);
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let parsed = std::panic::catch_unwind(|| {
            let _ = Decoder::new(4096).decode(&bytes);
        });
        assert!(parsed.is_ok(), "{}", path.display());
    }
}
