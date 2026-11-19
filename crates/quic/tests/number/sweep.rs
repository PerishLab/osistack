use quic::Number;

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn small() {
    for full in 0..600u64 {
        let none = Number::new(full, None);
        if let Ok(number) = none {
            assert_eq!(number.restore(full.checked_sub(1)), full, "{full}");
            assert_eq!(number.restore(None), full, "{full}");
        }
        for acked in 0..full {
            let number = Number::new(full, Some(acked)).unwrap();
            assert_eq!(number.restore(Some(acked)), full, "{full} {acked}");
            assert_eq!(number.restore(Some(full - 1)), full, "{full} {acked}");
        }
    }
}

#[test]
fn random() {
    let mut state = 0x1234_5678_9abc_def1u64;
    for round in 0..40000 {
        let bits = 1 + next(&mut state) % 62;
        let full = next(&mut state) & ((1u64 << bits) - 1);
        let width = 1 + next(&mut state) % 31;
        let gap = 1 + next(&mut state) % (1u64 << width);
        let acked = full.checked_sub(gap);
        let Ok(number) = Number::new(full, acked) else {
            continue;
        };
        let low = acked.map_or(0, |top| top);
        let span = (full - low).max(1);
        let largest = low + next(&mut state) % span;
        let known = if full == 0 { None } else { Some(largest) };
        let hit = number.restore(known);
        assert_eq!(hit, full, "{round} {full} {acked:?} {largest}");
    }
}
