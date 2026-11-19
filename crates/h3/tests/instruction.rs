use h3::{Decoder, Error, Feedback, Instruction, Name, STATIC};
use wire::Huffman;

struct Rng(u64);

impl Rng {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % bound
    }

    fn bytes(&mut self, most: u64) -> Vec<u8> {
        let length = self.next(most + 1);
        (0..length).map(|_| b'a' + self.next(26) as u8).collect()
    }
}

struct Model {
    held: Vec<(Vec<u8>, Vec<u8>)>,
    capacity: usize,
    dropped: u64,
}

impl Model {
    fn cost(entry: &(Vec<u8>, Vec<u8>)) -> usize {
        entry.0.len() + entry.1.len() + 32
    }

    fn size(&self) -> usize {
        self.held.iter().map(Self::cost).sum()
    }

    fn add(&mut self, entry: (Vec<u8>, Vec<u8>)) {
        while self.size() + Self::cost(&entry) > self.capacity {
            self.held.remove(0);
            self.dropped += 1;
        }
        self.held.push(entry);
    }
}

fn script(seed: u64) -> (Vec<Instruction>, Model) {
    let mut rng = Rng(seed);
    let mut model = Model {
        held: Vec::new(),
        capacity: 600,
        dropped: 0,
    };
    let mut steps = vec![Instruction::Capacity(600)];
    for _ in 0..60 {
        let count = model.held.len() as u64;
        let value = rng.bytes(20);
        let pick = rng.next(4);
        let (step, entry) = match pick {
            0 if count > 0 => {
                let back = rng.next(count);
                let source = model.held[(count - back - 1) as usize].clone();
                (Instruction::Duplicate(back), source)
            }
            1 if count > 0 => {
                let back = rng.next(count);
                let name = model.held[(count - back - 1) as usize].0.clone();
                let step = Instruction::Insert {
                    name: Name::Dynamic(back),
                    value: value.clone(),
                };
                (step, (name, value))
            }
            2 => {
                let index = rng.next(STATIC.len() as u64) as usize;
                let name = STATIC[index].0.as_bytes().to_vec();
                let step = Instruction::Insert {
                    name: Name::Static(index),
                    value: value.clone(),
                };
                (step, (name, value))
            }
            _ => {
                let name = rng.bytes(12);
                let step = Instruction::Insert {
                    name: Name::Literal(name.clone()),
                    value: value.clone(),
                };
                (step, (name, value))
            }
        };
        steps.push(step);
        model.add(entry);
    }
    (steps, model)
}

fn agrees(decoder: &Decoder, model: &Model) {
    let table = decoder.table();
    assert_eq!(table.size(), model.size());
    assert_eq!(table.dropped(), model.dropped);
    let held: Vec<(Vec<u8>, Vec<u8>)> = table
        .entries()
        .into_iter()
        .map(|field| (field.name, field.value))
        .collect();
    assert_eq!(held, model.held);
}

#[test]
fn replay() {
    let huffman = Huffman::new();
    for seed in 0..40 {
        let (steps, model) = script(seed);
        for coded in [None, Some(&huffman)] {
            let mut stream = Vec::new();
            for step in &steps {
                stream.extend(step.encode(coded).unwrap());
            }
            let mut decoder = Decoder::new(600);
            assert_eq!(decoder.apply(&stream).unwrap(), stream.len());
            agrees(&decoder, &model);
        }
    }
}

#[test]
fn pieces() {
    let (steps, model) = script(7);
    let mut stream = Vec::new();
    for step in &steps {
        stream.extend(step.encode(Some(&Huffman::new())).unwrap());
    }
    for cut in 0..stream.len() {
        let mut decoder = Decoder::new(600);
        let used = decoder.apply(&stream[..cut]).unwrap();
        assert!(used <= cut);
        let rest = decoder.apply(&stream[used..]).unwrap();
        assert_eq!(used + rest, stream.len());
        agrees(&decoder, &model);
    }
}

#[test]
fn trickle() {
    let (steps, model) = script(11);
    let mut stream = Vec::new();
    for step in &steps {
        stream.extend(step.encode(None).unwrap());
    }
    let mut decoder = Decoder::new(600);
    let mut pending = Vec::new();
    for byte in stream {
        pending.push(byte);
        let used = decoder.apply(&pending).unwrap();
        pending.drain(..used);
    }
    assert!(pending.is_empty());
    agrees(&decoder, &model);
}

#[test]
fn counters() {
    let cases = [
        (Feedback::Acknowledge(0), vec![0x80]),
        (Feedback::Acknowledge(127), vec![0xff, 0x00]),
        (Feedback::Acknowledge(300), vec![0xff, 0xad, 0x01]),
        (Feedback::Cancel(63), vec![0x7f, 0x00]),
        (Feedback::Increment(200), vec![0x3f, 0x89, 0x01]),
    ];
    for (feedback, bytes) in cases {
        assert_eq!(feedback.encode().unwrap(), bytes);
        assert_eq!(
            Feedback::decode(&bytes).unwrap(),
            Some((feedback, bytes.len()))
        );
    }
    assert_eq!(Feedback::decode(&[]), Ok(None));
    assert_eq!(Feedback::decode(&[0xff]), Ok(None));
    assert_eq!(Feedback::Increment(0).encode(), Err(Error::Zero));
}
