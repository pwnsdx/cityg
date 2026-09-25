//! Finding H-07: a reference JOIN anchor vs the spec S4.2 closed-world
//! registry and S4.2.1/S4.2.2 presence rules.
use cityg_client::demo;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = demo::demo_bundle("bob")?;
    let keys: Vec<u64> = bundle.header_map.keys().copied().collect();
    println!("JOIN header keys: {keys:?}");

    let mut required: Vec<u64> = vec![20];
    required.extend(90..=99);
    required.extend(104..=109);
    required.extend(110..=113);
    required.extend([116, 119, 125, 139, 141, 142, 143, 146, 152, 153, 176, 177]);
    let missing: Vec<u64> = required
        .iter()
        .copied()
        .filter(|key| !keys.contains(key))
        .collect();
    println!("S4.2.1/S4.2.2 required keys MISSING from reference JOIN: {missing:?}");

    let mut registry = required.clone();
    registry.extend([
        121, 122, 130, 131, 132, 133, 134, 135, 136, 138, 144, 145, 148, 160, 161, 175, 178, 179,
        180, 181, 182, 183,
    ]);
    let outside: Vec<u64> = keys
        .iter()
        .copied()
        .filter(|key| !registry.contains(key))
        .collect();
    println!("keys OUTSIDE the S4.2 closed-world registry (spec => reject 907.1): {outside:?}");
    Ok(())
}
