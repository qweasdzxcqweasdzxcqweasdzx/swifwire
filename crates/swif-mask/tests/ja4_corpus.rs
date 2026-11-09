//! Pack JA4/JA3 goldens — discrepancies vs browser capture are fixed in packs.

use swif_mask::{
    build_client_hello_record, ja3_string_from_record, ja4_a_from_record, ClientHelloProfile,
    TlsPackHints,
};

#[test]
fn chrome_stable_lab_matches_corpus() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/ja4/chrome_stable_lab.json"
    );
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("corpus")).unwrap();
    let hints = TlsPackHints {
        profile: ClientHelloProfile::ChromeStable,
        grease: v["grease"].as_bool().unwrap(),
        alpn: v["alpn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect(),
        sni_pool_ref: None,
    };
    let rec = build_client_hello_record(&hints, v["sni"].as_str().unwrap());
    assert_eq!(
        ja3_string_from_record(&rec).unwrap(),
        v["ja3_string"].as_str().unwrap()
    );
    assert_eq!(
        ja4_a_from_record(&rec).unwrap(),
        v["ja4_a"].as_str().unwrap()
    );
}
