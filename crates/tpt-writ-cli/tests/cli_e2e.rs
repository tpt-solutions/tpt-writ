//! CLI end-to-end tests: run the real `writ` binary against the real
//! `.telos` fixtures — doctor, verify, diff (both directions), and the
//! guard's fail-closed trust gate.

use std::process::{Command, Output};

fn writ() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_writ"));
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    cmd
}

fn assert_exit(output: &Output, expected: i32, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{label}: expected exit {expected}, got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn doctor_passes_in_a_proper_checkout() {
    let out = writ().arg("doctor").output().expect("spawn writ");
    assert_exit(&out, 0, "writ doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("environment looks good"), "{stdout}");
}

#[test]
fn verify_prints_the_derived_grant_table() {
    let out = writ()
        .args(["verify", "examples/counter.telos"])
        .output()
        .expect("spawn writ");
    assert_exit(&out, 0, "writ verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("2/2 functions verified"), "{stdout}");
    // Vacuous proof -> Pure; proved obligation -> conservative coarse write.
    assert!(
        stdout.contains("noop") && stdout.contains("Pure"),
        "{stdout}"
    );
    assert!(
        stdout.contains("bump") && stdout.contains("Write(*)"),
        "{stdout}"
    );
}

#[test]
fn diff_flags_a_widening_and_reverses_to_no_widening() {
    // v1 -> v2 adds `reset` (a new Write): widening, exit 1.
    let widened = writ()
        .args([
            "diff",
            "examples/counter.telos",
            "examples/counter-v2.telos",
        ])
        .output()
        .expect("spawn writ");
    assert_exit(&widened, 1, "diff v1->v2");
    let stdout = String::from_utf8_lossy(&widened.stdout);
    assert!(stdout.contains("WIDENED"), "{stdout}");
    assert!(stdout.contains("+reset"), "{stdout}");

    // v2 -> v1 removes it: narrowing, exit 0.
    let narrowed = writ()
        .args([
            "diff",
            "examples/counter-v2.telos",
            "examples/counter.telos",
        ])
        .output()
        .expect("spawn writ");
    assert_exit(&narrowed, 0, "diff v2->v1");
    let stdout = String::from_utf8_lossy(&narrowed.stdout);
    assert!(stdout.contains("no widening"), "{stdout}");
}

#[test]
fn identical_sources_are_not_a_widening() {
    let out = writ()
        .args(["diff", "examples/counter.telos", "examples/counter.telos"])
        .output()
        .expect("spawn writ");
    assert_exit(&out, 0, "diff self");
}

#[test]
fn guard_refuses_an_unverifiable_manifest() {
    // A manifest with no --source and no --pubkey/--signature has no trust
    // gate at all: the guard must refuse rather than enforce on faith.
    let dir = std::env::temp_dir().join(format!("writ-test-{}", std::process::id()));

    std::fs::create_dir_all(&dir).unwrap();
    let manifest_path = dir.join("telos-proof.json");

    // Generate a genuine manifest by compiling a fixture via the library.
    let source = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/counter.telos"
    ))
    .unwrap();
    let artifact = tpt_writ_cli::compile_service(&source).unwrap();
    std::fs::write(
        &manifest_path,
        tpt_telos_codegen::proof::to_json(&artifact.manifest),
    )
    .unwrap();

    let out = writ()
        .args([
            "guard",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--target",
            "this-program-does-not-exist",
        ])
        .output()
        .expect("spawn writ");
    assert_exit(&out, 1, "guard without trust gate");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to guard"), "{stderr}");

    // ...and with --source supplied (hash gate), the same manifest is
    // accepted far enough to try spawning the (nonexistent) target.
    let out = writ()
        .args([
            "guard",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--source",
            "examples/counter.telos",
            "--target",
            "this-program-does-not-exist",
        ])
        .output()
        .expect("spawn writ");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed to spawn target"),
        "hash-gated manifest should get past loading: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
