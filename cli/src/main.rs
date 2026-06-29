//! Thin shell for the `zip4n6` binary — all logic lives in `zip_forensic_cli`
//! (Humble Object). These lines are the irreducible binary entrypoint.
fn main() {
    let args: Vec<String> = std::env::args().collect(); // cov:unreachable: binary shell, logic tested in lib::dispatch
    let stdout = std::io::stdout(); // cov:unreachable: binary shell
    let mut out = stdout.lock(); // cov:unreachable: binary shell
    if let Err(e) = zip_forensic_cli::dispatch(&args, &mut out) {
        // cov:unreachable: binary shell
        eprintln!("{e}"); // cov:unreachable: binary shell
        std::process::exit(2); // cov:unreachable: binary shell
    }
}
