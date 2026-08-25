//! Thin binary shell: parse args, dispatch to the library's `run_*` fns,
//! exit with their code. All logic lives in the library for testability.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "writ",
    version,
    about = "Proof-gated capability guard for MCP tool calls",
    long_about = "Verify a .telos service, derive what its functions may do from \
                  the resulting proof, and enforce exactly that on MCP tool calls."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a .telos service and print its derived MCP grant table.
    Verify {
        /// Path to the .telos source.
        source: String,
    },
    /// Guard an MCP server by relaying its tool calls through a WritGuard.
    Guard {
        /// Path to a telos-proof.json manifest document.
        #[arg(long)]
        manifest: String,
        /// .telos source for the full VALIDATE (hash) check.
        #[arg(long)]
        source: Option<String>,
        /// Hex ed25519 public key the manifest must be signed with.
        #[arg(long, requires = "signature")]
        pubkey: Option<String>,
        /// Hex ed25519 signature, or a path to a file containing one.
        #[arg(long)]
        signature: Option<String>,
        /// The MCP server process to spawn and guard.
        #[arg(long = "target")]
        target_program: String,
        /// Arguments for the target program (repeatable).
        #[arg(long = "target-arg")]
        target_args: Vec<String>,
        /// Tools whose calls are existence-checked only (e.g. Pure tools).
        #[arg(long = "allow-tool")]
        allow_tools: Vec<String>,
    },
    /// Did the resource-access surface widen between two .telos versions?
    ///
    /// Exit 0 = no change or a narrowing; 1 = a widening (new Write,
    /// Pure -> Read/Write, or a new function earning access).
    Diff {
        /// The older .telos source.
        before: String,
        /// The newer .telos source.
        after: String,
    },
    /// Check the environment before running the pipeline.
    Doctor,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Verify { source } => tpt_writ_cli::run_verify(&source),
        Commands::Guard {
            manifest,
            source,
            pubkey,
            signature,
            target_program,
            target_args,
            allow_tools,
        } => tpt_writ_cli::run_guard(tpt_writ_cli::GuardOptions {
            manifest_path: manifest,
            source_path: source,
            pubkey_and_sig: pubkey.zip(signature),
            target_program,
            target_args,
            allow_tools,
        }),
        Commands::Diff { before, after } => tpt_writ_cli::run_diff(&before, &after),
        Commands::Doctor => {
            if tpt_writ_cli::doctor_ok() {
                0
            } else {
                1
            }
        }
    };
    std::process::exit(code);
}
