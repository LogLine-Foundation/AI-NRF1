
use clap::{Parser, Subcommand, Args};
use std::fs;
use anyhow::Result;

#[derive(Parser)]
#[command(name="nrf1", version="0.4.0")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd
}

#[derive(Subcommand)]
enum Cmd {
    Bundle { #[arg(long)] receipt: String, #[arg(long)] context: Option<String>, #[arg(long, default_value="bundle.zip")] out: String },
    VerifyBundle { #[arg(long)] bundle: String },
    Ghost(GhostCmd),
}

#[derive(Args)]
struct GhostCmd {
    #[command(subcommand)]
    action: GhostAction
}

#[derive(Subcommand)]
enum GhostAction {
    New { #[arg(long)] body_hex: String, #[arg(long)] cid: String, #[arg(long)] did: String, #[arg(long)] rt: String },
    Promote { #[arg(long)] ghost_id: String, #[arg(long)] receipt_id: String },
    Expire { #[arg(long)] ghost_id: String, #[arg(long)] cause: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Bundle { receipt, context, out } => { /* identical to previous step (omitted here) */ }
        Cmd::VerifyBundle { bundle } => { /* idem */ }
        Cmd::Ghost(g) => match g.action {
            GhostAction::New { body_hex, cid, did, rt } => {
                println!("(stub) would POST /ghosts with cid={cid} did={did} rt={rt} body_hex.len={}", body_hex.len());
            }
            GhostAction::Promote { ghost_id, receipt_id } => {
                println!("(stub) would POST /ghosts/{ghost_id}/promote with receipt_id={receipt_id}");
            }
            GhostAction::Expire { ghost_id, cause } => {
                println!("(stub) would POST /ghosts/{ghost_id}/expire cause={cause}");
            }
        }
    }
    Ok(())
}


#[derive(Subcommand)]
enum JsonCmd {
    /// Validate and show NRF mapping
    Validate { #[arg(long)] file: String },
}

#[derive(Subcommand)]
enum Cmd2 {
    Json(JsonCmd),
}

