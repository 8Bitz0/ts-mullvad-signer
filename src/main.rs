mod tailscale;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
struct Args {
    /// Signs without confirmation
    #[arg(short = 'y', long)]
    yes: bool,
    /// Prevents printing a list of nodes to be signed to the console
    #[arg(long)]
    no_print: bool,
    /// Signs already signed nodes
    #[arg(short = 'r', long)]
    resign: bool,
}

fn main() {
    let args = Args::parse();
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Fetching nodes...");
    
    let status = match tailscale::LockStatus::fetch_from_cli() {
        Ok(status) => status,
        Err(e) => {
            spinner.abandon_with_message("Failed to fetch nodes");
            eprintln!("Error fetching Tailscale lock status: {}", e);
            std::process::exit(1);
        }
    };
    
    spinner.finish_with_message("Fetched nodes");
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Selecting nodes...");
    
    let nodes: Vec<(String, String)> = status.select_mullvad_nodes(args.resign);
    
    spinner.finish_with_message("Nodes selected");
    
    if nodes.is_empty() {
        eprintln!("No filtered Mullvad nodes found. Make sure your device is authorized\nto access Mullvad nodes and that they aren't already signed.");
        std::process::exit(1);
    }
    
    if !args.no_print {
        println!("Nodes:");
        
        for n in &nodes {
            println!("- {}: {}", n.1, n.0);
        }
        
        println!();
    }
    
    println!("Selected {} node{}", nodes.len(), if nodes.len() == 1 { "" } else { "s" });
    println!("These nodes have been selected by checking for the node name suffix.");
    println!("By signing these nodes, you trust them to interact with your tailnet.");
    println!("The signing process may take a few minutes to complete.");
    
    if !args.yes {
        let dialog = dialoguer::Confirm::new()
            .with_prompt("Sign ALL selected nodes?")
            .default(false)
            .show_default(true)
            .interact()
            .unwrap();
        
        if !dialog {
            println!("Aborting...");
            std::process::exit(0);
        }
    }
    
    let progress_bar = ProgressBar::new(nodes.len() as u64);
    progress_bar.set_message("Signing nodes...");
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner} [{elapsed_precise}] [{bar:40}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#> "));
    
    for n in nodes {
        match tailscale::sign_node(&n.0) {
            Ok(_) => {},
            Err(e) => {
                progress_bar.abandon_with_message("Failed signing nodes");
                eprintln!("Error signing node: {} (node key: {})", e, n.0);
                std::process::exit(1);
            }
        };
        
        progress_bar.inc(1);
    }
    
    progress_bar.finish_with_message("Signed nodes");
    
    println!("All detected Mullvad nodes should now be signed.");
    println!("You may need to sign additional nodes over time as available Mullvad\nservers change (either manually or by re-running this tool.)");
}
