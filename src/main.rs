use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use darkroom_verify::{CheckOutcome, CheckSubject, verify_package};

/// Verifies record content and exported original hashes in an export package.
#[derive(Parser)]
struct Cli {
    /// Path to the export package folder
    export_folder: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let report = match verify_package(&cli.export_folder) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    println!("manifest sha256 {}", report.manifest_hashes.sha256);
    println!("manifest blake3 {}", report.manifest_hashes.blake3);
    println!();

    for check in &report.checks {
        let subject = match &check.subject {
            CheckSubject::RecordContent { record_id } => format!("record   {record_id}"),
            CheckSubject::RecordSeal { record_id } => format!("seal     {record_id}"),
            CheckSubject::Original { blob_id } => format!("original {blob_id}"),
        };
        match &check.outcome {
            CheckOutcome::Verified => println!("{subject}  verified"),
            CheckOutcome::Missing => println!("{subject}  missing"),
            CheckOutcome::Unreadable => println!("{subject}  unreadable"),
            CheckOutcome::Mismatch {
                algorithm,
                expected,
                actual,
            } => {
                println!("{subject}  {algorithm:?} mismatch");
                println!("  expected {expected}");
                println!("  actual   {actual}");
            }
        }
    }

    println!();
    if report.passed() {
        println!("Verified: {} checks passed", report.checks.len());
        ExitCode::SUCCESS
    } else {
        let failed = report
            .checks
            .iter()
            .filter(|check| !matches!(check.outcome, CheckOutcome::Verified))
            .count();

        println!(
            "Failed: {failed} of {} checks did not verify",
            report.checks.len()
        );

        ExitCode::FAILURE
    }
}
