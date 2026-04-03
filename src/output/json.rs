use crate::types::AnalysisReport;

/// Print the analysis report as pretty-printed JSON to stdout.
pub fn print_json(report: &AnalysisReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize report to JSON: {}", e),
    }
}
