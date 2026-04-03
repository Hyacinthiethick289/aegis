use crate::types::{AnalysisReport, Finding, RiskLabel, Severity};

/// Calculate a risk score from a list of findings and map it to a label.
///
/// Scoring weights:
///   Critical = 3.0, High = 1.5, Medium = 0.5, Low = 0.1
///
/// The total is capped at 10.0.
///
/// Labels:
///   0-1 = Clean, 1-3 = Low, 3-5 = Medium, 5-7 = High, 7+ = Critical
pub fn calculate_risk(findings: &[Finding]) -> (f64, RiskLabel) {
    let raw: f64 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 3.0,
            Severity::High => 1.5,
            Severity::Medium => 0.5,
            Severity::Low => 0.1,
            Severity::Info => 0.0,
        })
        .sum();

    let score = raw.min(10.0);

    let label = if score < 1.0 {
        RiskLabel::Clean
    } else if score < 3.0 {
        RiskLabel::Low
    } else if score < 5.0 {
        RiskLabel::Medium
    } else if score < 7.0 {
        RiskLabel::High
    } else {
        RiskLabel::Critical
    };

    (score, label)
}

/// Build a complete `AnalysisReport` from package info and findings.
pub fn build_report(name: &str, version: &str, findings: Vec<Finding>) -> AnalysisReport {
    let (risk_score, risk_label) = calculate_risk(&findings);

    AnalysisReport {
        package_name: name.to_string(),
        version: version.to_string(),
        findings,
        risk_score,
        risk_label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FindingCategory;

    fn make_finding(severity: Severity) -> Finding {
        Finding {
            severity,
            category: FindingCategory::Suspicious,
            title: "test".to_string(),
            description: "test finding".to_string(),
            file: None,
            line: None,
            snippet: None,
        }
    }

    #[test]
    fn empty_findings_are_clean() {
        let (score, label) = calculate_risk(&[]);
        assert_eq!(score, 0.0);
        assert!(matches!(label, RiskLabel::Clean));
    }

    #[test]
    fn single_critical_scores_three() {
        let (score, label) = calculate_risk(&[make_finding(Severity::Critical)]);
        assert!((score - 3.0).abs() < f64::EPSILON);
        assert!(matches!(label, RiskLabel::Medium));
    }

    #[test]
    fn score_is_capped_at_ten() {
        let findings: Vec<Finding> = (0..10).map(|_| make_finding(Severity::Critical)).collect();
        let (score, _label) = calculate_risk(&findings);
        assert!((score - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn label_boundaries() {
        // Low boundary: score = 1.5
        let (_, label) = calculate_risk(&[make_finding(Severity::High)]);
        assert!(matches!(label, RiskLabel::Low));

        // Medium boundary: score = 3.0
        let findings = vec![make_finding(Severity::High), make_finding(Severity::High)];
        let (_, label) = calculate_risk(&findings);
        assert!(matches!(label, RiskLabel::Medium));

        // High boundary: score = 6.0
        let findings: Vec<Finding> = (0..4).map(|_| make_finding(Severity::High)).collect();
        let (_, label) = calculate_risk(&findings);
        assert!(matches!(label, RiskLabel::High));

        // Critical boundary: score = 9.0
        let findings: Vec<Finding> = (0..3).map(|_| make_finding(Severity::Critical)).collect();
        let (_, label) = calculate_risk(&findings);
        assert!(matches!(label, RiskLabel::Critical));
    }

    #[test]
    fn build_report_wires_everything() {
        let findings = vec![make_finding(Severity::Medium)];
        let report = build_report("test-pkg", "1.0.0", findings);
        assert_eq!(report.package_name, "test-pkg");
        assert_eq!(report.version, "1.0.0");
        assert_eq!(report.findings.len(), 1);
        assert!((report.risk_score - 0.5).abs() < f64::EPSILON);
        assert!(matches!(report.risk_label, RiskLabel::Clean));
    }
}
