use super::HelmError;
use super::tgz::{ArchiveLimits, is_root_chart_file, unpack_tgz_with_limits};

/// Test-only: production callers must pass limits derived from config.
#[cfg(test)]
pub fn chart_config_from_tgz(tgz: &[u8]) -> Result<Vec<u8>, HelmError> {
    chart_config_from_tgz_with_limits(tgz, ArchiveLimits::default())
}

/// Root Chart.yaml re-encoded as JSON — the OCI config blob for a Helm chart.
pub fn chart_config_from_tgz_with_limits(
    tgz: &[u8],
    limits: ArchiveLimits,
) -> Result<Vec<u8>, HelmError> {
    let files = unpack_tgz_with_limits(tgz, limits)?;
    let chart = files
        .iter()
        .find(|f| is_root_chart_file(&f.name, "Chart.yaml"))
        .ok_or_else(|| HelmError::InvalidChart("Chart.yaml not found in chart archive".into()))?;
    let text = String::from_utf8_lossy(&chart.data);
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
        .map_err(|e| HelmError::InvalidChart(format!("Chart.yaml is not valid YAML: {e}")))?;
    if !value.is_mapping() {
        return Err(HelmError::InvalidChart(
            "Chart.yaml did not parse to an object".into(),
        ));
    }
    serde_json::to_vec(&value).map_err(|e| {
        HelmError::InvalidChart(format!("Chart.yaml could not be encoded as JSON: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helm::tgz::testutil::build_chart_tgz;

    #[test]
    fn extracts_root_chart_yaml_as_json() {
        let tgz = build_chart_tgz(&[
            ("demo/Chart.yaml", "name: demo\nversion: 1.0.0\n"),
            ("demo/values.yaml", "replicas: 1\n"),
            ("demo/charts/dep/Chart.yaml", "name: dep\nversion: 0.1.0\n"),
        ]);
        let config = chart_config_from_tgz(&tgz).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&config).unwrap();
        assert_eq!(value["name"], "demo");
        assert_eq!(value["version"], "1.0.0");
    }

    #[test]
    fn accepts_top_level_chart_yaml() {
        let tgz = build_chart_tgz(&[("Chart.yaml", "name: flat\nversion: 2.0.0\n")]);
        let config = chart_config_from_tgz(&tgz).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&config).unwrap();
        assert_eq!(value["name"], "flat");
    }

    #[test]
    fn missing_chart_yaml_is_an_error() {
        let tgz = build_chart_tgz(&[("demo/values.yaml", "a: 1\n")]);
        assert!(matches!(
            chart_config_from_tgz(&tgz).unwrap_err(),
            HelmError::InvalidChart(_)
        ));
    }

    #[test]
    fn bounded_chart_config_rejects_oversized_archive_entry() {
        let tgz = build_chart_tgz(&[("demo/Chart.yaml", "12345")]);
        let limits = crate::helm::tgz::ArchiveLimits::new(64, 4, 8);

        let error = chart_config_from_tgz_with_limits(&tgz, limits).unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid chart archive: regular file exceeds per-file limit (5 > 4 bytes)"
        );
    }
}
