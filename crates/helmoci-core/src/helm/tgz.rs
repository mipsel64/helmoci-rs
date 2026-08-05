#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    /// Build a chart tgz from (path, contents) pairs — for tests only.
    pub fn build_chart_tgz(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, content) in files {
                let mut header = tar::Header::new_ustar();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, content.as_bytes())
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }
}
use super::HelmError;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_expanded_bytes: u64,
    pub max_file_bytes: u64,
    pub max_files: usize,
}

impl ArchiveLimits {
    pub const fn for_chart_bytes(max_chart_bytes: u64) -> Self {
        Self {
            max_expanded_bytes: max_chart_bytes,
            max_file_bytes: max_chart_bytes,
            max_files: 10_000,
        }
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self::for_chart_bytes(50 * 1024 * 1024)
    }
}

pub(crate) struct TgzFile {
    pub name: String,
    pub data: Vec<u8>,
    pub mode: u32,
    pub mtime: u64,
}

fn invalid(e: impl std::fmt::Display) -> HelmError {
    HelmError::InvalidChart(format!("invalid chart archive: {e}"))
}

/// Regular files only — matches upstream helmoci, which drops other entry types.
pub(crate) fn unpack_tgz_with_limits(
    tgz: &[u8],
    limits: ArchiveLimits,
) -> Result<Vec<TgzFile>, HelmError> {
    let mut archive = tar::Archive::new(GzDecoder::new(tgz));
    let mut files = Vec::new();
    let mut expanded_bytes = 0_u64;
    let mut file_count = 0_usize;
    for entry in archive.entries().map_err(invalid)? {
        let mut entry = entry.map_err(invalid)?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }

        let next_file_count = file_count
            .checked_add(1)
            .ok_or_else(|| invalid("regular file count overflow"))?;
        if next_file_count > limits.max_files {
            return Err(invalid(format_args!(
                "regular file count exceeds limit ({next_file_count} > {})",
                limits.max_files
            )));
        }

        let file_size = entry.size();
        if file_size > limits.max_file_bytes {
            return Err(invalid(format_args!(
                "regular file exceeds per-file limit ({file_size} > {} bytes)",
                limits.max_file_bytes
            )));
        }
        let next_expanded_bytes = expanded_bytes
            .checked_add(file_size)
            .ok_or_else(|| invalid("expanded regular file byte count overflow"))?;
        if next_expanded_bytes > limits.max_expanded_bytes {
            return Err(invalid(format_args!(
                "expanded regular files exceed limit ({next_expanded_bytes} > {} bytes)",
                limits.max_expanded_bytes
            )));
        }
        let file_capacity = usize::try_from(file_size)
            .map_err(|_| invalid("regular file size cannot be represented on this platform"))?;

        files
            .try_reserve(1)
            .map_err(|_| invalid("regular file list could not be allocated within limits"))?;
        let name = entry
            .path()
            .map_err(invalid)?
            .to_string_lossy()
            .into_owned();
        let mode = entry.header().mode().unwrap_or(0o644);
        let mtime = entry.header().mtime().unwrap_or(0);
        let mut data = Vec::new();
        data.try_reserve_exact(file_capacity)
            .map_err(|_| invalid("regular file could not be allocated within limits"))?;
        entry.read_to_end(&mut data).map_err(invalid)?;
        let actual_size = u64::try_from(data.len())
            .map_err(|_| invalid("regular file size cannot be represented as bytes"))?;
        if actual_size != file_size {
            return Err(invalid(format_args!(
                "regular file size differs from header ({actual_size} != {file_size} bytes)"
            )));
        }
        files.push(TgzFile {
            name,
            data,
            mode,
            mtime,
        });
        file_count = next_file_count;
        expanded_bytes = next_expanded_bytes;
    }
    Ok(files)
}

pub(crate) fn pack_tgz(files: &[TgzFile]) -> Result<Vec<u8>, HelmError> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for f in files {
            let mut header = tar::Header::new_ustar();
            header.set_size(f.data.len() as u64);
            header.set_mode(f.mode);
            header.set_mtime(f.mtime);
            header.set_cksum();
            builder
                .append_data(&mut header, &f.name, f.data.as_slice())
                .map_err(invalid)?;
        }
        builder.finish().map_err(invalid)?;
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).map_err(invalid)?;
    gz.finish().map_err(invalid)
}

/// `Chart.yaml` or `<chartname>/Chart.yaml`, but never under `charts/` (those are deps).
pub(crate) fn is_root_chart_file(name: &str, basename: &str) -> bool {
    let parts: Vec<&str> = name.split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [only] => *only == basename,
        [dir, file] => *file == basename && *dir != "charts",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;

    fn header_only_tgz(name: &str, declared_size: u64) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(declared_size);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(header.as_bytes()).unwrap();
        gz.finish().unwrap()
    }

    fn invalid_chart_message(result: Result<Vec<TgzFile>, HelmError>) -> String {
        match result {
            Err(HelmError::InvalidChart(message)) => message,
            Err(other) => panic!("expected InvalidChart, got {other:?}"),
            Ok(_) => panic!("expected archive limit error"),
        }
    }

    #[test]
    fn rejects_oversized_file_from_header_before_reading_payload() {
        let tgz = header_only_tgz("demo/values.yaml", 5);
        let limits = ArchiveLimits {
            max_expanded_bytes: 10,
            max_file_bytes: 4,
            max_files: 1,
        };

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: regular file exceeds per-file limit (5 > 4 bytes)"
        );
    }

    #[test]
    fn rejects_files_that_exceed_the_cumulative_expanded_byte_limit() {
        let tgz = testutil::build_chart_tgz(&[("demo/a", "abc"), ("demo/b", "def")]);
        let limits = ArchiveLimits {
            max_expanded_bytes: 5,
            max_file_bytes: 3,
            max_files: 2,
        };

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: expanded regular files exceed limit (6 > 5 bytes)"
        );
    }

    #[test]
    fn rejects_archives_that_exceed_the_regular_file_count_limit() {
        let tgz = testutil::build_chart_tgz(&[("demo/a", "a"), ("demo/b", "b")]);
        let limits = ArchiveLimits {
            max_expanded_bytes: 2,
            max_file_bytes: 1,
            max_files: 1,
        };

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: regular file count exceeds limit (2 > 1)"
        );
    }
}
