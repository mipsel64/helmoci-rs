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

fn unsupported_extension_name(entry_type: tar::EntryType) -> Option<&'static str> {
    match entry_type {
        tar::EntryType::GNULongName => Some("GNU long-name"),
        tar::EntryType::GNULongLink => Some("GNU long-link"),
        tar::EntryType::XHeader => Some("local PAX"),
        tar::EntryType::XGlobalHeader => Some("global PAX"),
        tar::EntryType::GNUSparse => Some("GNU sparse"),
        _ => None,
    }
}

/// Regular files only — matches upstream helmoci, which drops other entry types.
pub(crate) fn unpack_tgz_with_limits(
    tgz: &[u8],
    limits: ArchiveLimits,
) -> Result<Vec<TgzFile>, HelmError> {
    let mut archive = tar::Archive::new(GzDecoder::new(tgz));
    let mut files = Vec::new();
    let mut expanded_bytes = 0_u64;
    let mut entry_count = 0_usize;
    for entry in archive.entries().map_err(invalid)?.raw(true) {
        let mut entry = entry.map_err(invalid)?;
        let entry_type = entry.header().entry_type();

        let next_entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid("archive entry count overflow"))?;
        if next_entry_count > limits.max_files {
            return Err(invalid(format_args!(
                "archive entry count exceeds limit ({next_entry_count} > {})",
                limits.max_files
            )));
        }

        let entry_size = entry.size();
        if entry_size > limits.max_file_bytes {
            if entry_type != tar::EntryType::Regular {
                return Err(invalid(format_args!(
                    "archive entry exceeds per-entry limit ({entry_size} > {} bytes)",
                    limits.max_file_bytes
                )));
            }
            return Err(invalid(format_args!(
                "regular file exceeds per-file limit ({entry_size} > {} bytes)",
                limits.max_file_bytes
            )));
        }
        let next_expanded_bytes = expanded_bytes
            .checked_add(entry_size)
            .ok_or_else(|| invalid("expanded archive entry byte count overflow"))?;
        if next_expanded_bytes > limits.max_expanded_bytes {
            return Err(invalid(format_args!(
                "expanded archive entries exceed limit ({next_expanded_bytes} > {} bytes)",
                limits.max_expanded_bytes
            )));
        }

        if let Some(name) = unsupported_extension_name(entry_type) {
            return Err(invalid(format_args!(
                "unsupported tar extension entry: {name}"
            )));
        }

        entry_count = next_entry_count;
        expanded_bytes = next_expanded_bytes;
        if entry_type != tar::EntryType::Regular {
            continue;
        }

        let file_capacity = usize::try_from(entry_size)
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
        if actual_size != entry_size {
            return Err(invalid(format_args!(
                "regular file size differs from header ({actual_size} != {entry_size} bytes)"
            )));
        }
        files.push(TgzFile {
            name,
            data,
            mode,
            mtime,
        });
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

    fn gzip(tar_bytes: &[u8]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    fn raw_entries_tgz(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, entry_type, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(*entry_type);
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        gzip(&tar_bytes)
    }

    fn header_only_entries_tgz(entries: &[(&str, tar::EntryType, u64)]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        for (name, entry_type, declared_size) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_entry_type(*entry_type);
            header.set_size(*declared_size);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            tar_bytes.extend_from_slice(header.as_bytes());
        }
        gzip(&tar_bytes)
    }

    fn header_only_tgz(name: &str, declared_size: u64) -> Vec<u8> {
        header_only_entries_tgz(&[(name, tar::EntryType::Regular, declared_size)])
    }

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let body = format!("{key}={value}\n");
        let mut digits = 1;
        loop {
            let length = digits + 1 + body.len();
            let next_digits = length.to_string().len();
            if digits == next_digits {
                return format!("{length} {body}").into_bytes();
            }
            digits = next_digits;
        }
    }

    fn extension_limits() -> ArchiveLimits {
        ArchiveLimits {
            max_expanded_bytes: 32,
            max_file_bytes: 32,
            max_files: 4,
        }
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
            "invalid chart archive: expanded archive entries exceed limit (6 > 5 bytes)"
        );
    }

    #[test]
    fn rejects_archives_that_exceed_the_entry_count_limit() {
        let tgz = testutil::build_chart_tgz(&[("demo/a", "a"), ("demo/b", "b")]);
        let limits = ArchiveLimits {
            max_expanded_bytes: 2,
            max_file_bytes: 1,
            max_files: 1,
        };

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: archive entry count exceeds limit (2 > 1)"
        );
    }

    #[test]
    fn rejects_oversized_highly_compressible_gnu_long_name_metadata() {
        let mut metadata = vec![b'a'; 4096];
        metadata.push(0);
        let tgz = raw_entries_tgz(&[
            ("././@LongLink", tar::EntryType::GNULongName, &metadata),
            ("placeholder", tar::EntryType::Regular, b"x"),
        ]);
        assert!(tgz.len() < metadata.len() / 4);

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, extension_limits()));

        assert_eq!(
            message,
            "invalid chart archive: archive entry exceeds per-entry limit (4097 > 32 bytes)"
        );
    }

    #[test]
    fn rejects_oversized_highly_compressible_local_pax_metadata() {
        let metadata = pax_record("path", &"a".repeat(4096));
        let tgz = raw_entries_tgz(&[
            ("PaxHeader", tar::EntryType::XHeader, &metadata),
            ("placeholder", tar::EntryType::Regular, b"x"),
        ]);
        assert!(tgz.len() < metadata.len() / 4);

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, extension_limits()));

        assert_eq!(
            message,
            "invalid chart archive: archive entry exceeds per-entry limit (4107 > 32 bytes)"
        );
    }

    #[test]
    fn rejects_unsupported_extensions_from_headers_before_reading_payload() {
        let limits = ArchiveLimits {
            max_expanded_bytes: 1,
            max_file_bytes: 1,
            max_files: 1,
        };
        let cases = [
            (tar::EntryType::GNULongName, "GNU long-name"),
            (tar::EntryType::GNULongLink, "GNU long-link"),
            (tar::EntryType::XHeader, "local PAX"),
            (tar::EntryType::XGlobalHeader, "global PAX"),
            (tar::EntryType::GNUSparse, "GNU sparse"),
        ];

        for (entry_type, label) in cases {
            let tgz = header_only_entries_tgz(&[("extension", entry_type, 1)]);
            let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

            assert_eq!(
                message,
                format!("invalid chart archive: unsupported tar extension entry: {label}")
            );
        }
    }

    #[test]
    fn counts_non_regular_and_sparse_entries_before_rejecting_extensions() {
        let tgz = header_only_entries_tgz(&[
            ("directory", tar::EntryType::Directory, 0),
            ("sparse", tar::EntryType::GNUSparse, 1),
        ]);
        let limits = ArchiveLimits {
            max_expanded_bytes: 1,
            max_file_bytes: 1,
            max_files: 1,
        };

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: archive entry count exceeds limit (2 > 1)"
        );
    }

    #[test]
    fn charges_skipped_entry_payloads_to_the_cumulative_limit() {
        let tgz = raw_entries_tgz(&[
            ("directory", tar::EntryType::Directory, b"abc"),
            ("symlink", tar::EntryType::Symlink, b"def"),
        ]);
        let limits = ArchiveLimits {
            max_expanded_bytes: 5,
            max_file_bytes: 3,
            max_files: 2,
        };

        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: expanded archive entries exceed limit (6 > 5 bytes)"
        );
    }

    #[test]
    fn accepts_ustar_prefix_paths_without_extension_headers() {
        let directory = "a".repeat(120);
        let path = format!("{directory}/Chart.yaml");
        let tgz = testutil::build_chart_tgz(&[(&path, "ok")]);

        let files = unpack_tgz_with_limits(&tgz, ArchiveLimits::for_chart_bytes(1024)).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, path);
        assert_eq!(files[0].data, b"ok");
    }
}
