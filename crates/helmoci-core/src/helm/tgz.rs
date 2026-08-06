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

/// Charts compress ~10x (measured: argo-cd 7.7.0 is 176 KiB packed, 1.9 MiB
/// expanded), so the compressed-download cap cannot double as the expansion cap
/// without quietly shrinking the documented chart limit by the compression ratio.
pub const DEFAULT_EXPANSION_MULTIPLIER: u64 = 10;
pub const DEFAULT_MAX_FILES: usize = 10_000;

impl ArchiveLimits {
    pub const fn new(max_expanded_bytes: u64, max_file_bytes: u64, max_files: usize) -> Self {
        Self {
            max_expanded_bytes,
            max_file_bytes,
            max_files,
        }
    }

    /// Expansion budget, i.e. the configured `max_expanded_chart_bytes`.
    pub const fn for_expanded_bytes(max_expanded_bytes: u64) -> Self {
        Self::new(max_expanded_bytes, max_expanded_bytes, DEFAULT_MAX_FILES)
    }

    /// Derive the expansion budget from the compressed-download cap.
    pub const fn for_chart_bytes(max_chart_bytes: u64) -> Self {
        Self::for_expanded_bytes(max_chart_bytes.saturating_mul(DEFAULT_EXPANSION_MULTIPLIER))
    }

    /// Configured expansion budget, floored at the compressed cap so a
    /// misconfigured `max_expanded_chart_bytes` cannot reject a downloadable chart
    /// outright.
    pub const fn for_chart_bytes_with_expansion(
        max_chart_bytes: u64,
        max_expanded_bytes: u64,
    ) -> Self {
        Self::for_expanded_bytes(if max_expanded_bytes < max_chart_bytes {
            max_chart_bytes
        } else {
            max_expanded_bytes
        })
    }
}

/// Test-only: production callers pass limits derived from config, and gating this
/// out of normal builds keeps a hardcoded policy from silently replacing them.
#[cfg(test)]
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

/// A configured bound was busted, which is an oversized artifact rather than a
/// malformed one. The rendered text is identical to [`invalid`] so only the variant,
/// and with it the HTTP status, distinguishes the two.
fn too_large(e: impl std::fmt::Display) -> HelmError {
    HelmError::ChartTooLarge(format!("invalid chart archive: {e}"))
}

/// PAX (`x`, `g`) and GNU (`L`, `K`) entries carry metadata for the member that
/// follows them rather than file contents of their own.
#[derive(Default)]
struct PendingMetadata {
    long_name: Option<Vec<u8>>,
    pax_seen: bool,
    pax_path: Option<Vec<u8>>,
    pax_size: Option<u64>,
}

impl PendingMetadata {
    fn is_empty(&self) -> bool {
        self.long_name.is_none() && !self.pax_seen
    }

    /// PAX records win over a GNU long name, matching Go's `archive/tar`.
    fn path_override(&self) -> Option<&[u8]> {
        self.pax_path.as_deref().or(self.long_name.as_deref())
    }
}

fn is_metadata_entry(entry_type: tar::EntryType) -> bool {
    matches!(
        entry_type,
        tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
            | tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader
    )
}

fn trim_trailing_nuls(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &bytes[..end]
}

/// Read exactly `declared_size` bytes, allocating no more than that up front.
fn read_entry_payload(
    reader: &mut impl Read,
    declared_size: u64,
    what: &str,
) -> Result<Vec<u8>, HelmError> {
    let capacity = usize::try_from(declared_size).map_err(|_| {
        invalid(format_args!(
            "{what} size cannot be represented on this platform"
        ))
    })?;
    let mut data = Vec::new();
    data.try_reserve_exact(capacity)
        .map_err(|_| invalid(format_args!("{what} could not be allocated within limits")))?;
    reader.read_to_end(&mut data).map_err(invalid)?;
    let actual_size = u64::try_from(data.len())
        .map_err(|_| invalid(format_args!("{what} size cannot be represented as bytes")))?;
    if actual_size != declared_size {
        return Err(invalid(format_args!(
            "{what} size differs from header ({actual_size} != {declared_size} bytes)"
        )));
    }
    Ok(data)
}

/// PAX records are `"<len> <key>=<value>\n"`, where `<len>` counts the whole record.
fn apply_pax_records(payload: &[u8], pending: &mut PendingMetadata) -> Result<(), HelmError> {
    let mut rest = payload;
    while !rest.is_empty() {
        // Some writers pad the record area out to the block size.
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| invalid("malformed PAX record: no length separator"))?;
        let length = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|digits| digits.parse::<usize>().ok())
            .filter(|length| *length > space + 1 && *length <= rest.len())
            .ok_or_else(|| invalid("malformed PAX record: invalid length"))?;
        let record = rest[space + 1..length]
            .strip_suffix(b"\n")
            .ok_or_else(|| invalid("malformed PAX record: no terminator"))?;
        let equals = record
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| invalid("malformed PAX record: no key separator"))?;
        let (key, value) = (&record[..equals], &record[equals + 1..]);
        // Sparse members store a block map instead of contents, so their payload
        // cannot be re-served as file bytes; nothing `helm package` emits is sparse.
        if key.starts_with(b"GNU.sparse.") {
            return Err(invalid("unsupported tar extension entry: PAX sparse"));
        }
        match key {
            b"path" if !value.is_empty() => pending.pax_path = Some(value.to_vec()),
            // A `size` record overrides the header field; honouring it keeps the
            // bounds and the read length in step with the header, so an archive
            // cannot look different to two parsers.
            b"size" => {
                pending.pax_size = Some(
                    std::str::from_utf8(value)
                        .ok()
                        .and_then(|digits| digits.parse::<u64>().ok())
                        .ok_or_else(|| invalid("malformed PAX record: invalid size"))?,
                );
            }
            _ => {}
        }
        rest = &rest[length..];
    }
    Ok(())
}

/// Unpack the regular files of a chart tgz, bounded by `limits`.
///
/// PAX and GNU long-name metadata is resolved onto the member it describes:
/// `helm package` emits a PAX header for any non-ASCII or over-long path, and GNU
/// `tar czf` emits an `L` entry for any path over 100 bytes, so rejecting those
/// entries would reject charts Helm itself produces. Upstream helmoci ignores the
/// metadata and keeps the truncated ustar name; resolving it matches Go's
/// `archive/tar` instead. Every other entry type is dropped, as upstream does.
pub(crate) fn unpack_tgz_with_limits(
    tgz: &[u8],
    limits: ArchiveLimits,
) -> Result<Vec<TgzFile>, HelmError> {
    let mut archive = tar::Archive::new(GzDecoder::new(tgz));
    let mut files = Vec::new();
    let mut expanded_bytes = 0_u64;
    let mut entry_count = 0_usize;
    let mut pending = PendingMetadata::default();
    for entry in archive.entries().map_err(invalid)?.raw(true) {
        let mut entry = entry.map_err(invalid)?;
        let entry_type = entry.header().entry_type();
        let is_metadata = is_metadata_entry(entry_type);

        let next_entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid("archive entry count overflow"))?;
        if next_entry_count > limits.max_files {
            return Err(too_large(format_args!(
                "archive entry count exceeds limit ({next_entry_count} > {})",
                limits.max_files
            )));
        }

        let entry_size = if is_metadata {
            entry.size()
        } else {
            pending.pax_size.unwrap_or_else(|| entry.size())
        };
        if entry_size > limits.max_file_bytes {
            if entry_type != tar::EntryType::Regular {
                return Err(too_large(format_args!(
                    "archive entry exceeds per-entry limit ({entry_size} > {} bytes)",
                    limits.max_file_bytes
                )));
            }
            return Err(too_large(format_args!(
                "regular file exceeds per-file limit ({entry_size} > {} bytes)",
                limits.max_file_bytes
            )));
        }
        let next_expanded_bytes = expanded_bytes
            .checked_add(entry_size)
            .ok_or_else(|| invalid("expanded archive entry byte count overflow"))?;
        if next_expanded_bytes > limits.max_expanded_bytes {
            return Err(too_large(format_args!(
                "expanded archive entries exceed limit ({next_expanded_bytes} > {} bytes)",
                limits.max_expanded_bytes
            )));
        }

        entry_count = next_entry_count;
        expanded_bytes = next_expanded_bytes;

        // GNU sparse members describe a block map, so their payload is not the file
        // content and cannot be re-served faithfully.
        if entry_type == tar::EntryType::GNUSparse {
            return Err(invalid("unsupported tar extension entry: GNU sparse"));
        }

        if is_metadata {
            let payload = read_entry_payload(&mut entry, entry_size, "tar extension entry")?;
            match entry_type {
                tar::EntryType::GNULongName => {
                    if pending.long_name.is_some() {
                        return Err(invalid("duplicate GNU long-name entry"));
                    }
                    pending.long_name = Some(payload);
                }
                tar::EntryType::XHeader => {
                    if pending.pax_seen {
                        return Err(invalid("duplicate local PAX entry"));
                    }
                    pending.pax_seen = true;
                    apply_pax_records(&payload, &mut pending)?;
                }
                // Long link targets are never used, and global PAX records carry
                // archive-wide defaults only: both are read (so the payload stays
                // charged against the limits) and dropped.
                _ => {}
            }
            continue;
        }

        let metadata = std::mem::take(&mut pending);
        if entry_type != tar::EntryType::Regular {
            continue;
        }

        files
            .try_reserve(1)
            .map_err(|_| invalid("regular file list could not be allocated within limits"))?;
        let name = match metadata.path_override() {
            Some(path) => String::from_utf8_lossy(trim_trailing_nuls(path)).into_owned(),
            None => entry
                .path()
                .map_err(invalid)?
                .to_string_lossy()
                .into_owned(),
        };
        let mode = entry.header().mode().unwrap_or(0o644);
        let mtime = entry.header().mtime().unwrap_or(0);
        let data = read_entry_payload(&mut entry, entry_size, "regular file")?;
        files.push(TgzFile {
            name,
            data,
            mode,
            mtime,
        });
    }
    if !pending.is_empty() {
        return Err(invalid("tar extension entry has no member to describe"));
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

    /// Append one real tar entry: header, payload, block padding.
    fn push_entry(out: &mut Vec<u8>, name: &str, entry_type: tar::EntryType, payload: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_entry_type(entry_type);
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(payload);
        let remainder = payload.len() % 512;
        if remainder != 0 {
            out.extend(std::iter::repeat_n(0_u8, 512 - remainder));
        }
    }

    /// A PAX `x` header followed by the member it describes, the shape `helm
    /// package` and bsdtar produce (the member header carries a truncated name).
    fn pax_metadata_tgz(records: &[u8], member_name: &str, content: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        push_entry(
            &mut tar_bytes,
            "PaxHeaders.0/demo",
            tar::EntryType::XHeader,
            records,
        );
        push_entry(
            &mut tar_bytes,
            member_name,
            tar::EntryType::Regular,
            content,
        );
        tar_bytes.extend(std::iter::repeat_n(0_u8, 1024));
        gzip(&tar_bytes)
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
            Ok(_) => panic!("expected a malformed archive error"),
        }
    }

    /// A configured bound was busted: the variant, not the wording, is what carries
    /// the 413 to the server.
    fn too_large_message(result: Result<Vec<TgzFile>, HelmError>) -> String {
        match result {
            Err(HelmError::ChartTooLarge(message)) => message,
            Err(other) => panic!("expected ChartTooLarge, got {other:?}"),
            Ok(_) => panic!("expected an archive limit error"),
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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, limits));

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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, limits));

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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, limits));

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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, extension_limits()));

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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, extension_limits()));

        assert_eq!(
            message,
            "invalid chart archive: archive entry exceeds per-entry limit (4107 > 32 bytes)"
        );
    }

    #[test]
    fn rejects_sparse_entries_from_headers_before_reading_payload() {
        let limits = ArchiveLimits {
            max_expanded_bytes: 1,
            max_file_bytes: 1,
            max_files: 1,
        };

        let tgz = header_only_entries_tgz(&[("sparse", tar::EntryType::GNUSparse, 1)]);
        let message = invalid_chart_message(unpack_tgz_with_limits(&tgz, limits));

        assert_eq!(
            message,
            "invalid chart archive: unsupported tar extension entry: GNU sparse"
        );
    }

    #[test]
    fn rejects_pax_sparse_records() {
        let records = pax_record("GNU.sparse.major", "1");
        let tgz = pax_metadata_tgz(&records, "demo/values.yaml", b"a: 1\n");

        let message = invalid_chart_message(unpack_tgz_with_limits(
            &tgz,
            ArchiveLimits::for_chart_bytes(4096),
        ));

        assert_eq!(
            message,
            "invalid chart archive: unsupported tar extension entry: PAX sparse"
        );
    }

    #[test]
    fn rejects_metadata_entries_with_no_member_to_describe() {
        let mut tar_bytes = Vec::new();
        push_entry(
            &mut tar_bytes,
            "././@LongLink",
            tar::EntryType::GNULongName,
            b"demo/orphan.yaml\0",
        );
        tar_bytes.extend(std::iter::repeat_n(0_u8, 1024));

        let message = invalid_chart_message(unpack_tgz_with_limits(
            &gzip(&tar_bytes),
            ArchiveLimits::for_chart_bytes(4096),
        ));

        assert_eq!(
            message,
            "invalid chart archive: tar extension entry has no member to describe"
        );
    }

    #[test]
    fn rejects_duplicate_metadata_entries_for_one_member() {
        let mut tar_bytes = Vec::new();
        for _ in 0..2 {
            push_entry(
                &mut tar_bytes,
                "PaxHeaders.0/demo",
                tar::EntryType::XHeader,
                &pax_record("path", "demo/values.yaml"),
            );
        }
        push_entry(
            &mut tar_bytes,
            "demo/truncated.yaml",
            tar::EntryType::Regular,
            b"a: 1\n",
        );
        tar_bytes.extend(std::iter::repeat_n(0_u8, 1024));

        let message = invalid_chart_message(unpack_tgz_with_limits(
            &gzip(&tar_bytes),
            ArchiveLimits::for_chart_bytes(4096),
        ));

        assert_eq!(message, "invalid chart archive: duplicate local PAX entry");
    }

    /// `helm package` forces a PAX header for any non-ASCII or over-long path.
    #[test]
    fn resolves_pax_long_and_non_ascii_paths() {
        for path in [
            format!("demo/templates/{}/café.yaml", "n".repeat(120)),
            "demo/templates/café.yaml".to_string(),
        ] {
            let tgz = pax_metadata_tgz(
                &pax_record("path", &path),
                "demo/templates/truncated.yaml",
                b"kind: ConfigMap\n",
            );

            let files = unpack_tgz_with_limits(&tgz, ArchiveLimits::for_chart_bytes(4096)).unwrap();

            assert_eq!(files.len(), 1);
            assert_eq!(files[0].name, path);
            assert_eq!(files[0].data, b"kind: ConfigMap\n");
        }
    }

    /// `tar czf` (GNU format) emits an `L` entry for any path over 100 bytes.
    #[test]
    fn resolves_gnu_long_name_paths() {
        let path = format!("demo/templates/{}.yaml", "n".repeat(120));
        let mut long_name = path.clone().into_bytes();
        long_name.push(0);
        let mut tar_bytes = Vec::new();
        push_entry(
            &mut tar_bytes,
            "././@LongLink",
            tar::EntryType::GNULongName,
            &long_name,
        );
        push_entry(
            &mut tar_bytes,
            "demo/templates/nnnn.yaml",
            tar::EntryType::Regular,
            b"kind: Secret\n",
        );
        tar_bytes.extend(std::iter::repeat_n(0_u8, 1024));

        let files = unpack_tgz_with_limits(&gzip(&tar_bytes), ArchiveLimits::for_chart_bytes(4096))
            .unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, path);
        assert_eq!(files[0].data, b"kind: Secret\n");
    }

    /// bsdtar writes global PAX records, and long link targets ride on `K` entries.
    #[test]
    fn tolerates_global_pax_and_long_link_metadata() {
        let mut tar_bytes = Vec::new();
        push_entry(
            &mut tar_bytes,
            "PaxHeaders.0/global",
            tar::EntryType::XGlobalHeader,
            &pax_record("comment", "written by bsdtar"),
        );
        let mut long_link = vec![b'l'; 120];
        long_link.push(0);
        push_entry(
            &mut tar_bytes,
            "././@LongLink",
            tar::EntryType::GNULongLink,
            &long_link,
        );
        push_entry(&mut tar_bytes, "demo/link", tar::EntryType::Symlink, b"");
        push_entry(
            &mut tar_bytes,
            "demo/Chart.yaml",
            tar::EntryType::Regular,
            b"name: demo\n",
        );
        tar_bytes.extend(std::iter::repeat_n(0_u8, 1024));

        let files = unpack_tgz_with_limits(&gzip(&tar_bytes), ArchiveLimits::for_chart_bytes(4096))
            .unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "demo/Chart.yaml");
        assert_eq!(files[0].data, b"name: demo\n");
    }

    #[test]
    fn round_trips_long_names_through_pack_and_unpack() {
        let name = format!("demo/{}.yaml", "n".repeat(120));
        let packed = pack_tgz(&[TgzFile {
            name: name.clone(),
            data: b"kind: ConfigMap\n".to_vec(),
            mode: 0o644,
            mtime: 0,
        }])
        .unwrap();

        let mut raw = Vec::new();
        GzDecoder::new(packed.as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        assert!(
            raw.windows(9).any(|w| w == b"@LongLink"),
            "expected pack_tgz to emit a GNU long-name entry"
        );

        let files = unpack_tgz_with_limits(&packed, ArchiveLimits::for_chart_bytes(4096)).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, name);
        assert_eq!(files[0].data, b"kind: ConfigMap\n");
    }

    #[test]
    fn honours_pax_size_records_that_disagree_with_the_header() {
        let tgz = pax_metadata_tgz(&pax_record("size", "4096"), "demo/values.yaml", b"a: 1\n");

        let message = too_large_message(unpack_tgz_with_limits(
            &tgz,
            ArchiveLimits::new(4096, 64, 8),
        ));

        assert_eq!(
            message,
            "invalid chart archive: regular file exceeds per-file limit (4096 > 64 bytes)"
        );
    }

    #[test]
    fn expansion_budget_is_larger_than_the_compressed_download_cap() {
        let limits = ArchiveLimits::for_chart_bytes(1024);
        assert_eq!(limits.max_expanded_bytes, 10 * 1024);
        assert_eq!(limits.max_file_bytes, 10 * 1024);
        assert_eq!(limits.max_files, DEFAULT_MAX_FILES);

        // A chart that expands past the compressed cap but stays inside the
        // expansion budget is served, not rejected.
        let body = "y".repeat(2048);
        let tgz = testutil::build_chart_tgz(&[("demo/values.yaml", &body)]);
        assert!(tgz.len() < 1024);

        let files = unpack_tgz_with_limits(&tgz, limits).unwrap();
        assert_eq!(files[0].data.len(), 2048);

        // An explicit expansion budget wins, but never drops below the download cap.
        assert_eq!(
            ArchiveLimits::for_chart_bytes_with_expansion(1024, 4096).max_expanded_bytes,
            4096
        );
        assert_eq!(
            ArchiveLimits::for_chart_bytes_with_expansion(1024, 16).max_expanded_bytes,
            1024
        );
        assert_eq!(
            ArchiveLimits::for_chart_bytes(u64::MAX).max_expanded_bytes,
            u64::MAX
        );
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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, limits));

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

        let message = too_large_message(unpack_tgz_with_limits(&tgz, limits));

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
