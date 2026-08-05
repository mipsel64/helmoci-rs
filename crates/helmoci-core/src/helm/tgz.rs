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
pub(crate) fn unpack_tgz(tgz: &[u8]) -> Result<Vec<TgzFile>, HelmError> {
    let mut archive = tar::Archive::new(GzDecoder::new(tgz));
    let mut files = Vec::new();
    for entry in archive.entries().map_err(invalid)? {
        let mut entry = entry.map_err(invalid)?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let name = entry
            .path()
            .map_err(invalid)?
            .to_string_lossy()
            .into_owned();
        let mode = entry.header().mode().unwrap_or(0o644);
        let mtime = entry.header().mtime().unwrap_or(0);
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(invalid)?;
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
