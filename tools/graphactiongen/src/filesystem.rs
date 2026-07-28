use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Error, Result};

pub const DEFAULT_CATALOG_PATH: &str = "internal/graphactions/action_catalog.yaml";
pub const DEFAULT_OUTPUT_PATH: &str = "internal/graphactions/registry_gen.go";
pub const DEFAULT_RUST_OUTPUT_PATH: &str = "crates/action-catalog/src/generated.rs";
pub const MAX_GENERATED_FILE_BYTES: usize = 4 << 20;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub(crate) fn read_bounded_file(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|source| Error::Io {
        operation: "read catalog",
        path: path.to_path_buf(),
        source,
    })?;
    read_limited(file, "file", path)
}

pub fn read_generated_file(path: &Path) -> Result<Vec<u8>> {
    reject_symlink(path)?;
    let file = open_no_follow(path)?;
    read_limited(file, "generated graph action file", path)
}

pub(crate) fn read_limited(file: File, label: &'static str, path: &Path) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    file.take((MAX_GENERATED_FILE_BYTES + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|source| Error::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
        })?;
    if content.len() > MAX_GENERATED_FILE_BYTES {
        return Err(Error::FileTooLarge {
            label,
            limit: MAX_GENERATED_FILE_BYTES,
        });
    }
    Ok(content)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| {
            if source.raw_os_error() == Some(libc::ELOOP) {
                Error::SymlinkNotAllowed
            } else {
                Error::Io {
                    operation: "read generated graph action file",
                    path: path.to_path_buf(),
                    source,
                }
            }
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File> {
    File::open(path).map_err(|source| Error::Io {
        operation: "read generated graph action file",
        path: path.to_path_buf(),
        source,
    })
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::SymlinkNotAllowed),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Io {
            operation: "inspect generated graph action file",
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn write_generated_file(path: &Path, content: &[u8]) -> Result<()> {
    ensure_supported_platform()?;
    reject_symlink(path)?;
    let directory = path
        .parent()
        .ok_or_else(|| Error::MissingParent(path.to_path_buf()))?;
    fs::create_dir_all(directory).map_err(|source| Error::Io {
        operation: "create generated file directory",
        path: directory.to_path_buf(),
        source,
    })?;
    let temp_path = temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let result = (|| {
        let mut file = options.open(&temp_path).map_err(|source| Error::Io {
            operation: "create generated temporary file",
            path: temp_path.clone(),
            source,
        })?;
        file.write_all(content).map_err(|source| Error::Io {
            operation: "write generated temporary file",
            path: temp_path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| Error::Io {
            operation: "sync generated temporary file",
            path: temp_path.clone(),
            source,
        })?;
        fs::set_permissions(&temp_path, permissions_0644()?).map_err(|source| Error::Io {
            operation: "set generated file permissions",
            path: temp_path.clone(),
            source,
        })?;
        fs::rename(&temp_path, path).map_err(|source| Error::Io {
            operation: "replace generated graph action file",
            path: path.to_path_buf(),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("generated");
    path.with_file_name(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ))
}

pub fn ensure_supported_platform() -> Result<()> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

fn permissions_0644() -> Result<fs::Permissions> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::Permissions::from_mode(0o644))
    }
    #[cfg(not(unix))]
    {
        Err(Error::UnsupportedPlatform)
    }
}
