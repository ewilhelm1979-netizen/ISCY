use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct EvidenceArtifactRef {
    stored_path: Option<String>,
}

impl EvidenceArtifactRef {
    pub fn new(stored_path: Option<String>) -> Self {
        Self { stored_path }
    }

    pub fn reference_present(&self) -> bool {
        self.stored_path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    }

    fn trimmed_path(&self) -> Option<&str> {
        self.stored_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceArtifactMetadata {
    pub backend: &'static str,
    pub artifact_reference_present: bool,
    pub artifact_present: bool,
    pub readable: bool,
    pub empty: bool,
    pub size_bytes: Option<u64>,
    pub safe_error_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceArtifactDrill {
    pub backend: &'static str,
    pub artifact_reference_present: bool,
    pub artifact_present: bool,
    pub readable: bool,
    pub empty: bool,
    pub size_bytes: Option<u64>,
    pub expected_sha256_present: bool,
    pub calculated_sha256: String,
    pub hash_matches: bool,
    pub status: String,
    pub safe_error_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceArtifactDisposition {
    pub backend: &'static str,
    pub artifact_reference_present: bool,
    pub artifact_present_before: bool,
    pub deleted: bool,
    pub safe_error_class: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceArtifactStorageError {
    MissingReference,
    MissingArtifact,
    UnsafeReference,
    NotReadable,
    StorageUnavailable,
}

impl EvidenceArtifactStorageError {
    pub fn safe_error_class(self) -> &'static str {
        match self {
            Self::MissingReference => "artifact_reference_missing",
            Self::MissingArtifact => "artifact_missing",
            Self::UnsafeReference => "artifact_reference_unsafe",
            Self::NotReadable => "artifact_not_readable",
            Self::StorageUnavailable => "artifact_storage_unavailable",
        }
    }
}

pub struct FilesystemEvidenceArtifactStorage {
    media_root: PathBuf,
}

impl FilesystemEvidenceArtifactStorage {
    pub const BACKEND: &'static str = "local_filesystem";

    pub fn new(media_root: PathBuf) -> Self {
        Self { media_root }
    }

    pub fn inspect_metadata(&self, artifact: &EvidenceArtifactRef) -> EvidenceArtifactMetadata {
        match self.safe_artifact_path(artifact) {
            Ok(path) => match fs::metadata(&path) {
                Ok(metadata) => {
                    let readable = fs::File::open(&path).is_ok();
                    EvidenceArtifactMetadata {
                        backend: Self::BACKEND,
                        artifact_reference_present: true,
                        artifact_present: true,
                        readable,
                        empty: metadata.len() == 0,
                        size_bytes: Some(metadata.len()),
                        safe_error_class: if readable {
                            String::new()
                        } else {
                            EvidenceArtifactStorageError::NotReadable
                                .safe_error_class()
                                .to_string()
                        },
                    }
                }
                Err(err) => {
                    let error = if err.kind() == std::io::ErrorKind::NotFound {
                        EvidenceArtifactStorageError::MissingArtifact
                    } else {
                        EvidenceArtifactStorageError::NotReadable
                    };
                    self.error_metadata(artifact.reference_present(), error)
                }
            },
            Err(error) => self.error_metadata(artifact.reference_present(), error),
        }
    }

    pub fn drill(
        &self,
        artifact: &EvidenceArtifactRef,
        expected_sha256: &str,
    ) -> EvidenceArtifactDrill {
        let expected = expected_sha256.trim().to_ascii_lowercase();
        let expected_present = !expected.is_empty();
        let path = match self.safe_artifact_path(artifact) {
            Ok(path) => path,
            Err(error) => {
                return self.error_drill(artifact.reference_present(), expected_present, error);
            }
        };
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => {
                let error = if err.kind() == std::io::ErrorKind::NotFound {
                    EvidenceArtifactStorageError::MissingArtifact
                } else {
                    EvidenceArtifactStorageError::NotReadable
                };
                return self.error_drill(artifact.reference_present(), expected_present, error);
            }
        };
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                return EvidenceArtifactDrill {
                    backend: Self::BACKEND,
                    artifact_reference_present: true,
                    artifact_present: true,
                    readable: false,
                    empty: metadata.len() == 0,
                    size_bytes: Some(metadata.len()),
                    expected_sha256_present: expected_present,
                    calculated_sha256: String::new(),
                    hash_matches: false,
                    status: "check_failed".to_string(),
                    safe_error_class: EvidenceArtifactStorageError::NotReadable
                        .safe_error_class()
                        .to_string(),
                };
            }
        };
        let calculated = format!("{:x}", Sha256::digest(&bytes));
        if !expected_present {
            return EvidenceArtifactDrill {
                backend: Self::BACKEND,
                artifact_reference_present: true,
                artifact_present: true,
                readable: true,
                empty: bytes.is_empty(),
                size_bytes: Some(metadata.len()),
                expected_sha256_present: false,
                calculated_sha256: calculated,
                hash_matches: false,
                status: "check_failed".to_string(),
                safe_error_class: "expected_hash_missing".to_string(),
            };
        }
        let matches = calculated == expected;
        EvidenceArtifactDrill {
            backend: Self::BACKEND,
            artifact_reference_present: true,
            artifact_present: true,
            readable: true,
            empty: bytes.is_empty(),
            size_bytes: Some(metadata.len()),
            expected_sha256_present: true,
            calculated_sha256: calculated,
            hash_matches: matches,
            status: if matches { "valid" } else { "mismatch" }.to_string(),
            safe_error_class: if matches { "" } else { "hash_mismatch" }.to_string(),
        }
    }

    pub fn delete_artifact(&self, artifact: &EvidenceArtifactRef) -> EvidenceArtifactDisposition {
        let path = match self.safe_artifact_path(artifact) {
            Ok(path) => path,
            Err(error) => {
                return EvidenceArtifactDisposition {
                    backend: Self::BACKEND,
                    artifact_reference_present: artifact.reference_present(),
                    artifact_present_before: false,
                    deleted: false,
                    safe_error_class: error.safe_error_class().to_string(),
                };
            }
        };
        match fs::remove_file(&path) {
            Ok(()) => EvidenceArtifactDisposition {
                backend: Self::BACKEND,
                artifact_reference_present: true,
                artifact_present_before: true,
                deleted: true,
                safe_error_class: String::new(),
            },
            Err(err) => {
                let error = if err.kind() == std::io::ErrorKind::NotFound {
                    EvidenceArtifactStorageError::MissingArtifact
                } else {
                    EvidenceArtifactStorageError::NotReadable
                };
                EvidenceArtifactDisposition {
                    backend: Self::BACKEND,
                    artifact_reference_present: true,
                    artifact_present_before: false,
                    deleted: false,
                    safe_error_class: error.safe_error_class().to_string(),
                }
            }
        }
    }

    fn safe_artifact_path(
        &self,
        artifact: &EvidenceArtifactRef,
    ) -> Result<PathBuf, EvidenceArtifactStorageError> {
        let Some(stored_path) = artifact.trimmed_path() else {
            return Err(EvidenceArtifactStorageError::MissingReference);
        };
        let relative = Path::new(stored_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err(EvidenceArtifactStorageError::UnsafeReference);
        }
        let canonical_root = self.media_root.canonicalize().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                EvidenceArtifactStorageError::MissingArtifact
            } else {
                EvidenceArtifactStorageError::StorageUnavailable
            }
        })?;
        let relative = strip_repeated_root_prefix(&self.media_root, relative);
        let candidate = canonical_root.join(relative);
        let canonical_candidate = candidate.canonicalize().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                EvidenceArtifactStorageError::MissingArtifact
            } else {
                EvidenceArtifactStorageError::NotReadable
            }
        })?;
        if !canonical_candidate.starts_with(&canonical_root) || !canonical_candidate.is_file() {
            return Err(EvidenceArtifactStorageError::UnsafeReference);
        }
        Ok(canonical_candidate)
    }

    fn error_metadata(
        &self,
        reference_present: bool,
        error: EvidenceArtifactStorageError,
    ) -> EvidenceArtifactMetadata {
        EvidenceArtifactMetadata {
            backend: Self::BACKEND,
            artifact_reference_present: reference_present,
            artifact_present: false,
            readable: false,
            empty: false,
            size_bytes: None,
            safe_error_class: error.safe_error_class().to_string(),
        }
    }

    fn error_drill(
        &self,
        reference_present: bool,
        expected_present: bool,
        error: EvidenceArtifactStorageError,
    ) -> EvidenceArtifactDrill {
        let status = match error {
            EvidenceArtifactStorageError::MissingReference
            | EvidenceArtifactStorageError::MissingArtifact
            | EvidenceArtifactStorageError::UnsafeReference => "missing_artifact",
            EvidenceArtifactStorageError::NotReadable
            | EvidenceArtifactStorageError::StorageUnavailable => "check_failed",
        };
        EvidenceArtifactDrill {
            backend: Self::BACKEND,
            artifact_reference_present: reference_present,
            artifact_present: false,
            readable: false,
            empty: false,
            size_bytes: None,
            expected_sha256_present: expected_present,
            calculated_sha256: String::new(),
            hash_matches: false,
            status: status.to_string(),
            safe_error_class: error.safe_error_class().to_string(),
        }
    }
}

fn strip_repeated_root_prefix<'a>(media_root: &Path, relative: &'a Path) -> &'a Path {
    let Some(root_name) = media_root.file_name() else {
        return relative;
    };
    relative.strip_prefix(root_name).unwrap_or(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_media_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("iscy-storage-{name}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn filesystem_storage_blocks_traversal_and_hashes_empty_files() {
        let root = temp_media_root("safe-path");
        fs::write(root.join("empty.txt"), b"").unwrap();
        let storage = FilesystemEvidenceArtifactStorage::new(root.clone());
        let empty = storage.drill(
            &EvidenceArtifactRef::new(Some("empty.txt".to_string())),
            &format!("{:x}", Sha256::digest(b"")),
        );
        assert_eq!(empty.status, "valid");
        assert!(empty.empty);
        assert_eq!(empty.size_bytes, Some(0));

        let traversal = storage.inspect_metadata(&EvidenceArtifactRef::new(Some(
            "../outside.txt".to_string(),
        )));
        assert_eq!(traversal.safe_error_class, "artifact_reference_unsafe");
        assert!(!traversal.artifact_present);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn filesystem_storage_deletes_only_safe_local_artifacts() {
        let root = temp_media_root("delete");
        fs::write(root.join("delete-me.txt"), b"delete me").unwrap();
        let storage = FilesystemEvidenceArtifactStorage::new(root.clone());

        let deleted =
            storage.delete_artifact(&EvidenceArtifactRef::new(Some("delete-me.txt".to_string())));
        assert!(deleted.deleted);
        assert!(deleted.artifact_present_before);
        assert_eq!(deleted.safe_error_class, "");
        assert!(!root.join("delete-me.txt").exists());

        let traversal = storage.delete_artifact(&EvidenceArtifactRef::new(Some(
            "../outside.txt".to_string(),
        )));
        assert!(!traversal.deleted);
        assert_eq!(traversal.safe_error_class, "artifact_reference_unsafe");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_storage_blocks_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = temp_media_root("symlink");
        let outside = temp_media_root("outside");
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        symlink(outside.join("secret.txt"), root.join("link.txt")).unwrap();
        let storage = FilesystemEvidenceArtifactStorage::new(root.clone());
        let metadata =
            storage.inspect_metadata(&EvidenceArtifactRef::new(Some("link.txt".to_string())));
        assert_eq!(metadata.safe_error_class, "artifact_reference_unsafe");
        assert!(!metadata.artifact_present);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }
}
