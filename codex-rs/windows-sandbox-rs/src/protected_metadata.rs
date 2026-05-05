use crate::setup::ProtectedMetadataMode;
use crate::setup::ProtectedMetadataTarget;
use crate::winutil::to_wide;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::Metadata;
use std::io;
use std::os::windows::fs::FileTypeExt;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::thread;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_CREATION;
use windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_DIR_NAME;
use windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_FILE_NAME;
use windows_sys::Win32::Storage::FileSystem::FindCloseChangeNotification;
use windows_sys::Win32::Storage::FileSystem::FindFirstChangeNotificationW;
use windows_sys::Win32::Storage::FileSystem::FindNextChangeNotification;
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::SetEvent;
use windows_sys::Win32::System::Threading::WaitForMultipleObjects;

/// Layer: Windows enforcement layer. Existing metadata objects can be protected
/// with ACLs. Missing names are materialized as empty deny sentinels when the
/// caller needs pre-command creation denial, or monitored and removed after
/// creation when the caller explicitly requests reactive cleanup.
#[derive(Debug)]
pub(crate) struct ProtectedMetadataGuard {
    deny_paths: Vec<PathBuf>,
    monitored_paths: Vec<PathBuf>,
    sentinel_paths: Vec<PathBuf>,
    sentinel_handles: Vec<SentinelHandle>,
}

impl ProtectedMetadataGuard {
    pub(crate) fn deny_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.deny_paths.iter()
    }

    pub(crate) fn sentinel_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.sentinel_paths.iter()
    }

    pub(crate) fn arm_sentinel_cleanup(&mut self) -> Result<()> {
        if !self.sentinel_paths.is_empty() {
            self.sentinel_handles
                .push(start_sentinel_cleanup_watchdog(&self.sentinel_paths)?);
        }
        Ok(())
    }

    pub(crate) fn into_runtime(self) -> Result<ProtectedMetadataRuntime> {
        let monitor = MissingCreationMonitor::start(&self.monitored_paths)?;
        Ok(ProtectedMetadataRuntime {
            guard: self,
            monitor,
        })
    }

    pub(crate) fn cleanup_created_paths(&mut self) -> Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        for path in &self.monitored_paths {
            let Some(existing_path) = existing_metadata_path(path)? else {
                continue;
            };
            remove_metadata_path(&existing_path)
                .with_context(|| format!("failed to remove protected metadata {}", path.display()))?;
            removed.push(existing_path);
        }
        // Sentinels are Codex-owned setup artifacts. Remove them, but do not
        // report them as command-created protected metadata violations.
        for path in &self.sentinel_paths {
            let Some(existing_path) = existing_metadata_path(path)? else {
                continue;
            };
            remove_metadata_path(&existing_path)
                .with_context(|| format!("failed to remove protected metadata {}", path.display()))?;
        }
        self.sentinel_handles.clear();
        Ok(removed)
    }
}

impl Drop for ProtectedMetadataGuard {
    fn drop(&mut self) {
        self.sentinel_handles.clear();
        for path in &self.sentinel_paths {
            let _ = remove_metadata_path(path);
        }
    }
}

/// Layer: Windows enforcement runtime. Owns the prepared guard plus any active
/// OS change listeners for the lifetime of one sandboxed command, then reports
/// whether protected metadata was created during that command.
pub(crate) struct ProtectedMetadataRuntime {
    guard: ProtectedMetadataGuard,
    monitor: MissingCreationMonitor,
}

impl ProtectedMetadataRuntime {
    pub(crate) fn set_violation_handler(&self, handler: ViolationHandler) -> Result<()> {
        self.monitor.set_violation_handler(handler)
    }

    pub(crate) fn finish(mut self) -> Result<Vec<PathBuf>> {
        let monitor_result = self.monitor.finish();
        let cleanup_result = self.guard.cleanup_created_paths();
        match (monitor_result, cleanup_result) {
            (Ok(mut removed), Ok(cleaned)) => {
                removed.extend(cleaned);
                Ok(unique_paths(removed))
            }
            (Err(err), Ok(_)) | (Ok(_), Err(err)) => Err(err),
            (Err(monitor_err), Err(cleanup_err)) => Err(anyhow!(
                "protected metadata monitor failed: {monitor_err:#}; cleanup also failed: {cleanup_err:#}"
            )),
        }
    }
}

/// Layer: Windows sentinel cleanup watchdog registration. Records the cleanup
/// script path for one out-of-job watchdog that removes Codex-created sentinels
/// if the parent process exits before normal cleanup.
#[derive(Debug)]
struct SentinelHandle {
    script_path: PathBuf,
}

impl Drop for SentinelHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.script_path);
    }
}

/// Layer: Windows OS-event listener. Watches parents of missing protected
/// metadata names and removes matching filesystem objects as soon as Windows
/// reports creation, rename, or file-name changes under those parents.
struct MissingCreationMonitor {
    stop_event: HANDLE,
    listeners: Vec<thread::JoinHandle<()>>,
    monitored_paths: Vec<PathBuf>,
    removed_paths: Arc<Mutex<Vec<PathBuf>>>,
    errors: Arc<Mutex<Vec<String>>>,
    armed: Arc<AtomicBool>,
    violation_seen: Arc<AtomicBool>,
    violation_handler: Arc<Mutex<Option<ViolationHandler>>>,
}

type ViolationHandler = Box<dyn Fn() + Send + Sync + 'static>;

impl MissingCreationMonitor {
    fn start(paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() {
            return Ok(Self {
                stop_event: 0,
                listeners: Vec::new(),
                monitored_paths: Vec::new(),
                removed_paths: Arc::new(Mutex::new(Vec::new())),
                errors: Arc::new(Mutex::new(Vec::new())),
                armed: Arc::new(AtomicBool::new(false)),
                violation_seen: Arc::new(AtomicBool::new(false)),
                violation_handler: Arc::new(Mutex::new(None)),
            });
        }

        let stop_event = unsafe { CreateEventW(std::ptr::null(), TRUE, FALSE, std::ptr::null()) };
        if stop_event == 0 {
            return Err(anyhow!(
                "failed to create protected metadata monitor stop event: {}",
                io::Error::last_os_error()
            ));
        }

        let mut monitor = Self {
            stop_event,
            listeners: Vec::new(),
            monitored_paths: paths.to_vec(),
            removed_paths: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            armed: Arc::new(AtomicBool::new(false)),
            violation_seen: Arc::new(AtomicBool::new(false)),
            violation_handler: Arc::new(Mutex::new(None)),
        };

        for (parent, watched_paths) in monitored_paths_by_parent(paths) {
            match monitor.spawn_listener(parent, watched_paths) {
                Ok(listener) => monitor.listeners.push(listener),
                Err(err) => {
                    monitor.stop_listeners();
                    return Err(err);
                }
            }
        }

        Ok(monitor)
    }

    fn spawn_listener(
        &self,
        parent: PathBuf,
        watched_paths: Vec<PathBuf>,
    ) -> Result<thread::JoinHandle<()>> {
        let parent_wide = to_wide(&parent);
        let change_handle = unsafe {
            FindFirstChangeNotificationW(
                parent_wide.as_ptr(),
                FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_CREATION,
            )
        };
        if change_handle == INVALID_HANDLE_VALUE {
            return Err(anyhow!(
                "failed to monitor protected metadata parent {}: {}",
                parent.display(),
                io::Error::last_os_error()
            ));
        }

        let stop_event = self.stop_event;
        let removed_paths = Arc::clone(&self.removed_paths);
        let errors = Arc::clone(&self.errors);
        let armed = Arc::clone(&self.armed);
        let violation_seen = Arc::clone(&self.violation_seen);
        let violation_handler = Arc::clone(&self.violation_handler);
        let parent_display = parent.display().to_string();
        let parent_display_for_listener = parent_display.clone();
        thread::Builder::new()
            .name("codex-protected-metadata-monitor".to_string())
            .spawn(move || {
                enforce_monitored_paths(
                    &watched_paths,
                    &removed_paths,
                    &errors,
                    armed.load(Ordering::SeqCst),
                    &violation_seen,
                    &violation_handler,
                );
                loop {
                    let handles = [change_handle, stop_event];
                    let wait_result = unsafe {
                        WaitForMultipleObjects(
                            handles.len() as u32,
                            handles.as_ptr(),
                            FALSE,
                            INFINITE,
                        )
                    };

                    if wait_result == WAIT_OBJECT_0 {
                        enforce_monitored_paths(
                            &watched_paths,
                            &removed_paths,
                            &errors,
                            armed.load(Ordering::SeqCst),
                            &violation_seen,
                            &violation_handler,
                        );
                        if unsafe { FindNextChangeNotification(change_handle) } == 0 {
                            record_monitor_error(
                                &errors,
                                format!(
                                    "failed to resume protected metadata monitor for {}: {}",
                                    parent_display_for_listener,
                                    io::Error::last_os_error()
                                ),
                            );
                            break;
                        }
                    } else if wait_result == WAIT_OBJECT_0 + 1 {
                        break;
                    } else if wait_result == WAIT_FAILED {
                        record_monitor_error(
                            &errors,
                            format!(
                                "failed while waiting for protected metadata changes under {}: {}",
                                parent_display_for_listener,
                                io::Error::last_os_error()
                            ),
                        );
                        break;
                    } else {
                        record_monitor_error(
                            &errors,
                            format!(
                                "unexpected protected metadata wait result {wait_result} for {parent_display_for_listener}"
                            ),
                        );
                        break;
                    }
                }
                unsafe {
                    FindCloseChangeNotification(change_handle);
                }
            })
            .map_err(|err| {
                unsafe {
                    FindCloseChangeNotification(change_handle);
                }
                anyhow!(
                    "failed to start protected metadata monitor for {parent_display}: {err}"
                )
            })
    }

    fn set_violation_handler(&self, handler: ViolationHandler) -> Result<()> {
        {
            let mut guard = self
                .violation_handler
                .lock()
                .map_err(|_| anyhow!("protected metadata monitor handler state is poisoned"))?;
            *guard = Some(handler);
        }

        self.armed.store(true, Ordering::SeqCst);
        enforce_monitored_paths(
            &self.monitored_paths,
            &self.removed_paths,
            &self.errors,
            /*record_violation*/ true,
            &self.violation_seen,
            &self.violation_handler,
        );

        Ok(())
    }

    fn finish(&mut self) -> Result<Vec<PathBuf>> {
        self.stop_listeners();
        let errors = self
            .errors
            .lock()
            .map_err(|_| anyhow!("protected metadata monitor error state is poisoned"))?
            .clone();
        if !errors.is_empty() {
            return Err(anyhow!(
                "protected metadata monitor failed: {}",
                errors.join("; ")
            ));
        }

        let removed = self
            .removed_paths
            .lock()
            .map_err(|_| anyhow!("protected metadata monitor removal state is poisoned"))?
            .clone();
        Ok(unique_paths(removed))
    }

    fn stop_listeners(&mut self) {
        if self.stop_event != 0 {
            if unsafe { SetEvent(self.stop_event) } == 0 {
                record_monitor_error(
                    &self.errors,
                    format!(
                        "failed to stop protected metadata monitor: {}",
                        io::Error::last_os_error()
                    ),
                );
            }
            while let Some(listener) = self.listeners.pop() {
                if listener.join().is_err() {
                    record_monitor_error(
                        &self.errors,
                        "protected metadata monitor listener panicked".to_string(),
                    );
                }
            }
            unsafe {
                CloseHandle(self.stop_event);
            }
            self.stop_event = 0;
        }
    }
}

impl Drop for MissingCreationMonitor {
    fn drop(&mut self) {
        self.stop_listeners();
    }
}

fn monitored_paths_by_parent(paths: &[PathBuf]) -> Vec<(PathBuf, Vec<PathBuf>)> {
    let mut grouped: HashMap<String, (PathBuf, Vec<PathBuf>)> = HashMap::new();
    for path in paths {
        let Some(parent) = path.parent() else {
            continue;
        };
        let entry = grouped
            .entry(path_text_key(parent))
            .or_insert_with(|| (parent.to_path_buf(), Vec::new()));
        entry.1.push(path.clone());
    }
    grouped.into_values().collect()
}

fn enforce_monitored_paths(
    paths: &[PathBuf],
    removed_paths: &Arc<Mutex<Vec<PathBuf>>>,
    errors: &Arc<Mutex<Vec<String>>>,
    record_violation: bool,
    violation_seen: &Arc<AtomicBool>,
    violation_handler: &Arc<Mutex<Option<ViolationHandler>>>,
) {
    for path in paths {
        match existing_metadata_path(path) {
            Ok(Some(existing_path)) => {
                if record_violation {
                    record_metadata_violation(violation_seen, violation_handler);
                }
                if let Err(err) = remove_metadata_path(&existing_path) {
                    record_monitor_error(
                        errors,
                        format!(
                            "failed to remove protected metadata {}: {err:#}",
                            existing_path.display()
                        ),
                    );
                    continue;
                }
                match removed_paths.lock() {
                    Ok(mut removed) => removed.push(existing_path),
                    Err(_) => record_monitor_error(
                        errors,
                        "protected metadata monitor removal state is poisoned".to_string(),
                    ),
                }
            }
            Ok(None) => {}
            Err(err) => record_monitor_error(
                errors,
                format!(
                    "failed to inspect protected metadata {}: {err:#}",
                    path.display()
                ),
            ),
        }
    }
}

fn record_metadata_violation(
    violation_seen: &Arc<AtomicBool>,
    violation_handler: &Arc<Mutex<Option<ViolationHandler>>>,
) {
    if !violation_seen.swap(true, Ordering::SeqCst) {
        invoke_violation_handler(violation_handler);
    }
}

fn invoke_violation_handler(violation_handler: &Arc<Mutex<Option<ViolationHandler>>>) {
    if let Ok(handler) = violation_handler.lock()
        && let Some(handler) = handler.as_ref()
    {
        handler();
    }
}

fn record_monitor_error(errors: &Arc<Mutex<Vec<String>>>, message: String) {
    if let Ok(mut errors) = errors.lock() {
        errors.push(message);
    }
}

pub(crate) fn prepare_protected_metadata_targets(
    targets: &[ProtectedMetadataTarget],
) -> Result<ProtectedMetadataGuard> {
    let mut deny_paths = Vec::new();
    let mut monitored_paths = Vec::new();
    let mut sentinel_paths = Vec::new();
    for target in targets {
        match target.mode {
            ProtectedMetadataMode::ExistingDeny => {
                deny_paths.extend(protected_metadata_existing_deny_paths(&target.path));
            }
            ProtectedMetadataMode::MissingCreationMonitor => {
                monitored_paths.push(target.path.clone());
            }
            ProtectedMetadataMode::MissingDenySentinel => {
                let created = ensure_missing_deny_sentinel(&target.path)?;
                if created {
                    sentinel_paths.push(target.path.clone());
                } else {
                    let existing_deny_paths = protected_metadata_existing_deny_paths(&target.path);
                    deny_paths.extend(existing_deny_paths);
                }
            }
        }
    }
    Ok(ProtectedMetadataGuard {
        deny_paths,
        monitored_paths,
        sentinel_paths,
        sentinel_handles: Vec::new(),
    })
}

pub fn protected_metadata_existing_deny_paths(path: &Path) -> Vec<PathBuf> {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    push_deny_path(&mut paths, &mut seen, path.to_path_buf());

    let file_type = metadata.file_type();
    if (is_directory_reparse_point(&metadata)
        || file_type.is_symlink_dir()
        || file_type.is_symlink_file())
        && let Ok(target_path) = dunce::canonicalize(path)
    {
        push_deny_path(&mut paths, &mut seen, target_path);
    }

    paths
}

fn push_deny_path(paths: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    if seen.insert(path_text_key(&path)) {
        paths.push(path);
    }
}

fn path_text_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn unique_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for path in paths {
        if seen.insert(path_text_key(&path)) {
            unique.push(path);
        }
    }
    unique
}

fn existing_metadata_path(path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(matching_metadata_child(path)?.or_else(|| Some(path.to_path_buf()))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to inspect protected metadata {}", path.display()));
        }
    }

    matching_metadata_child(path)
}

fn matching_metadata_child(path: &Path) -> Result<Option<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    let Some(expected_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to scan protected metadata parent {}", parent.display()));
        }
    };

    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to read protected metadata parent entry {}",
                parent.display()
            )
        })?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
        {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn remove_metadata_path(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to inspect protected metadata {}", path.display()));
        }
    };
    let file_type = metadata.file_type();
    if is_directory_reparse_point(&metadata) || file_type.is_symlink_dir() {
        std::fs::remove_dir(path)
            .with_context(|| format!("failed to remove protected metadata {}", path.display()))?;
    } else if file_type.is_symlink_file() {
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove protected metadata {}", path.display()))?;
    } else if metadata.is_dir() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("failed to remove protected metadata {}", path.display()))?;
    } else {
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove protected metadata {}", path.display()))?;
    }
    Ok(())
}

/// Creates an empty sentinel directory for a missing protected metadata name.
///
/// Returns true when this call created the sentinel. If the target already
/// exists by the time enforcement prepares, callers should still deny it, but
/// must not claim it for cleanup as a Codex-created sentinel.
pub fn ensure_missing_deny_sentinel(path: &Path) -> Result<bool> {
    if existing_metadata_path(path)?.is_some() {
        return Ok(false);
    }

    match std::fs::create_dir(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err)
            .with_context(|| format!("failed to create protected metadata sentinel {}", path.display())),
    }
}

fn start_sentinel_cleanup_watchdog(paths: &[PathBuf]) -> Result<SentinelHandle> {
    let quoted_paths = paths
        .iter()
        .map(|path| format!("'{}'", powershell_single_quoted(&path.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$parent = {}; $paths = @({}); try {{ while ($true) {{ $alive = Get-Process -Id $parent -ErrorAction SilentlyContinue; $remaining = @($paths | Where-Object {{ Test-Path -LiteralPath $_ }}); if (-not $alive -or $remaining.Count -eq 0) {{ break }}; Start-Sleep -Milliseconds 200 }}; foreach ($p in $paths) {{ Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }} }} finally {{ Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue }}",
        std::process::id(),
        quoted_paths
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis();
    let script_path = std::env::temp_dir().join(format!(
        "codex-sentinel-cleanup-{}-{now}.ps1",
        std::process::id()
    ));
    std::fs::write(&script_path, script).with_context(|| {
        format!(
            "failed to write protected metadata sentinel cleanup script {}",
            script_path.display()
        )
    })?;

    let cleanup_command = format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"",
        script_path.to_string_lossy().replace('"', "\\\"")
    );
    let start_script = format!(
        "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = '{}' }}; if ($r.ReturnValue -ne 0) {{ exit $r.ReturnValue }}",
        powershell_single_quoted(&cleanup_command)
    );
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &start_script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to start protected metadata sentinel cleanup watchdog launcher")?;
    if !status.success() {
        let _ = std::fs::remove_file(&script_path);
        return Err(anyhow!(
            "protected metadata sentinel cleanup watchdog launcher exited with {status}"
        ));
    }
    Ok(SentinelHandle { script_path })
}

fn powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

fn is_directory_reparse_point(metadata: &Metadata) -> bool {
    metadata.is_dir() && (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::ProtectedMetadataMode;
    use crate::setup::ProtectedMetadataTarget;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn cleanup_created_paths_removes_case_variant() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target = temp_dir.path().join(".git");
        let created = temp_dir.path().join(".GIT");
        std::fs::create_dir_all(&created).expect("create metadata");
        let mut guard = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: target.clone(),
            mode: ProtectedMetadataMode::MissingCreationMonitor,
        }])
        .expect("guard");

        let removed = guard.cleanup_created_paths().expect("cleanup");
        assert_eq!(removed.len(), 1);
        assert!(
            removed[0]
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case(".git")),
            "removed path should be a .git case variant: {}",
            removed[0].display()
        );
        assert!(!target.exists());
        assert!(!created.exists());
    }

    #[test]
    fn missing_creation_monitor_removes_created_case_variant() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target = temp_dir.path().join(".git");
        let created = temp_dir.path().join(".GIT");
        let runtime = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: target,
            mode: ProtectedMetadataMode::MissingCreationMonitor,
        }])
        .expect("guard")
        .into_runtime()
        .expect("runtime");

        std::fs::create_dir_all(&created).expect("create metadata");
        let deadline = Instant::now() + Duration::from_secs(2);
        while created.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(
            !created.exists(),
            "monitor should remove protected metadata before final cleanup"
        );
        let removed = runtime.finish().expect("finish");
        assert!(
            removed
                .iter()
                .any(|path| path.file_name().and_then(std::ffi::OsStr::to_str) == Some(".GIT")),
            "removed paths should include the created case variant: {removed:?}"
        );
    }

    #[test]
    fn missing_creation_monitor_invokes_violation_handler_when_path_is_created() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target = temp_dir.path().join(".codex");
        let created = temp_dir.path().join(".CODEX");
        let runtime = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: target,
            mode: ProtectedMetadataMode::MissingCreationMonitor,
        }])
        .expect("guard")
        .into_runtime()
        .expect("runtime");
        let violation_seen = Arc::new(AtomicBool::new(false));
        runtime
            .set_violation_handler(Box::new({
                let violation_seen = Arc::clone(&violation_seen);
                move || violation_seen.store(true, Ordering::SeqCst)
            }))
            .expect("set violation handler");

        std::fs::create_dir_all(&created).expect("create metadata");
        let deadline = Instant::now() + Duration::from_secs(2);
        while (!violation_seen.load(Ordering::SeqCst) || created.exists())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(
            violation_seen.load(Ordering::SeqCst),
            "monitor should invoke the violation handler"
        );
        assert!(
            !created.exists(),
            "monitor should remove protected metadata before final cleanup"
        );
        let removed = runtime.finish().expect("finish");
        assert!(
            removed
                .iter()
                .any(|path| path.file_name().and_then(std::ffi::OsStr::to_str) == Some(".CODEX")),
            "removed paths should include the created case variant: {removed:?}"
        );
    }

    #[test]
    fn missing_creation_monitor_cleans_pre_arm_path_without_violation() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target = temp_dir.path().join(".codex");
        let created = temp_dir.path().join(".CODEX");
        let runtime = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: target,
            mode: ProtectedMetadataMode::MissingCreationMonitor,
        }])
        .expect("guard")
        .into_runtime()
        .expect("runtime");

        std::fs::create_dir_all(&created).expect("create metadata before arm");
        let deadline = Instant::now() + Duration::from_secs(2);
        while created.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !created.exists(),
            "pre-arm cleanup should remove setup-created metadata"
        );

        let violation_seen = Arc::new(AtomicBool::new(false));
        runtime
            .set_violation_handler(Box::new({
                let violation_seen = Arc::clone(&violation_seen);
                move || violation_seen.store(true, Ordering::SeqCst)
            }))
            .expect("set violation handler");
        assert!(
            !violation_seen.load(Ordering::SeqCst),
            "pre-arm cleanup should not terminate the command"
        );

        let removed = runtime.finish().expect("finish");
        assert!(
            removed
                .iter()
                .any(|path| path.file_name().and_then(std::ffi::OsStr::to_str) == Some(".CODEX")),
            "removed paths should include the pre-arm case variant: {removed:?}"
        );
    }

    #[test]
    fn existing_deny_paths_include_symlink_target() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target_dir = temp_dir.path().join("target-codex");
        let symlink_dir = temp_dir.path().join(".codex");
        std::fs::create_dir_all(&target_dir).expect("create target");
        if let Err(err) = std::os::windows::fs::symlink_dir(&target_dir, &symlink_dir) {
            eprintln!("skipping symlink test because symlink creation failed: {err}");
            return;
        }

        let guard = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: symlink_dir.clone(),
            mode: ProtectedMetadataMode::ExistingDeny,
        }])
        .expect("guard");
        let deny_paths: Vec<PathBuf> = guard.deny_paths().cloned().collect();
        let canonical_target = dunce::canonicalize(&target_dir).expect("canonical target");

        assert!(
            deny_paths
                .iter()
                .any(|path| path_text_key(path) == path_text_key(&symlink_dir)),
            "deny paths should include metadata symlink: {deny_paths:?}"
        );
        assert!(
            deny_paths
                .iter()
                .any(|path| path_text_key(path) == path_text_key(&canonical_target)),
            "deny paths should include symlink target: {deny_paths:?}"
        );
    }

    #[test]
    fn missing_deny_sentinel_creates_and_cleans_path() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target = temp_dir.path().join(".git");

        let mut guard = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: target.clone(),
            mode: ProtectedMetadataMode::MissingDenySentinel,
        }])
        .expect("guard");

        assert!(target.is_dir(), "sentinel directory should be created");
        assert!(
            guard
                .sentinel_paths()
                .any(|path| path_text_key(path) == path_text_key(&target)),
            "sentinel should be tracked separately from inherited deny paths"
        );
        assert!(
            guard.deny_paths().next().is_none(),
            "fresh sentinel should not use inherited deny ACL setup"
        );

        let removed = guard.cleanup_created_paths().expect("cleanup");
        assert!(removed.is_empty(), "sentinel cleanup is not a command violation");
        assert!(!target.exists(), "sentinel directory should be removed");
    }

    #[test]
    fn missing_deny_sentinel_does_not_cleanup_preexisting_path() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let target = temp_dir.path().join(".git");
        std::fs::create_dir_all(&target).expect("create metadata");

        let mut guard = prepare_protected_metadata_targets(&[ProtectedMetadataTarget {
            path: target.clone(),
            mode: ProtectedMetadataMode::MissingDenySentinel,
        }])
        .expect("guard");

        assert!(
            guard.deny_paths().any(|path| path_text_key(path) == path_text_key(&target)),
            "pre-existing metadata should still use deny paths"
        );
        assert!(
            guard.sentinel_paths().next().is_none(),
            "pre-existing metadata should not be claimed as a sentinel"
        );
        let removed = guard.cleanup_created_paths().expect("cleanup");
        assert!(removed.is_empty(), "pre-existing metadata is not Codex-owned cleanup");
        assert!(target.exists(), "pre-existing metadata should not be removed");
    }
}
