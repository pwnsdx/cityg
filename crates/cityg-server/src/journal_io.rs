use super::*;

#[derive(Debug)]
pub(crate) struct ServerJournal {
    file: File,
}

#[cfg(test)]
static JOURNAL_FAIL_ON_APPEND: AtomicIsize = AtomicIsize::new(-1);
#[cfg(test)]
static JOURNAL_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
static JOURNAL_SERIAL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
fn journal_failure_lock() -> &'static Mutex<()> {
    JOURNAL_HOOK_LOCK.get_or_init(Mutex::default)
}

#[cfg(test)]
fn journal_serial_lock() -> &'static Mutex<()> {
    JOURNAL_SERIAL_LOCK.get_or_init(Mutex::default)
}

#[cfg(test)]
pub(crate) struct JournalFailureGuard {
    _lock: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for JournalFailureGuard {
    fn drop(&mut self) {
        JOURNAL_FAIL_ON_APPEND.store(-1, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) fn fail_journal_after(countdown: usize) -> JournalFailureGuard {
    let lock = match journal_failure_lock().lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    JOURNAL_FAIL_ON_APPEND.store(countdown as isize, Ordering::SeqCst);
    JournalFailureGuard { _lock: lock }
}

#[cfg(test)]
pub(crate) fn journal_serial_guard() -> MutexGuard<'static, ()> {
    match journal_serial_lock().lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl ServerJournal {
    pub(crate) fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        #[allow(clippy::collapsible_if)]
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        Ok(Self { file })
    }

    pub(crate) fn append(&mut self, bundle: &ClientEpochBundle) -> Result<(), CityGError> {
        let bytes = bundle.to_cbor()?;
        let len = bytes.len() as u32;
        #[cfg(test)]
        {
            let remaining = JOURNAL_FAIL_ON_APPEND.load(Ordering::SeqCst);
            if remaining >= 0 {
                if remaining == 0 {
                    JOURNAL_FAIL_ON_APPEND.store(-1, Ordering::SeqCst);
                    return Err(std::io::Error::other("forced journal failure").into());
                } else {
                    JOURNAL_FAIL_ON_APPEND.store(remaining - 1, Ordering::SeqCst);
                }
            }
        }
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub(crate) fn load_entries(path: &Path) -> Result<Vec<Vec<u8>>, CityGError> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(CityGError::Io(err)),
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let mut cursor = &buf[..];
        let mut entries = Vec::new();
        while cursor.len() >= 4 {
            let (len_bytes, rest) = cursor.split_at(4);
            let len = u32::from_le_bytes(
                len_bytes
                    .try_into()
                    .map_err(|_| CityGError::InvalidInput("Invalid journal entry length"))?,
            );
            if rest.len() < len as usize {
                break;
            }
            let (entry, remainder) = rest.split_at(len as usize);
            entries.push(entry.to_vec());
            cursor = remainder;
        }
        Ok(entries)
    }
}
