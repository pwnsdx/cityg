use super::*;

pub(crate) fn kbroad_state_path_for_journal(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("kbroad.cbor")
}

pub(crate) fn load_kbroad_state(path: &Path) -> Result<PersistedKbroadState, CityGError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(CityGError::Io(err)),
    };
    ciborium::de::from_reader(file).map_err(|_| CityGError::InvalidInput("invalid kbroad state"))
}

pub(crate) fn persist_kbroad_state(
    path: &Path,
    state: &PersistedKbroadState,
) -> Result<(), CityGError> {
    #[allow(clippy::collapsible_if)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)
        .map_err(|_| CityGError::InvalidInput("failed to encode kbroad state"))?;

    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_data()?;
    }
    std::fs::rename(tmp_path, path)?;
    Ok(())
}
