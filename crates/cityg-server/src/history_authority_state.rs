use super::*;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedHistoryAuthorityState {
    #[serde(default)]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) scope_id_hex: String,
    #[serde(default)]
    pub(crate) public_key_hex: String,
    #[serde(default)]
    pub(crate) secret_key_hex: String,
    #[serde(default = "default_require_full_verification_receipt")]
    pub(crate) require_full_verification_receipt: bool,
}

pub(crate) fn default_require_full_verification_receipt() -> bool {
    true
}

pub(crate) fn history_authority_path_for_journal(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("history-authority.cbor")
}

pub(crate) fn load_history_authority_state(
    path: &Path,
) -> Result<Option<HistoryAuthorityState>, CityGError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CityGError::Io(err)),
    };
    let persisted: PersistedHistoryAuthorityState = ciborium::de::from_reader(file)
        .map_err(|_| CityGError::InvalidInput("invalid history authority state"))?;
    if persisted.scope_id_hex.is_empty()
        || persisted.public_key_hex.is_empty()
        || persisted.secret_key_hex.is_empty()
    {
        return Ok(None);
    }
    let mode = HistoryAuthorityMode::from_persisted_tag(&persisted.mode)?;
    Ok(Some(HistoryAuthorityState {
        mode,
        descriptor: HistoryAuthorityDescriptor {
            scope_id: decode_hex_32("history authority scope_id", &persisted.scope_id_hex)?,
            public_key: hex::decode(&persisted.public_key_hex)
                .map_err(|_| CityGError::InvalidInput("invalid history authority public key"))?,
        },
        secret_key: hex::decode(&persisted.secret_key_hex)
            .map_err(|_| CityGError::InvalidInput("invalid history authority secret key"))?,
        require_full_verification_receipt: normalize_history_authority_receipt_requirement(
            mode,
            persisted.require_full_verification_receipt,
        ),
    }))
}

pub(crate) fn persist_history_authority_state(
    path: &Path,
    state: &HistoryAuthorityState,
) -> Result<(), CityGError> {
    #[allow(clippy::collapsible_if)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let persisted = PersistedHistoryAuthorityState {
        mode: state.mode.persisted_tag().to_string(),
        scope_id_hex: hex::encode(state.descriptor.scope_id),
        public_key_hex: hex::encode(&state.descriptor.public_key),
        secret_key_hex: hex::encode(&state.secret_key),
        require_full_verification_receipt: state.require_full_verification_receipt,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&persisted, &mut bytes)
        .map_err(|_| CityGError::InvalidInput("failed to encode history authority state"))?;
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

pub(crate) fn derive_history_authority_scope_id(public_key: &[u8]) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct ScopePreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    h_l(
        "barrier/history-authority/scope",
        &ScopePreimage(public_key),
    )
    .map_err(CityGError::from)
}

pub(crate) fn generate_history_authority_state(
    mode: HistoryAuthorityMode,
    require_full_verification_receipt: bool,
) -> Result<HistoryAuthorityState, CityGError> {
    let (public_key, secret_key) = cityg_pqc::ml_dsa_65_keypair()
        .map_err(|_| CityGError::InvalidInput("failed to generate history authority keypair"))?;
    let secret_key = secret_key.into_bytes();
    Ok(HistoryAuthorityState {
        mode,
        descriptor: HistoryAuthorityDescriptor {
            scope_id: derive_history_authority_scope_id(public_key.as_slice())?,
            public_key,
        },
        secret_key,
        require_full_verification_receipt: normalize_history_authority_receipt_requirement(
            mode,
            require_full_verification_receipt,
        ),
    })
}

pub(crate) fn normalize_history_authority_receipt_requirement(
    mode: HistoryAuthorityMode,
    requested: bool,
) -> bool {
    if mode.requires_full_verification_receipt() {
        true
    } else {
        requested
    }
}

pub(crate) fn load_or_generate_history_authority_state(
    path: Option<&Path>,
    mode: HistoryAuthorityMode,
    require_full_verification_receipt: bool,
) -> Result<HistoryAuthorityState, CityGError> {
    let require_full_verification_receipt =
        normalize_history_authority_receipt_requirement(mode, require_full_verification_receipt);
    if let Some(path) = path {
        if let Some(mut state) = load_history_authority_state(path)? {
            state.mode = mode;
            state.require_full_verification_receipt = require_full_verification_receipt;
            persist_history_authority_state(path, &state)?;
            return Ok(state);
        }
        let state = generate_history_authority_state(mode, require_full_verification_receipt)?;
        persist_history_authority_state(path, &state)?;
        return Ok(state);
    }
    generate_history_authority_state(mode, require_full_verification_receipt)
}

pub(crate) fn decode_hex_32(label: &'static str, value: &str) -> Result<[u8; 32], CityGError> {
    let bytes = hex::decode(value).map_err(|_| CityGError::InvalidInput(label))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CityGError::InvalidInput(label))
}
