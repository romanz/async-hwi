use crate::{AddressScript, DeviceKind, Error as HWIError, HWI};

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
    Address, Network,
};
use trezor_client::{client::handle_interaction, AvailableDevice, Trezor};

pub struct TrezorClient {
    client: Arc<Mutex<Trezor>>,
    kind: DeviceKind,
    network: Network,
}

impl From<TrezorClient> for Box<dyn HWI + Send> {
    fn from(s: TrezorClient) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl std::fmt::Debug for TrezorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrezorClient")
            .field("client", &self.client.lock().unwrap().model())
            .finish()
    }
}

impl TrezorClient {
    fn new(client: Trezor, network: Network) -> Self {
        let kind = match client.model() {
            trezor_client::Model::TrezorEmulator => DeviceKind::TrezorSimulator,
            _ => DeviceKind::Trezor,
        };
        Self {
            client: Arc::new(Mutex::new(client)),
            kind,
            network,
        }
    }

    pub fn connect(device: AvailableDevice, network: Network) -> Result<Self, HWIError> {
        let mut client = device.connect()?;
        client.init_device(None)?;
        Ok(Self::new(client, network))
    }

    pub fn find_devices() -> Vec<AvailableDevice> {
        trezor_client::find_devices(false)
    }
}

#[async_trait]
impl HWI for TrezorClient {
    fn device_kind(&self) -> crate::DeviceKind {
        self.kind
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        let client = self.client.lock().unwrap();
        let features = client
            .features()
            .ok_or_else(|| HWIError::Device(String::from("No features found")))?;
        Ok(super::Version {
            major: features.major_version(),
            minor: features.minor_version(),
            patch: features.patch_version(),
            prerelease: None,
        })
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let xpub = handle_interaction(self.client.lock().unwrap().get_public_key(
            path,
            trezor_client::InputScriptType::SPENDADDRESS,
            self.network,
            false,
        )?)?;
        Ok(xpub)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        self.get_extended_pubkey(&DerivationPath::default())
            .await
            .map(|xpub| xpub.fingerprint())
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(path) => {
                let _addr: Address = handle_interaction(self.client.lock().unwrap().get_address(
                    path,
                    trezor_client::InputScriptType::SPENDTAPROOT,
                    self.network,
                    true,
                )?)?;
                Ok(())
            }
            AddressScript::Miniscript { .. } => Err(HWIError::UnimplementedMethod),
        }
    }

    async fn sign_tx(&self, _tx: &mut Psbt) -> Result<(), HWIError> {
        return Err(HWIError::UnimplementedMethod);
    }

    async fn register_wallet(
        &self,
        _name: &str,
        _policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        return Err(HWIError::UnimplementedMethod);
    }

    async fn is_wallet_registered(&self, _name: &str, _policy: &str) -> Result<bool, HWIError> {
        return Err(HWIError::UnimplementedMethod);
    }
}

impl From<trezor_client::Error> for HWIError {
    fn from(value: trezor_client::Error) -> Self {
        HWIError::Device(format!("{:#?}", value))
    }
}
