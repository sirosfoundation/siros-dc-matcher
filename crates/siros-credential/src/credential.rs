//! A credential of the wallet state, read through its format component (C1).

use siros_mdoc::{Mdoc, P256Key};
use siros_sdjwt::SdJwt;
use siros_trust::IssuerChain;
use siros_wallet_state::{
    BatchId, CredentialEntry, CredentialId, InstanceId, KeyId, MetadataValue,
};

use crate::error::CredentialError;
use crate::sd_jwt_vc::SdJwtVc;
use crate::usable::Validity;
use crate::value;

/// The `metadata` type of the data an issuer delivers with a credential (privatedata 3.1,
/// Section 5A.2).
const AUXILIARY_DATA: &str = "auxiliary_data";

/// A wallet state entry whose `data` its format component reads.
pub struct Credential {
    entry: EntryRef,
    id: String,
    issuer: Option<String>,
    configuration_id: Option<String>,
    key_id: Option<KeyId>,
    auxiliary_data: Vec<MetadataValue>,
    validity: Validity,
    issuer_chain: Option<IssuerChain>,
    pub(crate) body: Body,
}

/// The parsed format value.
pub(crate) enum Body {
    SdJwtVc(Box<SdJwtVc>),
    Mdoc(Box<Mdoc>),
}

/// The entry a credential is read from: its `credentialId`, `batchId` and `instanceId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryRef {
    credential_id: CredentialId,
    batch_id: BatchId,
    instance_id: InstanceId,
}

impl EntryRef {
    /// `credentialId`.
    pub fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// `batchId`.
    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    /// `instanceId`.
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }
}

/// A credential format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// SD-JWT VC, stored as `dc+sd-jwt` or, by earlier wallets, as `vc+sd-jwt`.
    SdJwtVc,
    /// ISO/IEC 18013-5 mdoc, stored as `mso_mdoc`.
    Mdoc,
}

impl Format {
    /// The format identifier of OpenID4VP 1.0, Appendix B: `dc+sd-jwt` or `mso_mdoc`.
    pub fn identifier(self) -> &'static str {
        match self {
            Self::SdJwtVc => "dc+sd-jwt",
            Self::Mdoc => "mso_mdoc",
        }
    }
}

/// The parsed format value of a credential.
#[derive(Clone, Copy)]
pub enum Parsed<'a> {
    /// The SD-JWT of an SD-JWT VC.
    SdJwtVc(&'a SdJwt),
    /// The mdoc.
    Mdoc(&'a Mdoc),
}

impl Credential {
    /// The credential of `entry`.
    ///
    /// `format` selects the reader: `dc+sd-jwt` and `vc+sd-jwt` read as SD-JWT VC, `mso_mdoc`
    /// as mdoc. An SD-JWT VC has a string `vct`; `iss`, `nbf`, `exp`, `cnf`, `vct`,
    /// `vct#integrity`, `aka_vcts` and `status` are permanently disclosed; `cnf`, when present,
    /// is a JSON object; `nbf` and `exp` are NumericDates. Every mdoc element value, at every
    /// depth, has one of the ten types of [`TypedValue`](crate::TypedValue): its tags are 0
    /// over a `tdate` and 1004 over a `full-date`, its map keys are text, and it holds no
    /// `undefined`. The issuer chain (TR2), the mdoc's `x5chain` or the SD-JWT VC issuer JWT's
    /// `x5c`, parses.
    ///
    /// # Errors
    ///
    /// [`CredentialError`]: the first rule `entry` breaks.
    pub fn parse(entry: &CredentialEntry) -> Result<Self, CredentialError> {
        let (body, validity, issuer_chain) = match entry.format() {
            "dc+sd-jwt" | "vc+sd-jwt" => {
                let vc = SdJwtVc::read(entry.data())?;
                let validity = vc.validity();
                let chain = vc
                    .sd_jwt()
                    .x5c()
                    .map(|x5c| IssuerChain::parse(x5c.certificates()))
                    .transpose()?;
                (Body::SdJwtVc(Box::new(vc)), validity, chain)
            }
            "mso_mdoc" => {
                let mdoc = Box::new(Mdoc::parse(entry.data())?);
                value::typed(&mdoc)?;
                let mso = mdoc.mso().validity();
                let validity = Validity::new(Some(mso.valid_from()), Some(mso.valid_until()));
                let chain = IssuerChain::parse(mdoc.issuer_auth().x5chain().certificates())?;
                (Body::Mdoc(mdoc), validity, Some(chain))
            }
            _ => return Err(CredentialError::UnsupportedFormat),
        };
        Ok(Self {
            entry: EntryRef {
                credential_id: entry.credential_id(),
                batch_id: entry.batch_id(),
                instance_id: entry.instance_id(),
            },
            id: entry.credential_id().to_string(),
            issuer: entry.issuer().map(str::to_owned),
            configuration_id: entry.configuration_id().map(str::to_owned),
            key_id: entry.key_id().cloned(),
            auxiliary_data: entry
                .metadata()
                .iter()
                .filter(|m| m.kind() == AUXILIARY_DATA)
                .map(|m| m.value().clone())
                .collect(),
            validity,
            issuer_chain,
            body,
        })
    }

    /// The entry the credential is read from.
    pub fn entry(&self) -> EntryRef {
        self.entry
    }

    /// The format.
    pub fn format(&self) -> Format {
        match self.body {
            Body::SdJwtVc(_) => Format::SdJwtVc,
            Body::Mdoc(_) => Format::Mdoc,
        }
    }

    /// The parsed format value.
    pub fn parsed(&self) -> Parsed<'_> {
        match &self.body {
            Body::SdJwtVc(vc) => Parsed::SdJwtVc(vc.sd_jwt()),
            Body::Mdoc(mdoc) => Parsed::Mdoc(mdoc),
        }
    }

    /// The type: the SD-JWT VC's `vct`, or the mdoc's `docType`.
    pub fn credential_type(&self) -> &str {
        match &self.body {
            Body::SdJwtVc(vc) => vc.vct(),
            Body::Mdoc(mdoc) => mdoc.doc_type(),
        }
    }

    /// The entry's `credentialIssuerIdentifier`. `None` when the wallet did not know it.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// The entry's `credentialConfigurationId`. `None` when the wallet did not know it.
    pub fn configuration_id(&self) -> Option<&str> {
        self.configuration_id.as_deref()
    }

    /// The validity: the MSO's `validFrom` and `validUntil`, or the SD-JWT VC's `nbf` and
    /// `exp`.
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// The public key a presentation of the credential proves possession of: the P-256 key of
    /// an SD-JWT VC's `cnf.jwk`, or an mdoc's `deviceKey`. `None` for an SD-JWT VC without
    /// `cnf`, which is bound to no key.
    pub fn holder_key(&self) -> Option<P256Key> {
        match &self.body {
            Body::SdJwtVc(vc) => vc.holder_key(),
            Body::Mdoc(mdoc) => Some(*mdoc.mso().device_key()),
        }
    }

    /// The issuer chain (TR2): the mdoc's `x5chain`, or the SD-JWT VC issuer JWT's `x5c`. `None`
    /// for an SD-JWT VC without `x5c`.
    pub fn issuer_chain(&self) -> Option<&IssuerChain> {
        self.issuer_chain.as_ref()
    }

    /// The entry's `kid`: the key pair the credential is bound to.
    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// The value of each `metadata` entry of type `auxiliary_data`, in their order: the
    /// Auxiliary Data Entries the issuer delivered (privatedata 3.1, Section 5A.2).
    pub fn auxiliary_data(&self) -> &[MetadataValue] {
        &self.auxiliary_data
    }

    /// The decimal `credentialId`: the identifier DCQL evaluation echoes.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}
