//! `issuerAuth`: the issuer's `COSE_Sign1` over the MSO (ISO/IEC 18013-5, 9.1.2.4).

use siros_codec::cbor::{self, Item, Kind};

use crate::error::{AlgorithmFault, IssuerAuthFault, MdocError, MemberFault};
use crate::signature::{CoseAlgorithm, SigStructure};

/// The COSE label of `alg` (RFC 9052, Section 3.1).
const ALG: i64 = 1;
/// The COSE label of `x5chain` (RFC 9360).
const X5CHAIN: i64 = 33;

/// `issuerAuth`, as the issuer wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerAuth {
    encoded: Vec<u8>,
    algorithm: CoseAlgorithm,
    x5chain: X5Chain,
    sig_structure: SigStructure,
    signature: Vec<u8>,
}

/// `x5chain` (RFC 9360): the issuer's certificates as it wrote them, DER, the Document
/// Signer's first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X5Chain {
    document_signer: Vec<u8>,
    issuers: Vec<Vec<u8>>,
}

impl IssuerAuth {
    /// `COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]`, and
    /// the payload's content.
    pub(crate) fn read<'a>(item: &Item<'a>) -> Result<(Self, &'a [u8]), MdocError> {
        let fault = MdocError::IssuerAuth;
        let Some([protected, unprotected, payload, signature]) = item.as_array() else {
            return Err(fault(IssuerAuthFault::NotSign1));
        };
        let header = protected
            .as_bytes()
            .ok_or(fault(IssuerAuthFault::Protected))?;
        let algorithm = cbor::decode(header)
            .map_err(|e| MdocError::Algorithm(AlgorithmFault::Header(e)))?
            .get_int(ALG)
            .and_then(Item::as_int)
            .map(CoseAlgorithm::new)
            .ok_or(MdocError::Algorithm(AlgorithmFault::Absent))?;
        let x5chain = X5Chain::read(unprotected.get_int(X5CHAIN)).map_err(MdocError::X5chain)?;
        let payload_bytes = payload.as_bytes().ok_or(fault(IssuerAuthFault::Payload))?;
        let signature = signature
            .as_bytes()
            .ok_or(fault(IssuerAuthFault::Signature))?;
        // RFC 9052, Section 4.4: ["Signature1", protected, external_aad = h'', payload], with the
        // protected header and the payload as the issuer wrote them.
        let sig_structure = [
            &[0x84, 0x6a][..],
            b"Signature1",
            protected.raw(),
            &[0x40],
            payload.raw(),
        ]
        .concat();
        let auth = Self {
            encoded: item.raw().to_vec(),
            algorithm,
            x5chain,
            sig_structure: SigStructure::new(sig_structure),
            signature: signature.to_vec(),
        };
        Ok((auth, payload_bytes))
    }

    /// The encoded `COSE_Sign1`.
    #[must_use]
    pub fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }

    /// The COSE algorithm of the protected header.
    #[must_use]
    pub fn algorithm(&self) -> CoseAlgorithm {
        self.algorithm
    }

    /// `x5chain`.
    #[must_use]
    pub fn x5chain(&self) -> &X5Chain {
        &self.x5chain
    }

    /// The COSE `Sig_structure` the signature covers.
    #[must_use]
    pub fn sig_structure(&self) -> &SigStructure {
        &self.sig_structure
    }

    /// The signature, in the form [`IssuerAuth::algorithm`] defines.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl X5Chain {
    /// `x5chain`: one certificate, or a non-empty array of them, the signer's first (RFC 9360).
    fn read(item: Option<&Item<'_>>) -> Result<Self, MemberFault> {
        match item.ok_or(MemberFault::Absent)?.kind() {
            Kind::Bytes(der) => Ok(Self {
                document_signer: der.to_vec(),
                issuers: Vec::new(),
            }),
            Kind::Array(certificates) => {
                let mut ders = certificates.iter().map(|certificate| {
                    certificate
                        .as_bytes()
                        .map(<[u8]>::to_vec)
                        .ok_or(MemberFault::WrongType)
                });
                let document_signer = ders.next().ok_or(MemberFault::Empty)??;
                Ok(Self {
                    document_signer,
                    issuers: ders.collect::<Result<_, _>>()?,
                })
            }
            _ => Err(MemberFault::WrongType),
        }
    }

    /// The Document Signer certificate, DER: the first.
    #[must_use]
    pub fn document_signer(&self) -> &[u8] {
        &self.document_signer
    }

    /// The certificates, DER, the Document Signer's first.
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.document_signer.as_slice())
            .chain(self.issuers.iter().map(Vec::as_slice))
    }
}
