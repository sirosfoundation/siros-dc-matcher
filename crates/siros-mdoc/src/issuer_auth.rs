//! `issuerAuth`: the issuer's `COSE_Sign1` over the MSO (ISO/IEC 18013-5, 9.1.2.4).

use siros_codec::cbor::{self, Item, Kind};

use crate::error::MdocError;

/// The COSE label of `alg` (RFC 9052, Section 3.1).
const ALG: i64 = 1;
/// The COSE label of `x5chain` (RFC 9360).
const X5CHAIN: i64 = 33;

/// `issuerAuth`, as the issuer wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerAuth {
    encoded: Vec<u8>,
    algorithm: i64,
    document_signer: Vec<u8>,
    sig_structure: Vec<u8>,
    signature: Vec<u8>,
}

impl IssuerAuth {
    /// `COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]`, and
    /// the payload's content.
    pub(crate) fn read<'a>(item: &Item<'a>) -> Result<(Self, &'a [u8]), MdocError> {
        let Some([protected, unprotected, payload, signature]) = item.as_array() else {
            return Err(MdocError::IssuerAuth);
        };
        let header = protected.as_bytes().ok_or(MdocError::IssuerAuth)?;
        let algorithm = cbor::decode(header)
            .ok()
            .and_then(|h| h.get_int(ALG).and_then(Item::as_int))
            .ok_or(MdocError::Algorithm)?;
        let x5chain = unprotected.get_int(X5CHAIN).ok_or(MdocError::X5chain)?;
        let document_signer = read_document_signer(x5chain)?;
        let payload_bytes = payload.as_bytes().ok_or(MdocError::IssuerAuth)?;
        let signature = signature.as_bytes().ok_or(MdocError::IssuerAuth)?;
        // RFC 9052, Section 4.4: ["Signature1", protected, external_aad = h'', payload], with the
        // protected header and the payload as the issuer wrote them.
        let sig_structure = [
            &[0x84, 0x6a][..],
            b"Signature1",
            protected.raw,
            &[0x40],
            payload.raw,
        ]
        .concat();
        let auth = Self {
            encoded: item.raw.to_vec(),
            algorithm,
            document_signer,
            sig_structure,
            signature: signature.to_vec(),
        };
        Ok((auth, payload_bytes))
    }

    /// The encoded `COSE_Sign1`.
    pub fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }

    /// The COSE algorithm of the protected header.
    pub fn algorithm(&self) -> i64 {
        self.algorithm
    }

    /// The Document Signer certificate, DER: the first of `x5chain`.
    pub fn document_signer(&self) -> &[u8] {
        &self.document_signer
    }

    /// The COSE `Sig_structure` the signature covers.
    pub fn sig_structure(&self) -> &[u8] {
        &self.sig_structure
    }

    /// The signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// `x5chain`: one certificate, or a non-empty array of them, the signer's first (RFC 9360).
fn read_document_signer(item: &Item<'_>) -> Result<Vec<u8>, MdocError> {
    match &item.kind {
        Kind::Bytes(der) => Ok(der.to_vec()),
        Kind::Array(certificates) => {
            let mut ders = certificates.iter().map(Item::as_bytes);
            let signer = ders.next().flatten().ok_or(MdocError::X5chain)?;
            if ders.any(|der| der.is_none()) {
                return Err(MdocError::X5chain);
            }
            Ok(signer.to_vec())
        }
        _ => Err(MdocError::X5chain),
    }
}
