//! What the transaction data and response layers read of a verified request, without its
//! crypto: its `transaction_data` entries, its Response Mode, and whether it arrived signed.

/// A string of the `transaction_data` parameter, exactly as the request carried it (Section
/// 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionDataItem(String);

impl TransactionDataItem {
    /// The string `text`, as a request carries it.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The Response Mode of a verified request (Sections 8.2, 8.3.1; A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// `direct_post`.
    DirectPost,
    /// `direct_post.jwt`.
    DirectPostJwt,
    /// `direct_post.cwt` (`zkp_req.md`, Section 6.2).
    DirectPostCwt,
    /// `dc_api`.
    DcApi,
    /// `dc_api.jwt`.
    DcApiJwt,
}

impl ResponseMode {
    /// The `response_mode` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectPost => "direct_post",
            Self::DirectPostJwt => "direct_post.jwt",
            Self::DirectPostCwt => "direct_post.cwt",
            Self::DcApi => "dc_api",
            Self::DcApiJwt => "dc_api.jwt",
        }
    }
}

/// Whether a request arrived as a signed Request Object (RFC 9101).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestSignature {
    /// A Request Object whose signature intake verified.
    Signed,
    /// A request of a `redirect_uri` client, or an unsigned DC API request.
    Unsigned,
}
