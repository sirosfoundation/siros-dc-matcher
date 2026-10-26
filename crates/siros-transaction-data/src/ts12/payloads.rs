//! `urn:eudi:sca:login_risk_transaction:1`, `urn:eudi:sca:account_access:1` and
//! `urn:eudi:sca:emandate:1` (EC TS12 v1.0.1, Sections 4.3.2 to 4.3.4).

use crate::error::TransactionDataError;
use crate::json::{self, optional, Fields};
use crate::ts12::display::Leaves;
use crate::ts12::payment::{Party, PartyPaths, Payment};
use crate::ts12::{bounded, transaction_id, Payload};
use crate::view::Level;

/// Login and risk-based authentication (Section 4.3.2).
pub(crate) struct LoginRisk {
    transaction_id: String,
    date_time: Option<String>,
    service: Option<String>,
    action: String,
}

/// Payment account information access (Section 4.3.3).
pub(crate) struct AccountAccess {
    transaction_id: String,
    date_time: Option<String>,
    aisp: Option<Party>,
    description: Option<String>,
}

/// E-mandate (Section 4.3.4).
pub(crate) struct Emandate {
    transaction_id: String,
    date_time: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    reference_number: Option<String>,
    creditor_id: Option<String>,
    purpose: Option<String>,
    payment_payload: Option<Payment>,
}

const AISP: PartyPaths = PartyPaths {
    legal_name: "aisp.legal_name",
    brand_name: "aisp.brand_name",
    domain_name: "aisp.domain_name",
};

impl Payload for LoginRisk {
    const TYPE: &'static str = "urn:eudi:sca:login_risk_transaction:1";

    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        let login = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(&mut fields, "date_time", "date_time", json::text)?,
            service: optional(&mut fields, "service", "service", |value, path| {
                bounded(value, path, 0, 100)
            })?,
            action: bounded(fields.require("action", "action")?, "action", 0, 140)?,
        };
        fields.finish()?;
        Ok(login)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text("transaction_id", &self.transaction_id, Some(Level::Main));
        leaves.optional_text("date_time", self.date_time.as_deref());
        leaves.optional_text("service", self.service.as_deref());
        leaves.text("action", &self.action, Some(Level::Prominent));
    }
}

impl Payload for AccountAccess {
    const TYPE: &'static str = "urn:eudi:sca:account_access:1";

    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        let access = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(&mut fields, "date_time", "date_time", json::text)?,
            aisp: optional(&mut fields, "aisp", "aisp", |value, path| {
                Party::parse(json::object(value, path)?, &AISP)
            })?,
            description: optional(&mut fields, "description", "description", |value, path| {
                bounded(value, path, 0, 140)
            })?,
        };
        fields.finish()?;
        Ok(access)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text("transaction_id", &self.transaction_id, Some(Level::Main));
        leaves.optional_text("date_time", self.date_time.as_deref());
        if let Some(aisp) = &self.aisp {
            leaves.object("aisp", |leaves| aisp.leaves(leaves));
        }
        leaves.optional_text("description", self.description.as_deref());
    }
}

impl Payload for Emandate {
    const TYPE: &'static str = "urn:eudi:sca:emandate:1";

    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        let mandate = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(&mut fields, "date_time", "date_time", json::text)?,
            start_date: optional(&mut fields, "start_date", "start_date", json::text)?,
            end_date: optional(&mut fields, "end_date", "end_date", json::text)?,
            reference_number: optional(
                &mut fields,
                "reference_number",
                "reference_number",
                |value, path| bounded(value, path, 1, 50),
            )?,
            creditor_id: optional(&mut fields, "creditor_id", "creditor_id", |value, path| {
                bounded(value, path, 1, 50)
            })?,
            purpose: optional(&mut fields, "purpose", "purpose", |value, path| {
                bounded(value, path, 0, 1000)
            })?,
            // The schema's `$ref` to the payment schema.
            payment_payload: optional(
                &mut fields,
                "payment_payload",
                "payment_payload",
                |value, path| Payment::parse(json::object(value, path)?),
            )?,
        };
        fields.finish()?;
        Ok(mandate)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text("transaction_id", &self.transaction_id, Some(Level::Main));
        leaves.optional_text("date_time", self.date_time.as_deref());
        leaves.optional_text("start_date", self.start_date.as_deref());
        leaves.optional_text("end_date", self.end_date.as_deref());
        leaves.optional_text("reference_number", self.reference_number.as_deref());
        leaves.optional_text("creditor_id", self.creditor_id.as_deref());
        leaves.optional_text("purpose", self.purpose.as_deref());
        if let Some(payment) = &self.payment_payload {
            leaves.object("payment_payload", |leaves| payment.leaves(leaves));
        }
    }
}
