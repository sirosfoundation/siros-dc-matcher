//! `urn:eudi:sca:payment:1`: payment confirmation (EC TS12 v1.0.1, Section 4.3.1).

use crate::error::TransactionDataError;
use crate::json::{self, optional, Fields, Json, Number};
use crate::ts12::display::Leaves;
use crate::ts12::{bounded, transaction_id, Payload};
use crate::view::{Frequency, Level};

/// A payment: the payload of `urn:eudi:sca:payment:1`, also the `payment_payload` of an
/// e-mandate.
pub(crate) struct Payment {
    transaction_id: String,
    date_time: Option<String>,
    payee: Payee,
    pisp: Option<Party>,
    execution_date: Option<String>,
    currency: String,
    amount: Number,
    amount_estimated: Option<bool>,
    amount_earmarked: Option<bool>,
    sct_inst: Option<bool>,
    recurrence: Option<Recurrence>,
}

/// `payee`. Its schema leaves further members open.
struct Payee {
    name: String,
    id: String,
    logo: Option<String>,
    website: Option<String>,
    rest: Vec<(String, Json)>,
}

/// A third party: the `pisp` of a payment, the `aisp` of an account access. Its schema leaves
/// further members open.
pub(crate) struct Party {
    legal_name: String,
    brand_name: String,
    domain_name: String,
    rest: Vec<(String, Json)>,
}

/// The paths of a party's members.
pub(crate) struct PartyPaths {
    pub(crate) legal_name: &'static str,
    pub(crate) brand_name: &'static str,
    pub(crate) domain_name: &'static str,
}

/// `recurrence`. Its schema leaves further members open.
struct Recurrence {
    start_date: Option<String>,
    end_date: Option<String>,
    number: Option<Number>,
    frequency: Frequency,
    mit_options: Option<MitOptions>,
    rest: Vec<(String, Json)>,
}

/// `recurrence.mit_options`. Its schema leaves further members open.
struct MitOptions {
    amount_variable: Option<bool>,
    min_amount: Option<Number>,
    max_amount: Option<Number>,
    total_amount: Option<Number>,
    initial_amount: Option<Number>,
    initial_amount_number: Option<Number>,
    apr: Option<Number>,
    rest: Vec<(String, Json)>,
}

const PISP: PartyPaths = PartyPaths {
    legal_name: "pisp.legal_name",
    brand_name: "pisp.brand_name",
    domain_name: "pisp.domain_name",
};

impl Payload for Payment {
    const TYPE: &'static str = "urn:eudi:sca:payment:1";

    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        let payment = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(&mut fields, "date_time", "date_time", json::text)?,
            payee: Payee::parse(json::object(fields.require("payee", "payee")?, "payee")?)?,
            pisp: optional(&mut fields, "pisp", "pisp", |value, path| {
                Party::parse(json::object(value, path)?, &PISP)
            })?,
            execution_date: optional(&mut fields, "execution_date", "execution_date", json::text)?,
            currency: currency(fields.require("currency", "currency")?)?,
            amount: json::number(fields.require("amount", "amount")?, "amount")?,
            amount_estimated: optional(
                &mut fields,
                "amount_estimated",
                "amount_estimated",
                json::boolean,
            )?,
            amount_earmarked: optional(
                &mut fields,
                "amount_earmarked",
                "amount_earmarked",
                json::boolean,
            )?,
            sct_inst: optional(&mut fields, "sct_inst", "sct_inst", json::boolean)?,
            recurrence: optional(&mut fields, "recurrence", "recurrence", |value, path| {
                Recurrence::parse(json::object(value, path)?)
            })?,
        };
        fields.finish()?;
        Ok(payment)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text("transaction_id", &self.transaction_id, Some(Level::Main));
        leaves.optional_text("date_time", self.date_time.as_deref());
        leaves.object("payee", |payee| {
            payee.text("name", &self.payee.name, Some(Level::Prominent));
            payee.text("id", &self.payee.id, Some(Level::Main));
            payee.optional_text("logo", self.payee.logo.as_deref());
            payee.optional_text("website", self.payee.website.as_deref());
            payee.rest(&self.payee.rest);
        });
        if let Some(pisp) = &self.pisp {
            leaves.object("pisp", |leaves| pisp.leaves(leaves));
        }
        leaves.optional_text("execution_date", self.execution_date.as_deref());
        leaves.text("currency", &self.currency, Some(Level::Prominent));
        leaves.number("amount", &self.amount, Some(Level::Prominent));
        leaves.optional_boolean("amount_estimated", self.amount_estimated);
        leaves.optional_boolean("amount_earmarked", self.amount_earmarked);
        leaves.optional_boolean("sct_inst", self.sct_inst);
        if let Some(recurrence) = &self.recurrence {
            leaves.object("recurrence", |leaves| recurrence.leaves(leaves));
        }
    }
}

impl Payee {
    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        Ok(Self {
            name: json::text(fields.require("name", "payee.name")?, "payee.name")?,
            id: json::text(fields.require("id", "payee.id")?, "payee.id")?,
            logo: optional(&mut fields, "logo", "payee.logo", json::text)?,
            website: optional(&mut fields, "website", "payee.website", json::text)?,
            rest: fields.rest(),
        })
    }
}

impl Party {
    /// The party of `fields`, its members at `paths`.
    pub(crate) fn parse(
        mut fields: Fields,
        paths: &PartyPaths,
    ) -> Result<Self, TransactionDataError> {
        Ok(Self {
            legal_name: json::text(
                fields.require("legal_name", paths.legal_name)?,
                paths.legal_name,
            )?,
            brand_name: json::text(
                fields.require("brand_name", paths.brand_name)?,
                paths.brand_name,
            )?,
            domain_name: json::text(
                fields.require("domain_name", paths.domain_name)?,
                paths.domain_name,
            )?,
            rest: fields.rest(),
        })
    }

    /// Its leaves.
    pub(crate) fn leaves(&self, leaves: &mut Leaves) {
        leaves.text("legal_name", &self.legal_name, None);
        leaves.text("brand_name", &self.brand_name, None);
        leaves.text("domain_name", &self.domain_name, None);
        leaves.rest(&self.rest);
    }
}

impl Recurrence {
    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        Ok(Self {
            start_date: optional(
                &mut fields,
                "start_date",
                "recurrence.start_date",
                json::text,
            )?,
            end_date: optional(&mut fields, "end_date", "recurrence.end_date", json::text)?,
            number: optional(&mut fields, "number", "recurrence.number", json::integer)?,
            frequency: frequency(fields.require("frequency", "recurrence.frequency")?)?,
            mit_options: optional(
                &mut fields,
                "mit_options",
                "recurrence.mit_options",
                |value, path| MitOptions::parse(json::object(value, path)?),
            )?,
            rest: fields.rest(),
        })
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.optional_text("start_date", self.start_date.as_deref());
        leaves.optional_text("end_date", self.end_date.as_deref());
        leaves.optional_number("number", self.number.as_ref());
        leaves.frequency("frequency", self.frequency);
        if let Some(options) = &self.mit_options {
            leaves.object("mit_options", |leaves| options.leaves(leaves));
        }
        leaves.rest(&self.rest);
    }
}

impl MitOptions {
    fn parse(mut fields: Fields) -> Result<Self, TransactionDataError> {
        const AMOUNT_VARIABLE: &str = "recurrence.mit_options.amount_variable";
        const MIN_AMOUNT: &str = "recurrence.mit_options.min_amount";
        const MAX_AMOUNT: &str = "recurrence.mit_options.max_amount";
        const TOTAL_AMOUNT: &str = "recurrence.mit_options.total_amount";
        const INITIAL_AMOUNT: &str = "recurrence.mit_options.initial_amount";
        const INITIAL_AMOUNT_NUMBER: &str = "recurrence.mit_options.initial_amount_number";
        const APR: &str = "recurrence.mit_options.apr";
        Ok(Self {
            amount_variable: optional(
                &mut fields,
                "amount_variable",
                AMOUNT_VARIABLE,
                json::boolean,
            )?,
            min_amount: optional(&mut fields, "min_amount", MIN_AMOUNT, json::number)?,
            max_amount: optional(&mut fields, "max_amount", MAX_AMOUNT, json::number)?,
            total_amount: optional(&mut fields, "total_amount", TOTAL_AMOUNT, json::number)?,
            initial_amount: optional(&mut fields, "initial_amount", INITIAL_AMOUNT, json::number)?,
            initial_amount_number: optional(
                &mut fields,
                "initial_amount_number",
                INITIAL_AMOUNT_NUMBER,
                json::integer,
            )?,
            apr: optional(&mut fields, "apr", APR, json::number)?,
            rest: fields.rest(),
        })
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.optional_boolean("amount_variable", self.amount_variable);
        leaves.optional_number("min_amount", self.min_amount.as_ref());
        leaves.optional_number("max_amount", self.max_amount.as_ref());
        leaves.optional_number("total_amount", self.total_amount.as_ref());
        leaves.optional_number("initial_amount", self.initial_amount.as_ref());
        leaves.optional_number("initial_amount_number", self.initial_amount_number.as_ref());
        leaves.optional_number("apr", self.apr.as_ref());
        leaves.rest(&self.rest);
    }
}

/// `currency`: three ASCII capital letters, the schema's `^[A-Z]{3}$` (an ISO 4217 alphabetic
/// code).
fn currency(value: Json) -> Result<String, TransactionDataError> {
    let currency = bounded(value, "currency", 3, 3)?;
    if currency.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(currency)
    } else {
        Err(TransactionDataError::InvalidValue("currency"))
    }
}

/// `recurrence.frequency`: one of the ISO 20022 codes the schema enumerates.
fn frequency(value: Json) -> Result<Frequency, TransactionDataError> {
    const PATH: &str = "recurrence.frequency";
    Frequency::named(&json::text(value, PATH)?).ok_or(TransactionDataError::InvalidValue(PATH))
}
