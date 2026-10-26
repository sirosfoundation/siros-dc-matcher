//! The payload fixtures: one per construction rule of the four TS12 schemas, and the payloads
//! those schemas accept at their edges. The refusal table and the schema differential read the
//! same list.

use serde_json::{json, Value};

use siros_transaction_data::MAX_DEPTH;

use crate::common::{payment, with, ACCESS, LOGIN, MANDATE, PAYMENT};

pub struct Payload {
    pub case: &'static str,
    pub transaction_type: &'static str,
    pub payload: Value,
    /// `Ok`, or the code of the refusal.
    pub expected: Result<(), &'static str>,
}

const MISSING: Result<(), &str> = Err("transaction_data_member_missing");
const WRONG_TYPE: Result<(), &str> = Err("transaction_data_member_wrong_type");
const INVALID: Result<(), &str> = Err("transaction_data_member_invalid");
const UNKNOWN: Result<(), &str> = Err("transaction_data_member_unknown");

fn row(
    case: &'static str,
    transaction_type: &'static str,
    payload: Value,
    expected: Result<(), &'static str>,
) -> Payload {
    Payload {
        case,
        transaction_type,
        payload,
        expected,
    }
}

/// A payment with `changes`.
fn pay(changes: Value) -> Value {
    with(payment(), changes)
}

/// `depth` arrays, each inside the one before.
fn nested(depth: usize) -> Value {
    (1..depth).fold(json!([]), |inner, _| json!([inner]))
}

/// A payment whose `date_time` is `null`.
fn null_date_time() -> Value {
    let mut payload = payment();
    payload["date_time"] = Value::Null;
    payload
}

fn chars(c: char, n: usize) -> String {
    c.to_string().repeat(n)
}

pub fn payloads() -> Vec<Payload> {
    let party =
        json!({"legal_name": "PISP Ltd", "brand_name": "Pisp", "domain_name": "pisp.example"});
    vec![
        row("a payment", PAYMENT, payment(), Ok(())),
        row(
            "a payment with every member",
            PAYMENT,
            pay(json!({
                "date_time": "2025-11-13T20:20:39+00:00",
                "payee": {"name": "Shop AB", "id": "SE1", "logo": "https://shop.example/logo.png",
                          "website": "https://shop.example"},
                "pisp": party,
                "execution_date": "2026-12-01",
                "amount_estimated": true,
                "amount_earmarked": false,
                "sct_inst": true,
                "recurrence": {
                    "start_date": "2026-01-01", "end_date": "2027-01-01", "number": 12,
                    "frequency": "MNTH",
                    "mit_options": {"amount_variable": true, "min_amount": 1, "max_amount": 100.5,
                                    "total_amount": 1000, "initial_amount": 5,
                                    "initial_amount_number": 2, "apr": 3.9}
                }
            })),
            Ok(()),
        ),
        row(
            "members the nested schemas leave open",
            PAYMENT,
            pay(json!({
                "payee": {"name": "Shop AB", "id": "SE1", "tags": ["a", null], "branch": {"city": "Malmö"}},
                "recurrence": {"frequency": "YEAR", "note": 1, "mit_options": {"cap": false}}
            })),
            Ok(()),
        ),
        row(
            "an open member nesting to MAX_DEPTH in the entry",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB", "id": "SE1", "x": nested(MAX_DEPTH - 3)}})),
            Ok(()),
        ),
        row(
            "an amount in exponent form",
            PAYMENT,
            pay(json!({"amount": 1e2})),
            Ok(()),
        ),
        row(
            "a recurrence number written with a zero fraction",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "WEEK", "number": 12.0}})),
            Ok(()),
        ),
        row(
            "a date_time that is no date: `format` is an annotation",
            PAYMENT,
            pay(json!({"date_time": "yesterday"})),
            Ok(()),
        ),
        row(
            "a transaction_id of 36 characters outside the BMP",
            PAYMENT,
            pay(json!({"transaction_id": chars('\u{1f600}', 36)})),
            Ok(()),
        ),
        row(
            "a payment without transaction_id",
            PAYMENT,
            pay(json!({"transaction_id": null})),
            MISSING,
        ),
        row(
            "an empty transaction_id",
            PAYMENT,
            pay(json!({"transaction_id": ""})),
            INVALID,
        ),
        row(
            "a transaction_id of 37 characters",
            PAYMENT,
            pay(json!({"transaction_id": chars('t', 37)})),
            INVALID,
        ),
        row(
            "a payment without payee",
            PAYMENT,
            pay(json!({"payee": null})),
            MISSING,
        ),
        row(
            "a payee that is a string",
            PAYMENT,
            pay(json!({"payee": "Shop"})),
            WRONG_TYPE,
        ),
        row(
            "a payee without id",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB"}})),
            MISSING,
        ),
        row(
            "an amount that is a string",
            PAYMENT,
            pay(json!({"amount": "49.99"})),
            WRONG_TYPE,
        ),
        row(
            "a payment without amount",
            PAYMENT,
            pay(json!({"amount": null})),
            MISSING,
        ),
        row(
            "a currency in lower case",
            PAYMENT,
            pay(json!({"currency": "eur"})),
            INVALID,
        ),
        row(
            "a currency of four letters",
            PAYMENT,
            pay(json!({"currency": "EURO"})),
            INVALID,
        ),
        row("a null date_time", PAYMENT, null_date_time(), WRONG_TYPE),
        row(
            "an amount_estimated that is a string",
            PAYMENT,
            pay(json!({"amount_estimated": "true"})),
            WRONG_TYPE,
        ),
        row(
            "a pisp without domain_name",
            PAYMENT,
            pay(json!({"pisp": {"legal_name": "PISP Ltd", "brand_name": "Pisp"}})),
            MISSING,
        ),
        row(
            "a recurrence without frequency",
            PAYMENT,
            pay(json!({"recurrence": {"number": 3}})),
            MISSING,
        ),
        row(
            "a frequency outside the enumeration",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "MONTHLY"}})),
            INVALID,
        ),
        row(
            "a recurrence number with a fraction",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "WEEK", "number": 2.5}})),
            WRONG_TYPE,
        ),
        row(
            "a mit_options amount that is a string",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "WEEK", "mit_options": {"min_amount": "1"}}})),
            WRONG_TYPE,
        ),
        row(
            "a payment member its schema does not define",
            PAYMENT,
            pay(json!({"note": "x"})),
            UNKNOWN,
        ),
        row(
            "a login",
            LOGIN,
            json!({"transaction_id": "t", "date_time": "2025-11-13T20:20:39+00:00",
                   "service": "Superbank Online Banking", "action": "Log in"}),
            Ok(()),
        ),
        row(
            "a login without action",
            LOGIN,
            json!({"transaction_id": "t"}),
            MISSING,
        ),
        row(
            "a login without transaction_id",
            LOGIN,
            json!({"action": "Log in"}),
            MISSING,
        ),
        row(
            "an action of 141 characters",
            LOGIN,
            json!({"transaction_id": "t", "action": chars('a', 141)}),
            INVALID,
        ),
        row(
            "a service of 101 characters",
            LOGIN,
            json!({"transaction_id": "t", "action": "Log in", "service": chars('s', 101)}),
            INVALID,
        ),
        row(
            "a login member its schema does not define",
            LOGIN,
            json!({"transaction_id": "t", "action": "Log in", "amount": 1}),
            UNKNOWN,
        ),
        row(
            "an account access",
            ACCESS,
            json!({"transaction_id": "t"}),
            Ok(()),
        ),
        row(
            "an account access through an AISP",
            ACCESS,
            json!({"transaction_id": "t", "aisp": party, "description": "Read the balance"}),
            Ok(()),
        ),
        row(
            "an account access without transaction_id",
            ACCESS,
            json!({}),
            MISSING,
        ),
        row(
            "an aisp without brand_name",
            ACCESS,
            json!({"transaction_id": "t", "aisp": {"legal_name": "A", "domain_name": "a.example"}}),
            MISSING,
        ),
        row(
            "a description of 141 characters",
            ACCESS,
            json!({"transaction_id": "t", "description": chars('d', 141)}),
            INVALID,
        ),
        row(
            "a mandate",
            MANDATE,
            json!({"transaction_id": "t", "start_date": "2026-01-01", "end_date": "2027-01-01",
                   "reference_number": "A-98765", "creditor_id": "FR14ZZZ001122334455",
                   "purpose": "Pay monthly bill"}),
            Ok(()),
        ),
        row(
            "a mandate without purpose or payment: the schema requires neither",
            MANDATE,
            json!({"transaction_id": "t"}),
            Ok(()),
        ),
        row(
            "a mandate with a payment",
            MANDATE,
            json!({"transaction_id": "t", "payment_payload": payment()}),
            Ok(()),
        ),
        row(
            "a mandate without transaction_id",
            MANDATE,
            json!({"purpose": "p"}),
            MISSING,
        ),
        row(
            "a mandate whose payment has a lower-case currency",
            MANDATE,
            json!({"transaction_id": "t", "payment_payload": pay(json!({"currency": "eur"}))}),
            INVALID,
        ),
        row(
            "a mandate whose payment has a member its schema does not define",
            MANDATE,
            json!({"transaction_id": "t", "payment_payload": pay(json!({"note": "x"}))}),
            UNKNOWN,
        ),
        row(
            "an empty reference_number",
            MANDATE,
            json!({"transaction_id": "t", "reference_number": ""}),
            INVALID,
        ),
        row(
            "a creditor_id of 51 characters",
            MANDATE,
            json!({"transaction_id": "t", "creditor_id": chars('c', 51)}),
            INVALID,
        ),
        row(
            "a purpose of 1001 characters",
            MANDATE,
            json!({"transaction_id": "t", "purpose": chars('p', 1001)}),
            INVALID,
        ),
    ]
}
