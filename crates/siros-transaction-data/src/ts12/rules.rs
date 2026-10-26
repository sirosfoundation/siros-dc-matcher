//! The value rules EC TS12 v1.0.1 states in prose (Sections 4.3.1 to 4.3.4), which its schemas
//! leave out.
//!
//! An `[ISO8601]` date or date and time is read in the profile JSON Schema names: RFC 3339
//! `full-date`, `YYYY-MM-DD`, and RFC 3339 `date-time`, with seconds and a UTC offset.

use siros_codec::base64;
use siros_codec::date::Date;

use crate::error::TransactionDataError;
use crate::json::{self, Json, Number};
use crate::ts12::currency::{minor_unit, Minor};

/// `value` as an ISO 8601 date (RFC 3339 `full-date`).
pub(crate) fn date(value: Json, path: &'static str) -> Result<Date, TransactionDataError> {
    Date::parse(&json::text(value, path)?).ok_or(TransactionDataError::InvalidValue(path))
}

/// `value` as an ISO 8601 date and time (RFC 3339 `date-time`).
pub(crate) fn date_time(value: Json, path: &'static str) -> Result<String, TransactionDataError> {
    let text = json::text(value, path)?;
    checked(is_date_time(&text), text, path)
}

/// `value` as an ISO 8601 date, or date and time.
pub(crate) fn date_or_date_time(
    value: Json,
    path: &'static str,
) -> Result<String, TransactionDataError> {
    let text = json::text(value, path)?;
    checked(
        Date::parse(&text).is_some() || is_date_time(&text),
        text,
        path,
    )
}

/// `value` as a domain name: dot-separated labels of 1 to 63 letters, digits and hyphens, no
/// label starting or ending with a hyphen, at most 253 characters (RFC 1123, Section 2.1). A
/// QWAC names its domain in a `dNSName`, of these characters only.
pub(crate) fn domain_name(value: Json, path: &'static str) -> Result<String, TransactionDataError> {
    let text = json::text(value, path)?;
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let valid = text.len() <= 253 && text.split('.').all(label);
    checked(valid, text, path)
}

/// `value` as a resolvable URL: `http` or `https`, with an authority, of visible ASCII
/// characters.
pub(crate) fn url(value: Json, path: &'static str) -> Result<String, TransactionDataError> {
    let text = json::text(value, path)?;
    checked(is_url(&text), text, path)
}

/// `value` as a resolvable URL or a `data` URL (RFC 2397).
pub(crate) fn image(value: Json, path: &'static str) -> Result<String, TransactionDataError> {
    let text = json::text(value, path)?;
    checked(is_url(&text) || is_data_url(&text), text, path)
}

/// `value` as an ISO 4217 alphabetic code.
pub(crate) fn currency(
    value: Json,
    path: &'static str,
) -> Result<(String, Minor), TransactionDataError> {
    let code = json::text(value, path)?;
    let minor = minor_unit(&code).ok_or(TransactionDataError::InvalidValue(path))?;
    Ok((code, minor))
}

/// `value` as an amount of a currency of minor unit `minor`: an optional minus, the major units,
/// and an optional decimal point with exactly the digits of the minor unit (Section 4.3.1,
/// `amount`). A currency without a minor unit takes no fraction.
pub(crate) fn amount(
    value: Json,
    path: &'static str,
    minor: Minor,
) -> Result<Number, TransactionDataError> {
    let number = json::number(value, path)?;
    let text = number.text();
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (major, fraction) = match unsigned.split_once('.') {
        Some((major, fraction)) => (major, Some(fraction)),
        None => (unsigned, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let fraction_fits = match (fraction, minor) {
        (None, _) => true,
        (Some(fraction), Minor::Digits(n)) => {
            n > 0 && digits(fraction) && fraction.len() == usize::from(n)
        }
        (Some(_), Minor::Undefined) => false,
    };
    if digits(major) && fraction_fits {
        Ok(number)
    } else {
        Err(TransactionDataError::InvalidValue(path))
    }
}

/// `text` when `valid`.
fn checked(valid: bool, text: String, path: &'static str) -> Result<String, TransactionDataError> {
    if valid {
        Ok(text)
    } else {
        Err(TransactionDataError::InvalidValue(path))
    }
}

/// RFC 3339 `date-time`: `full-date "T" hh:mm:ss [.digits] ("Z" / ("+" / "-") hh:mm)`, `T`
/// and `Z` in either case (Section 5.6).
fn is_date_time(text: &str) -> bool {
    let Some((date, rest)) = text.split_at_checked(10) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(['T', 't']).and_then(clock) else {
        return false;
    };
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => {
            let digits = fraction.bytes().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                return false;
            }
            fraction.get(digits..).unwrap_or_default()
        }
        None => rest,
    };
    Date::parse(date).is_some() && offset(rest)
}

/// What follows `hh:mm:ss` at the start of `text`. A second of 60 is a leap second (RFC 3339,
/// Section 5.7).
fn clock(text: &str) -> Option<&str> {
    let rest = two(text, 23)?;
    let rest = two(rest.strip_prefix(':')?, 59)?;
    two(rest.strip_prefix(':')?, 60)
}

/// Whether `text` is `Z`, or a sign and `hh:mm`.
fn offset(text: &str) -> bool {
    match text.strip_prefix(['+', '-']) {
        Some(rest) => {
            two(rest, 23)
                .and_then(|rest| rest.strip_prefix(':'))
                .and_then(|rest| two(rest, 59))
                == Some("")
        }
        None => text.eq_ignore_ascii_case("z"),
    }
}

/// What follows two digits of a value up to `max` at the start of `text`.
fn two(text: &str, max: u8) -> Option<&str> {
    let (digits, rest) = text.split_at_checked(2)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u8 = digits.parse().ok()?;
    (value <= max).then_some(rest)
}

/// `http://` or `https://` (any case), a non-empty authority, visible ASCII only.
fn is_url(text: &str) -> bool {
    let rest = ["https://", "http://"].iter().find_map(|scheme| {
        text.get(..scheme.len())
            .filter(|s| s.eq_ignore_ascii_case(scheme))
            .and_then(|_| text.get(scheme.len()..))
    });
    let authority = rest.and_then(|rest| rest.split(['/', '?', '#']).next());
    authority.is_some_and(|a| !a.is_empty()) && text.bytes().all(|b| b.is_ascii_graphic())
}

/// RFC 2397: `data:` (any case), a media type of `type/subtype` and `attribute=value`
/// parameters, an optional `;base64`, a comma, and the data: base64 after `;base64`, URL
/// characters otherwise.
fn is_data_url(text: &str) -> bool {
    let Some(rest) = text
        .get(..5)
        .filter(|s| s.eq_ignore_ascii_case("data:"))
        .and_then(|_| text.get(5..))
    else {
        return false;
    };
    let Some((header, data)) = rest.split_once(',') else {
        return false;
    };
    let parts: Vec<&str> = header.split(';').collect();
    let (base64, parts) = match parts.split_last() {
        Some((last, rest)) if !rest.is_empty() && last.eq_ignore_ascii_case("base64") => {
            (true, rest)
        }
        _ => (false, parts.as_slice()),
    };
    // RFC 2045, Section 5.1: a token holds no space, control or tspecial.
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b))
    };
    let media_type = match parts.split_first() {
        Some((media_type, parameters)) => {
            let kind = media_type.is_empty()
                || matches!(media_type.split_once('/'), Some((t, s)) if token(t) && token(s));
            kind && parameters.iter().all(|p| {
                matches!(p.split_once('='), Some((attribute, value)) if token(attribute) && !value.is_empty())
            })
        }
        None => true,
    };
    let data_fits = if base64 {
        base64::decode(data).is_some()
    } else {
        data.bytes().all(|b| b.is_ascii_graphic())
    };
    media_type && data_fits && header.bytes().all(|b| b.is_ascii_graphic())
}
