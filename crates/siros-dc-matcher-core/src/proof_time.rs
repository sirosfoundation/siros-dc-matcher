//! `proof_time` of a `zkp_req` presentation: the 20-byte rendering, and the
//! verifier's tolerance check.
//!
//! The rulebook's `proof_time` is a CBOR `tdate` (tag 0) chosen by the prover
//! and used by the system for validity checks. A Longfellow circuit takes it
//! as a public input of exactly 20 ASCII bytes, `YYYY-MM-DDThh:mm:ssZ`
//! (second precision, no fractional seconds, always `Z`), so the verifier
//! assembles the same bytes from the value in the presentation. This module
//! renders and parses that exact form and implements the tolerance check the
//! rulebook leaves to the Verifier ("MUST reject if `proof_time` deviates from
//! its own clock by more than its tolerance").
//!
//! The recommended defaults are 60 s into the future and 600 s into the past.
//! They are recommendations, not protocol constants: pass your own.

#![deny(missing_docs)]

/// Length in bytes of the exact form.
pub const LEN: usize = 20;

/// The largest second that renders in four year digits: 9999-12-31T23:59:59Z.
pub const MAX_SECS: i64 = 253_402_300_799;

/// Recommended tolerance for a `proof_time` ahead of the verifier's clock.
pub const RECOMMENDED_SKEW_SECS: i64 = 60;

/// Recommended bound on how far a `proof_time` may lag the verifier's clock.
pub const RECOMMENDED_MAX_AGE_SECS: i64 = 600;

/// Why a `proof_time` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum InvalidProofTime {
    /// Not exactly `YYYY-MM-DDThh:mm:ssZ`: wrong length, separators, digits,
    /// a lowercase `t` or `z`, an offset, or fractional seconds.
    Form,
    /// The right form, but not a real UTC instant (month 13, 30 February,
    /// hour 24, second 60).
    NotAnInstant,
    /// Seconds outside `0..=MAX_SECS` cannot be rendered.
    OutOfRange,
    /// Later than the verifier's clock plus the skew.
    InFuture,
    /// Earlier than the verifier's clock minus the maximum age.
    TooOld,
}

impl InvalidProofTime {
    /// A stable identifier shared with the conformance vectors.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Form => "proof_time_form",
            Self::NotAnInstant => "proof_time_not_an_instant",
            Self::OutOfRange => "proof_time_out_of_range",
            Self::InFuture => "proof_time_in_future",
            Self::TooOld => "proof_time_too_old",
        }
    }
}

/// Render seconds since the Unix epoch (UTC) as the 20-byte form.
///
/// # Errors
///
/// [`InvalidProofTime::OutOfRange`] outside `0..=MAX_SECS`.
pub fn render(secs: i64) -> Result<String, InvalidProofTime> {
    if !(0..=MAX_SECS).contains(&secs) {
        return Err(InvalidProofTime::OutOfRange);
    }
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Parse the exact 20-byte form to seconds since the Unix epoch.
///
/// # Errors
///
/// [`InvalidProofTime::Form`] or [`InvalidProofTime::NotAnInstant`].
pub fn parse(text: &str) -> Result<i64, InvalidProofTime> {
    let b = text.as_bytes();
    if b.len() != LEN {
        return Err(InvalidProofTime::Form);
    }
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    for (c, s) in b.iter().zip(shape) {
        let ok = if *s == b'd' {
            c.is_ascii_digit()
        } else {
            c == s
        };
        if !ok {
            return Err(InvalidProofTime::Form);
        }
    }
    let num = |from: usize, to: usize| -> Option<i64> { text.get(from..to)?.parse().ok() };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    ) else {
        return Err(InvalidProofTime::Form);
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(InvalidProofTime::NotAnInstant),
    };
    if !(1..=month_days).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return Err(InvalidProofTime::NotAnInstant);
    }
    Ok(crate::zkp_req::days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// The verifier's tolerance check of a `proof_time` against its own clock.
///
/// Accepts `now - max_age_secs <= proof_time <= now + skew_secs`, both bounds
/// inclusive. `proof_time` must be the exact 20-byte form.
///
/// # Errors
///
/// Any [`InvalidProofTime`].
pub fn check_tolerance(
    proof_time: &str,
    now_secs: i64,
    skew_secs: i64,
    max_age_secs: i64,
) -> Result<(), InvalidProofTime> {
    let t = parse(proof_time)?;
    if t > now_secs.saturating_add(skew_secs) {
        Err(InvalidProofTime::InFuture)
    } else if t < now_secs.saturating_sub(max_age_secs) {
        Err(InvalidProofTime::TooOld)
    } else {
        Ok(())
    }
}
