//! The pixels of an SVG length attribute in an absolute unit (SVG 1.1, Section 7.10; CSS 96
//! pixels per inch), exact in decimal: the number's digits times the unit's ratio, rounded up.

/// The pixels of the length `value`, rounded up and saturating at `u32::MAX`; `None` for an
/// absent attribute, a relative unit, no number, or a length of -1 pixel or less.
pub(super) fn pixels(value: Option<&str>) -> Option<u32> {
    let value = value?.trim();
    let split = value
        .find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '+' | '-' | 'e')))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at_checked(split)?;
    let unit = Unit::named(unit.trim())?;
    Decimal::parse(number)?.times(unit).round_up()
}

/// An absolute unit, as its pixels per `per` units.
#[derive(Clone, Copy)]
struct Unit {
    pixels: u64,
    per: u64,
}

impl Unit {
    /// The unit `name`; an empty name is the pixel.
    fn named(name: &str) -> Option<Self> {
        let (pixels, per) = match name {
            "" | "px" => (1, 1),
            "in" => (96, 1),
            // 96 / 2.54 and 96 / 25.4.
            "cm" => (4800, 127),
            "mm" => (480, 127),
            // 96 / 72.
            "pt" => (4, 3),
            "pc" => (16, 1),
            _ => return None,
        };
        Some(Self { pixels, per })
    }
}

/// The sign of a number.
#[derive(Clone, Copy)]
enum Sign {
    Plus,
    Minus,
}

/// The exponent beyond which every length saturates or vanishes.
const EXPONENT_CAP: i64 = 1_000_000;

/// A decimal number: `sign` 0.d₁d₂… × 10^`point`.
struct Decimal {
    sign: Sign,
    /// The digits, without leading or trailing zeros; empty for zero.
    digits: Vec<u8>,
    point: i64,
}

/// A length times its unit.
enum Scaled {
    /// At least 10¹² pixels.
    Huge(Sign),
    /// Of the sign, under one pixel, and above zero.
    Tiny(Sign),
    /// This many whole pixels, and whether a fraction remains.
    Pixels(Sign, u64, Remainder),
}

/// Whether a fraction remains of a division.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Remainder {
    None,
    Some,
}

impl Decimal {
    /// The number `text`, as Rust writes an `f64` without `inf` or `nan`: a sign, digits with
    /// at most one point, and an exponent after `e`.
    fn parse(text: &str) -> Option<Self> {
        let (sign, unsigned) = signed(text);
        let (mantissa, exponent) = match unsigned.split_once('e') {
            Some((mantissa, exponent)) => (mantissa, exponent_value(exponent)?),
            None => (unsigned, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if whole.len() + fraction.len() == 0 || !all_digits(whole) || !all_digits(fraction) {
            return None;
        }
        let point = i64::try_from(whole.len()).ok()?.saturating_add(exponent);
        let all: Vec<u8> = whole
            .bytes()
            .chain(fraction.bytes())
            .map(|b| b - b'0')
            .collect();
        let leading = all.iter().take_while(|&&d| d == 0).count();
        let digits: Vec<u8> = match all.iter().rposition(|&d| d != 0) {
            Some(last) => all.get(leading..=last)?.to_vec(),
            None => Vec::new(),
        };
        let point = point.saturating_sub(i64::try_from(leading).ok()?);
        Some(Self {
            sign,
            digits,
            point,
        })
    }

    /// The length in pixels of this number of `unit`.
    fn times(&self, unit: Unit) -> Scaled {
        if self.digits.is_empty() {
            return Scaled::Pixels(self.sign, 0, Remainder::None);
        }
        // A unit is at least 1 and at most 96 pixels: from 10¹² on, a length is huge, and under
        // 10⁻³ it is under one pixel.
        let (whole_digits, zeros) = match self.point {
            13.. => return Scaled::Huge(self.sign),
            ..=-3 => return Scaled::Tiny(self.sign),
            point => (point.clamp(0, 12) as usize, (-point).clamp(0, 2) as usize),
        };
        let whole = (0..whole_digits)
            .map(|at| self.digits.get(at).copied().unwrap_or(0))
            .fold(0_u64, |whole, digit| whole * 10 + u64::from(digit));
        // The fraction times the unit's pixels, from its last digit: the carry is the whole
        // pixels, and a digit left over is a fraction.
        let (carry, remainder) = self
            .digits
            .iter()
            .skip(whole_digits)
            .rev()
            .map(|&digit| u64::from(digit))
            .chain(std::iter::repeat_n(0, zeros))
            .fold((0_u64, Remainder::None), |(carry, remainder), digit| {
                let product = digit * unit.pixels + carry;
                let left = if product % 10 == 0 {
                    remainder
                } else {
                    Remainder::Some
                };
                (product / 10, left)
            });
        let scaled = whole * unit.pixels + carry;
        let remainder = if scaled % unit.per == 0 {
            remainder
        } else {
            Remainder::Some
        };
        Scaled::Pixels(self.sign, scaled / unit.per, remainder)
    }
}

impl Scaled {
    /// The pixels, rounded up and saturating at `u32::MAX`; `None` at -1 pixel or less.
    fn round_up(self) -> Option<u32> {
        match self {
            Self::Huge(Sign::Plus) => Some(u32::MAX),
            Self::Huge(Sign::Minus) => None,
            Self::Tiny(Sign::Plus) => Some(1),
            Self::Tiny(Sign::Minus) => Some(0),
            Self::Pixels(Sign::Plus, whole, remainder) => {
                let up = whole + u64::from(remainder == Remainder::Some);
                Some(u32::try_from(up).unwrap_or(u32::MAX))
            }
            Self::Pixels(Sign::Minus, 0, _) => Some(0),
            Self::Pixels(Sign::Minus, ..) => None,
        }
    }
}

/// The sign of `text` and the rest.
fn signed(text: &str) -> (Sign, &str) {
    match text.strip_prefix('-') {
        Some(rest) => (Sign::Minus, rest),
        None => (Sign::Plus, text.strip_prefix('+').unwrap_or(text)),
    }
}

/// Whether `text` holds ASCII digits only.
fn all_digits(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_digit())
}

/// The exponent `text`, a sign and at least one digit, within [`EXPONENT_CAP`].
fn exponent_value(text: &str) -> Option<i64> {
    let (sign, digits) = signed(text);
    if digits.is_empty() || !all_digits(digits) {
        return None;
    }
    let magnitude = digits.bytes().fold(0_i64, |magnitude, b| {
        (magnitude * 10 + i64::from(b - b'0')).min(EXPONENT_CAP)
    });
    Some(match sign {
        Sign::Plus => magnitude,
        Sign::Minus => -magnitude,
    })
}
