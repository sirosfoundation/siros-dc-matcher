//! Card colours: the numerical colour values of CSS Color Module Level 3, Section 4.2.

use crate::error::DisplayError;

/// An sRGB colour with its opacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Colour {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
}

impl Colour {
    /// The colour of a numerical colour value: `#rgb`, `#rrggbb`, `rgb()`, `rgba()`, `hsl()` or
    /// `hsla()` (CSS Color Module Level 3, Sections 4.2.1 to 4.2.5). Components outside their
    /// range are clipped to it, as Section 4.2 requires.
    ///
    /// # Errors
    ///
    /// [`DisplayError::Colour`] for text of none of these forms.
    pub fn parse(text: &str) -> Result<Self, DisplayError> {
        let text = text.trim();
        let parsed = match text.strip_prefix('#') {
            Some(hex) => hexadecimal(hex),
            None => functional(text),
        };
        parsed.ok_or(DisplayError::Colour)
    }

    /// The red component.
    pub fn red(&self) -> u8 {
        self.red
    }

    /// The green component.
    pub fn green(&self) -> u8 {
        self.green
    }

    /// The blue component.
    pub fn blue(&self) -> u8 {
        self.blue
    }

    /// The opacity, from 0 (transparent) to 255 (opaque).
    pub fn alpha(&self) -> u8 {
        self.alpha
    }
}

fn opaque(red: u8, green: u8, blue: u8) -> Colour {
    Colour {
        red,
        green,
        blue,
        alpha: u8::MAX,
    }
}

/// `#rgb`, each digit repeated, or `#rrggbb`.
fn hexadecimal(hex: &str) -> Option<Colour> {
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let digit = |at: usize| {
        hex.get(at..=at)
            .and_then(|d| u8::from_str_radix(d, 16).ok())
    };
    let pair = |at: usize| {
        hex.get(at..at + 2)
            .and_then(|d| u8::from_str_radix(d, 16).ok())
    };
    match hex.len() {
        3 => Some(opaque(digit(0)? * 17, digit(1)? * 17, digit(2)? * 17)),
        6 => Some(opaque(pair(0)?, pair(2)?, pair(4)?)),
        _ => None,
    }
}

/// `rgb(…)`, `rgba(…)`, `hsl(…)` or `hsla(…)`, the name in any ASCII case.
fn functional(text: &str) -> Option<Colour> {
    let open = text.find('(')?;
    let name = text.get(..open)?.to_ascii_lowercase();
    let inner = text.get(open + 1..)?.strip_suffix(')')?;
    let args: Vec<&str> = inner.split(',').map(str::trim).collect();
    let (colour, alpha) = match (name.as_str(), args.as_slice()) {
        ("rgb", [r, g, b]) => (rgb(r, g, b)?, None),
        ("rgba", [r, g, b, a]) => (rgb(r, g, b)?, Some(*a)),
        ("hsl", [h, s, l]) => (hsl(h, s, l)?, None),
        ("hsla", [h, s, l, a]) => (hsl(h, s, l)?, Some(*a)),
        _ => return None,
    };
    let alpha = match alpha {
        None => u8::MAX,
        Some(a) => channel(number(a)?.clamp(0.0, 1.0)),
    };
    Some(Colour { alpha, ..colour })
}

/// Three integers, or three percentages (Section 4.2.1).
fn rgb(r: &str, g: &str, b: &str) -> Option<Colour> {
    let parts = [r, g, b];
    let values: Vec<f64> = if parts.iter().all(|p| p.ends_with('%')) {
        parts
            .iter()
            .map(|p| percentage(p).map(|v| v.clamp(0.0, 1.0) * 255.0))
            .collect::<Option<_>>()?
    } else {
        parts
            .iter()
            .map(|p| integer(p).map(|v| v.clamp(0.0, 255.0)))
            .collect::<Option<_>>()?
    };
    match values.as_slice() {
        [r, g, b] => Some(opaque(rounded(*r), rounded(*g), rounded(*b))),
        _ => None,
    }
}

/// A hue in degrees, then saturation and lightness as percentages (Section 4.2.4).
fn hsl(h: &str, s: &str, l: &str) -> Option<Colour> {
    let hue = number(h)?;
    let saturation = percentage(s)?.clamp(0.0, 1.0);
    let lightness = percentage(l)?.clamp(0.0, 1.0);
    // The HSL-to-RGB conversion of Section 4.2.4, with the hue in degrees.
    let m2 = if lightness <= 0.5 {
        lightness * (saturation + 1.0)
    } else {
        lightness + saturation - lightness * saturation
    };
    let m1 = lightness * 2.0 - m2;
    let component = |h: f64| channel(hue_to_rgb(m1, m2, h));
    Some(opaque(
        component(hue + 120.0),
        component(hue),
        component(hue - 120.0),
    ))
}

fn hue_to_rgb(m1: f64, m2: f64, degrees: f64) -> f64 {
    let h = degrees.rem_euclid(360.0);
    if h < 60.0 {
        m1 + (m2 - m1) * h / 60.0
    } else if h < 180.0 {
        m2
    } else if h < 240.0 {
        m1 + (m2 - m1) * (240.0 - h) / 60.0
    } else {
        m1
    }
}

/// `value` of 0 to 1 as 0 to 255.
fn channel(value: f64) -> u8 {
    rounded(value * 255.0)
}

/// `value` of 0 to 255, to the nearest integer.
fn rounded(value: f64) -> u8 {
    // The value is clamped to 0 to 255 first, so the conversion is exact.
    value.round().clamp(0.0, 255.0) as u8
}

/// A CSS `<integer>`: an optional sign and decimal digits.
fn integer(text: &str) -> Option<f64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    let valid = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    valid.then(|| text.parse().ok()).flatten()
}

/// A CSS `<number>`: an optional sign, digits, and an optional fraction with at least one digit
/// after the point.
fn number(text: &str) -> Option<f64> {
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, "1"));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let valid = !unsigned.is_empty() && digits(whole) && !fraction.is_empty() && digits(fraction);
    valid.then(|| text.parse().ok()).flatten()
}

/// A CSS `<percentage>` as a fraction of one.
fn percentage(text: &str) -> Option<f64> {
    number(text.strip_suffix('%')?).map(|p| p / 100.0)
}
