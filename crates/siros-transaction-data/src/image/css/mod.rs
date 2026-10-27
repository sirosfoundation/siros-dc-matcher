//! The CSS of an SVG document: a `<style>` element, a `style` attribute, or a presentation
//! attribute, read with the tokenizer of CSS Syntax Module Level 3, Section 4. Only an allowed
//! subset passes: the at-rules `@font-face` and `@media`, and the functions of colours, maths,
//! transforms, gradients, filters and selectors. The URLs it names are those of url tokens and
//! the strings of the functions that take URLs.

mod tokens;

use tokens::{tokens, Token};

/// The functions whose strings and url tokens are URLs (CSS Values 4, Section 4.5; CSS Images
/// 4, Sections 2.2 to 2.4; CSS Fonts 4, Section 4.3).
const URL_FUNCTIONS: [&str; 7] = [
    "url",
    "src",
    "image",
    "image-set",
    "-webkit-image-set",
    "cross-fade",
    "-webkit-cross-fade",
];

/// The functions that take no URL: colours, maths, transforms, gradients, filters, timing,
/// font sources by name and format, and selectors.
const PLAIN_FUNCTIONS: [&str; 58] = [
    "rgb",
    "rgba",
    "hsl",
    "hsla",
    "hwb",
    "lab",
    "lch",
    "oklab",
    "oklch",
    "color",
    "color-mix",
    "calc",
    "min",
    "max",
    "clamp",
    "var",
    "translate",
    "translatex",
    "translatey",
    "translate3d",
    "rotate",
    "rotatex",
    "rotatey",
    "rotatez",
    "scale",
    "scalex",
    "scaley",
    "skew",
    "skewx",
    "skewy",
    "matrix",
    "linear-gradient",
    "radial-gradient",
    "conic-gradient",
    "repeating-linear-gradient",
    "repeating-radial-gradient",
    "repeating-conic-gradient",
    "blur",
    "brightness",
    "contrast",
    "drop-shadow",
    "grayscale",
    "hue-rotate",
    "invert",
    "opacity",
    "saturate",
    "sepia",
    "cubic-bezier",
    "steps",
    "local",
    "format",
    "not",
    "is",
    "where",
    "nth-child",
    "nth-last-child",
    "nth-of-type",
    "nth-last-of-type",
];

/// The at-rules that pass: font faces, whose `src` names its URLs by url tokens, and media
/// queries.
const AT_RULES: [&str; 2] = ["font-face", "media"];

/// What the CSS of an SVG document holds that the check refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CssFault {
    /// An at-rule other than `@font-face` and `@media`, `@import` included.
    AtRule(String),
    /// A function the check does not know, by its name as written after its escapes.
    Function(String),
    /// A bad string or a bad url token (CSS Syntax 3, Sections 4.3.5 and 4.3.6).
    Unreadable,
}

impl CssFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AtRule(_) => "svg_css_at_rule",
            Self::Function(_) => "svg_css_function",
            Self::Unreadable => "svg_css_unreadable",
        }
    }
}

siros_codec::display_code!(CssFault);

impl std::error::Error for CssFault {}

/// Whether a parenthesised block is a function that takes URLs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    Urls,
    Plain,
}

/// The URLs the CSS text `css` names, in order.
///
/// # Errors
///
/// [`CssFault`]: the first token the check refuses.
pub(super) fn urls(css: &str) -> Result<Vec<String>, CssFault> {
    let mut found = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    for token in tokens(css) {
        match token {
            Token::AtKeyword(name) => {
                if !AT_RULES.iter().any(|rule| rule.eq_ignore_ascii_case(&name)) {
                    return Err(CssFault::AtRule(name));
                }
            }
            Token::Function(name) => {
                let named = |list: &[&str]| list.iter().any(|f| f.eq_ignore_ascii_case(&name));
                if named(&URL_FUNCTIONS) {
                    blocks.push(Block::Urls);
                } else if named(&PLAIN_FUNCTIONS) {
                    blocks.push(Block::Plain);
                } else {
                    return Err(CssFault::Function(name));
                }
            }
            Token::OpenParen => blocks.push(Block::Plain),
            Token::CloseParen => drop(blocks.pop()),
            Token::Url(url) => found.push(url),
            Token::String(text) if blocks.last() == Some(&Block::Urls) => found.push(text),
            Token::BadString | Token::BadUrl => return Err(CssFault::Unreadable),
            Token::Ident(_)
            | Token::Hash
            | Token::String(_)
            | Token::Delim
            | Token::Numeric
            | Token::Whitespace
            | Token::Cdo
            | Token::Cdc
            | Token::Colon
            | Token::Semicolon
            | Token::Comma
            | Token::OpenSquare
            | Token::CloseSquare
            | Token::OpenCurly
            | Token::CloseCurly => {}
        }
    }
    Ok(found)
}
