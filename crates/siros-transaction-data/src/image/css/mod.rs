//! The CSS of an SVG document: a `<style>` element, a `style` attribute, or a presentation
//! attribute, read with the tokenizer of CSS Syntax Module Level 3, Section 4. Only an allowed
//! subset passes: the at-rules `@charset`, `@font-face` and `@media`, and the functions of
//! colours, maths, transforms, gradients, filters and selectors. The URLs it names are those of
//! url tokens and the strings inside the functions that take URLs. A custom property holds no
//! string and no URL, and no `var()` stands inside a function that takes URLs: a substituted
//! value reaches the renderer unchecked.

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
const PLAIN_FUNCTIONS: [&str; 59] = [
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
    "rect",
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

/// The at-rules that pass: the encoding, font faces, whose `src` names its URLs by url tokens,
/// and media queries.
const AT_RULES: [&str; 3] = ["charset", "font-face", "media"];

/// What the CSS of an SVG document holds that the check refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CssFault {
    /// An at-rule other than `@charset`, `@font-face` and `@media`, `@import` included.
    AtRule(String),
    /// A function the check does not know, by its name as written after its escapes.
    Function(String),
    /// A `var()` inside a function that takes URLs.
    UrlVariable,
    /// The custom property of this name holds a string or a URL, which a `var()` carries into
    /// any function.
    CustomProperty(String),
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
            Self::UrlVariable => "svg_css_url_variable",
            Self::CustomProperty(_) => "svg_css_custom_property",
            Self::Unreadable => "svg_css_unreadable",
        }
    }
}

siros_codec::display_code!(CssFault);

impl std::error::Error for CssFault {}

/// An open block (CSS Syntax 3, Section 5.4.8): each closes only by its mirror token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    /// A function that takes URLs.
    Urls,
    /// A function that takes none, or a parenthesis.
    Plain,
    /// A square bracket.
    Square,
    /// A curly bracket.
    Curly,
}

/// The URLs the CSS text `css` names, in order.
///
/// # Errors
///
/// [`CssFault`]: the first token the check refuses.
pub(super) fn urls(css: &str) -> Result<Vec<String>, CssFault> {
    let mut found = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    let mut custom = Custom::Outside;
    for token in tokens(css) {
        let in_urls = blocks.contains(&Block::Urls);
        custom = custom.next(&token, blocks.len())?;
        match token {
            Token::AtKeyword(name) => {
                if !AT_RULES.iter().any(|rule| rule.eq_ignore_ascii_case(&name)) {
                    return Err(CssFault::AtRule(name));
                }
            }
            Token::Function(name) => {
                if name.eq_ignore_ascii_case("var") && in_urls {
                    return Err(CssFault::UrlVariable);
                }
                if named(&URL_FUNCTIONS, &name) {
                    blocks.push(Block::Urls);
                } else if named(&PLAIN_FUNCTIONS, &name) {
                    blocks.push(Block::Plain);
                } else {
                    return Err(CssFault::Function(name));
                }
            }
            Token::OpenParen => blocks.push(Block::Plain),
            Token::OpenSquare => blocks.push(Block::Square),
            Token::OpenCurly => blocks.push(Block::Curly),
            Token::CloseParen => close(&mut blocks, &[Block::Urls, Block::Plain]),
            Token::CloseSquare => close(&mut blocks, &[Block::Square]),
            Token::CloseCurly => close(&mut blocks, &[Block::Curly]),
            Token::Url(url) => found.push(url),
            Token::String(text) if in_urls => found.push(text),
            Token::BadString | Token::BadUrl => return Err(CssFault::Unreadable),
            Token::Ident(_)
            | Token::Hash
            | Token::String(_)
            | Token::Delim
            | Token::Numeric
            | Token::UnicodeRange
            | Token::Whitespace
            | Token::Cdo
            | Token::Cdc
            | Token::Colon
            | Token::Semicolon
            | Token::Comma => {}
        }
        custom = custom.closed(blocks.len());
    }
    Ok(found)
}

/// Whether `list` names the function `name`, without regard to ASCII case.
fn named(list: &[&str], name: &str) -> bool {
    list.iter()
        .any(|function| function.eq_ignore_ascii_case(name))
}

/// Closes the innermost block when it is one of `kinds`; a closing token of another kind is a
/// value inside it.
fn close(blocks: &mut Vec<Block>, kinds: &[Block]) {
    if let Some(last) = blocks.pop() {
        if !kinds.contains(&last) {
            blocks.push(last);
        }
    }
}

/// Where the tokens stand relative to a custom property declaration (CSS Variables 1, Section
/// 2): its name, then its colon, then its value up to the `;` at its depth or the end of its
/// block.
enum Custom {
    Outside,
    /// The name `--…` at the block depth, before the colon.
    Named(String, usize),
    /// The value of the property of the name, declared at the block depth.
    Value(String, usize),
}

impl Custom {
    /// The state after `token`, read at block depth `depth`.
    ///
    /// # Errors
    ///
    /// [`CssFault::CustomProperty`] for a string, a url token or a function that takes URLs
    /// inside a custom property's value.
    fn next(self, token: &Token, depth: usize) -> Result<Self, CssFault> {
        Ok(match (self, token) {
            (Self::Value(name, _), Token::String(_) | Token::Url(_)) => {
                return Err(CssFault::CustomProperty(name))
            }
            (Self::Value(name, _), Token::Function(function))
                if named(&URL_FUNCTIONS, function) =>
            {
                return Err(CssFault::CustomProperty(name))
            }
            (Self::Value(_, at), Token::Semicolon) if at == depth => Self::Outside,
            (value @ Self::Value(..), _) => value,
            (Self::Named(name, at), Token::Colon) if at == depth => Self::Value(name, at),
            (named @ Self::Named(..), Token::Whitespace) => named,
            (_, Token::Ident(name)) if name.starts_with("--") => Self::Named(name.clone(), depth),
            (Self::Outside | Self::Named(..), _) => Self::Outside,
        })
    }

    /// The state once the block depth is `depth`: a value ends with the block it stands in.
    fn closed(self, depth: usize) -> Self {
        match self {
            Self::Value(_, at) | Self::Named(_, at) if depth < at => Self::Outside,
            other => other,
        }
    }
}
