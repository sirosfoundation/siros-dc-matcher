//! The tokenizer of CSS Syntax Module Level 3, Section 4: the input preprocessed (Section 3.3),
//! comments consumed, escapes decoded, strings, url tokens and functions told apart. It also
//! reads the unicode-range token of the 2014 Candidate Recommendation (Section 4.3.7), which
//! WebKit keeps: a `url(` after one is a url token there.

/// A token of Section 4. Numbers keep no value: the check reads names, strings and URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Token {
    Ident(String),
    Function(String),
    AtKeyword(String),
    Hash,
    String(String),
    BadString,
    Url(String),
    BadUrl,
    Delim,
    Numeric,
    UnicodeRange,
    Whitespace,
    Cdo,
    Cdc,
    Colon,
    Semicolon,
    Comma,
    OpenSquare,
    CloseSquare,
    OpenParen,
    CloseParen,
    OpenCurly,
    CloseCurly,
}

/// The tokens of `css`.
pub(super) fn tokens(css: &str) -> Vec<Token> {
    let mut input = Input::new(css);
    std::iter::from_fn(|| input.token()).collect()
}

/// The preprocessed code points and the position of the next one.
struct Input {
    chars: Vec<char>,
    at: usize,
}

impl Input {
    /// `css` preprocessed: CR LF, CR and FF as LF, and NUL as U+FFFD (Section 3.3).
    fn new(css: &str) -> Self {
        let mut chars = Vec::with_capacity(css.len());
        let mut after_cr = false;
        for c in css.chars() {
            match c {
                // The CR before it gave the LF.
                '\n' if after_cr => {}
                '\r' | '\u{c}' => chars.push('\n'),
                '\0' => chars.push('\u{fffd}'),
                other => chars.push(other),
            }
            after_cr = c == '\r';
        }
        Self { chars, at: 0 }
    }

    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        Some(c)
    }

    /// Consumes a token (Section 4.3.1), comments first; `None` at the end.
    fn token(&mut self) -> Option<Token> {
        self.comments();
        let c = self.next()?;
        Some(match c {
            c if whitespace(c) => {
                while self.peek(0).is_some_and(whitespace) {
                    self.at += 1;
                }
                Token::Whitespace
            }
            '"' | '\'' => self.string(c),
            '#' => {
                if self.peek(0).is_some_and(ident_code_point) || self.escape_at(0) {
                    drop(self.ident_sequence());
                    Token::Hash
                } else {
                    Token::Delim
                }
            }
            '(' => Token::OpenParen,
            ')' => Token::CloseParen,
            ',' => Token::Comma,
            ':' => Token::Colon,
            ';' => Token::Semicolon,
            '[' => Token::OpenSquare,
            ']' => Token::CloseSquare,
            '{' => Token::OpenCurly,
            '}' => Token::CloseCurly,
            '+' | '.' if self.starts_number(-1) => self.numeric(),
            '-' if self.starts_number(-1) => self.numeric(),
            '-' if self.peek(0) == Some('-') && self.peek(1) == Some('>') => {
                self.at += 2;
                Token::Cdc
            }
            '-' if self.starts_ident(-1) => {
                self.at -= 1;
                self.ident_like()
            }
            '<' if self.peek(0) == Some('!')
                && self.peek(1) == Some('-')
                && self.peek(2) == Some('-') =>
            {
                self.at += 3;
                Token::Cdo
            }
            '@' if self.starts_ident(0) => Token::AtKeyword(self.ident_sequence()),
            '\\' if self.escape_at(-1) => {
                self.at -= 1;
                self.ident_like()
            }
            c if c.is_ascii_digit() => {
                self.at -= 1;
                self.numeric()
            }
            c if ident_start(c) => self.ident_or_range(c),
            _ => Token::Delim,
        })
    }

    /// The token at the name-start code point `c`, just consumed: a unicode-range token at `U+`
    /// and a hex digit or `?`, else an ident-like token.
    fn ident_or_range(&mut self, c: char) -> Token {
        let range = matches!(c, 'u' | 'U')
            && self.peek(0) == Some('+')
            && self
                .peek(1)
                .is_some_and(|c| c.is_ascii_hexdigit() || c == '?');
        if range {
            self.at += 1;
            self.unicode_range();
            Token::UnicodeRange
        } else {
            self.at -= 1;
            self.ident_like()
        }
    }

    /// Consumes a unicode-range token after its `U+`: up to 6 hex digits, then `?` up to 6 code
    /// points, or else a `-` and up to 6 hex digits of the range's end.
    fn unicode_range(&mut self) {
        let digits = self.hex_run(6);
        self.at += digits;
        let mut questions = 0;
        while digits + questions < 6 && self.peek(questions) == Some('?') {
            questions += 1;
        }
        self.at += questions;
        if questions == 0
            && self.peek(0) == Some('-')
            && self.peek(1).is_some_and(|c| c.is_ascii_hexdigit())
        {
            self.at += 1;
            self.at += self.hex_run(6);
        }
    }

    /// The count of hex digits from here, at most `most`.
    fn hex_run(&self, most: usize) -> usize {
        (0..most)
            .take_while(|&ahead| self.peek(ahead).is_some_and(|c| c.is_ascii_hexdigit()))
            .count()
    }

    /// Consumes the comments here (Section 4.3.2); an unterminated one runs to the end.
    fn comments(&mut self) {
        while self.peek(0) == Some('/') && self.peek(1) == Some('*') {
            self.at += 2;
            while self.peek(0).is_some()
                && !(self.peek(0) == Some('*') && self.peek(1) == Some('/'))
            {
                self.at += 1;
            }
            self.at = (self.at + 2).min(self.chars.len());
        }
    }

    /// Whether the code point at `offset` from the next one and its follower are a valid escape
    /// (Section 4.3.8).
    fn escape_at(&self, offset: isize) -> bool {
        let at = |o: isize| {
            self.at
                .checked_add_signed(offset + o)
                .and_then(|i| self.chars.get(i))
                .copied()
        };
        at(0) == Some('\\') && at(1).is_some_and(|c| c != '\n')
    }

    /// Whether the three code points from `offset` start an ident sequence (Section 4.3.9).
    fn starts_ident(&self, offset: isize) -> bool {
        let at = |o: isize| {
            self.at
                .checked_add_signed(offset + o)
                .and_then(|i| self.chars.get(i))
                .copied()
        };
        match at(0) {
            Some('-') => {
                at(1).is_some_and(|c| ident_start(c) || c == '-') || self.escape_at(offset + 1)
            }
            Some('\\') => self.escape_at(offset),
            Some(c) => ident_start(c),
            None => false,
        }
    }

    /// Whether the three code points from `offset` start a number (Section 4.3.10).
    fn starts_number(&self, offset: isize) -> bool {
        let at = |o: isize| {
            self.at
                .checked_add_signed(offset + o)
                .and_then(|i| self.chars.get(i))
                .copied()
        };
        let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
        match at(0) {
            Some('+' | '-') => digit(at(1)) || (at(1) == Some('.') && digit(at(2))),
            Some('.') => digit(at(1)),
            c => digit(c),
        }
    }

    /// Consumes an escaped code point after its backslash (Section 4.3.7).
    fn escaped(&mut self) -> char {
        let Some(c) = self.next() else {
            return '\u{fffd}';
        };
        let Some(first) = c.to_digit(16) else {
            return c;
        };
        let mut value = first;
        for _ in 0..5 {
            match self.peek(0).and_then(|c| c.to_digit(16)) {
                Some(digit) => {
                    value = value * 16 + digit;
                    self.at += 1;
                }
                None => break,
            }
        }
        if self.peek(0).is_some_and(whitespace) {
            self.at += 1;
        }
        match char::from_u32(value) {
            Some(c) if value != 0 => c,
            _ => '\u{fffd}',
        }
    }

    /// Consumes an ident sequence (Section 4.3.11).
    fn ident_sequence(&mut self) -> String {
        let mut name = String::new();
        loop {
            match self.peek(0) {
                Some(c) if ident_code_point(c) => {
                    name.push(c);
                    self.at += 1;
                }
                Some('\\') if self.escape_at(0) => {
                    self.at += 1;
                    name.push(self.escaped());
                }
                _ => return name,
            }
        }
    }

    /// Consumes an ident-like token (Section 4.3.4): an ident, a function, or a url token.
    fn ident_like(&mut self) -> Token {
        let name = self.ident_sequence();
        if self.peek(0) != Some('(') {
            return Token::Ident(name);
        }
        self.at += 1;
        if !name.eq_ignore_ascii_case("url") {
            return Token::Function(name);
        }
        while self.peek(0).is_some_and(whitespace) && self.peek(1).is_some_and(whitespace) {
            self.at += 1;
        }
        let quote = |c: Option<char>| matches!(c, Some('"' | '\''));
        if quote(self.peek(0)) || (self.peek(0).is_some_and(whitespace) && quote(self.peek(1))) {
            Token::Function(name)
        } else {
            self.url()
        }
    }

    /// Consumes a string token ending at `quote` (Section 4.3.5).
    fn string(&mut self, quote: char) -> Token {
        let mut text = String::new();
        loop {
            match self.next() {
                None => return Token::String(text),
                Some(c) if c == quote => return Token::String(text),
                Some('\n') => {
                    self.at -= 1;
                    return Token::BadString;
                }
                Some('\\') => match self.peek(0) {
                    None => {}
                    Some('\n') => self.at += 1,
                    Some(_) => text.push(self.escaped()),
                },
                Some(c) => text.push(c),
            }
        }
    }

    /// Consumes a url token after `url(` (Section 4.3.6).
    fn url(&mut self) -> Token {
        let mut text = String::new();
        while self.peek(0).is_some_and(whitespace) {
            self.at += 1;
        }
        loop {
            match self.next() {
                None | Some(')') => return Token::Url(text),
                Some(c) if whitespace(c) => {
                    while self.peek(0).is_some_and(whitespace) {
                        self.at += 1;
                    }
                    return match self.next() {
                        None | Some(')') => Token::Url(text),
                        Some(_) => self.bad_url(),
                    };
                }
                Some('"' | '\'' | '(') => return self.bad_url(),
                Some(c) if non_printable(c) => return self.bad_url(),
                Some('\\') if self.escape_at(-1) => text.push(self.escaped()),
                Some('\\') => return self.bad_url(),
                Some(c) => text.push(c),
            }
        }
    }

    /// Consumes the remnants of a bad url (Section 4.3.14).
    fn bad_url(&mut self) -> Token {
        loop {
            match self.next() {
                None | Some(')') => return Token::BadUrl,
                Some('\\') if self.escape_at(-1) => drop(self.escaped()),
                Some(_) => {}
            }
        }
    }

    /// Consumes a numeric token (Section 4.3.3): a number, a percentage or a dimension.
    fn numeric(&mut self) -> Token {
        if matches!(self.peek(0), Some('+' | '-')) {
            self.at += 1;
        }
        self.digits();
        if self.peek(0) == Some('.') && self.peek(1).is_some_and(|c| c.is_ascii_digit()) {
            self.at += 1;
            self.digits();
        }
        let exponent_digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
        if matches!(self.peek(0), Some('e' | 'E'))
            && (exponent_digit(self.peek(1))
                || (matches!(self.peek(1), Some('+' | '-')) && exponent_digit(self.peek(2))))
        {
            self.at += 2;
            self.digits();
        }
        if self.starts_ident(0) {
            drop(self.ident_sequence());
        } else if self.peek(0) == Some('%') {
            self.at += 1;
        }
        Token::Numeric
    }

    fn digits(&mut self) {
        while self.peek(0).is_some_and(|c| c.is_ascii_digit()) {
            self.at += 1;
        }
    }
}

/// A newline, a tab or a space (Section 4.2).
fn whitespace(c: char) -> bool {
    matches!(c, '\n' | '\t' | ' ')
}

/// A letter, a non-ASCII code point or `_` (Section 4.2).
fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || !c.is_ascii() || c == '_'
}

/// An ident-start code point, a digit or `-` (Section 4.2).
fn ident_code_point(c: char) -> bool {
    ident_start(c) || c.is_ascii_digit() || c == '-'
}

/// U+0000 to U+0008, U+000B, U+000E to U+001F, or U+007F (Section 4.2).
fn non_printable(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{8}' | '\u{b}' | '\u{e}'..='\u{1f}' | '\u{7f}')
}
