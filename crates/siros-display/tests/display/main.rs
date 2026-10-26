//! The tests of siros-display, in one binary.

#[cfg(feature = "credential")]
mod known_answer;
mod locale;
#[cfg(feature = "credential")]
mod strip;
mod text;
