// Nothing panics outside the tests. scripts/check_panic_sites.py finds the
// panics these lints cannot see.
#![cfg_attr(
    not(test),
    forbid(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

fn main() {
    uniffi::uniffi_bindgen_main()
}
