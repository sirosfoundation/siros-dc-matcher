//! The matcher's allocator: a bump allocator. It grows linear memory with
//! `memory.grow` and never frees: the host tears the instance down after one
//! invocation. std's allocator on `wasm32-wasip1`, wasi-libc's dlmalloc, adds
//! 24 KB to the module.

use core::alloc::{GlobalAlloc, Layout};

pub struct SimpleAllocator;

unsafe extern "C" {
    static __heap_base: u8;
}

static mut NEXT_ADDR: usize = 0;
static mut CURRENT_PAGES: usize = 0;

const PAGE_SIZE: usize = 65536;

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut next_addr = unsafe { NEXT_ADDR };
        if next_addr == 0 {
            next_addr = core::ptr::addr_of!(__heap_base) as usize;
            unsafe { CURRENT_PAGES = core::arch::wasm32::memory_size(0) };
        }

        let align = layout.align();
        let size = layout.size();

        // Checked, not wrapping: a wrapped `end_ptr` would land below
        // `next_addr` and hand out memory already in use, which for a global
        // allocator is undefined behaviour rather than a mere bad pointer.
        // Overflow is an allocation failure like any other, so it is null.
        // `align` is a power of two, so `& !(align - 1)` rounds up without
        // any further arithmetic that could wrap.
        let Some(alloc_ptr) = next_addr
            .checked_add(align - 1)
            .map(|addr| addr & !(align - 1))
        else {
            return core::ptr::null_mut();
        };
        let Some(end_ptr) = alloc_ptr.checked_add(size) else {
            return core::ptr::null_mut();
        };

        // Saturating: 65536 pages of 64 KiB is exactly 2^32, one past what a
        // 32-bit `usize` holds. At that limit nothing can grow further anyway,
        // and saturating keeps the comparison below meaningful.
        let current_limit = unsafe { CURRENT_PAGES.saturating_mul(PAGE_SIZE) };

        if end_ptr > current_limit {
            let needed_bytes = end_ptr - current_limit;
            let needed_pages = needed_bytes.div_ceil(PAGE_SIZE);
            if core::arch::wasm32::memory_grow(0, needed_pages) == usize::MAX {
                return core::ptr::null_mut();
            }
            unsafe { CURRENT_PAGES += needed_pages };
        }

        unsafe { NEXT_ADDR = end_ptr };
        alloc_ptr as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: SimpleAllocator = SimpleAllocator;
