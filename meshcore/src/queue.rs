use core::{
    cell::{Cell, UnsafeCell},
    mem::MaybeUninit,
};

use crate::{Error, Result, packet::Packet};
use heapless::Vec;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct BufferId(u8);

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct BufferRef<'a> {
    pub id: BufferId,
    pub bytes: &'a [u8; 255],
}

#[derive(PartialEq, Eq, Ord)]
struct Entry {
    id: BufferId,
    priority: u8,
    timestamp: u32,
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.timestamp < other.timestamp || self.priority < other.priority {
            return Some(std::cmp::Ordering::Less);
        }
        if self.timestamp > other.timestamp || self.priority > other.priority {
            return Some(std::cmp::Ordering::Greater);
        }
        return Some(std::cmp::Ordering::Equal);
    }
}

// pub struct Pool<T, const N: usize> {
//     used: [Cell<bool>; N],
//     data: [UnsafeCell<MaybeUninit<T>>; N],
// }

// impl<T, const N: usize> Pool<T, N> {
//     const VALUE: Cell<bool> = Cell::new(false);
//     const UNINIT: UnsafeCell<MaybeUninit<T>> = UnsafeCell::new(MaybeUninit::uninit());
//     const fn new() -> Self {
//         Self {
//             used: [VALUE; N],
//             data: [UNINIT; N],
//         }
//     }
// }

// impl<T, const N: usize> Pool<T, N> {}

// pub struct Queue<const N: usize> {
//     entries: [Option<Entry>; N],
//     priority: [Option<u8>; N],
//     schedule: [Option<u8>; N],
// }

// impl<const N: usize> Queue<N> {
//     pub fn push(&mut self, buf: &BufferRef, priority: u8, timestamp: u32) -> Result<()> {
//         todo!()
//     }
// }

// mod tests {
//     #[test]
//     fn basic_test() {}
// }
