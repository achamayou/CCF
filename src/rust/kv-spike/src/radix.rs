// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Routing for the experimental persistent radix index.

/// Zero is the end-of-key symbol; the high and low nibbles occupy 1..=16.
#[inline]
pub fn symbol(key: &[u8], digit: usize) -> usize {
    let at = digit / 2;
    if at >= key.len() {
        return 0;
    }
    let byte = key[at];
    if digit % 2 == 0 {
        1 + (byte / 16) as usize
    } else {
        1 + (byte % 16) as usize
    }
}

fn byte_difference(index: usize, a: u8, b: u8) -> usize {
    if a / 16 != b / 16 {
        2 * index
    } else {
        2 * index + 1
    }
}

/// The first differing routing digit, including a shorter key's terminator.
#[inline]
pub fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < a.len() && i < b.len() {
        if a[i] != b[i] {
            return Some(byte_difference(i, a[i], b[i]));
        }
        i += 1;
    }
    if a.len() == b.len() {
        None
    } else {
        Some(2 * i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test every pair of byte values, both at the root and below a common prefix.
    #[test]
    fn split_is_the_first_digit_that_differs() {
        fn check(a: &[u8], b: &[u8]) {
            let end = 2 * a.len().max(b.len());
            let expected = (0..=end).find(|&digit| symbol(a, digit) != symbol(b, digit));
            assert_eq!(first_difference(a, b), expected);
        }
        for a in 0..=255 {
            check(&[], &[a]);
            check(&[a, 0], &[a]);
            for b in 0..=255 {
                check(&[a], &[b]);
                check(&[0, 255, a], &[0, 255, b]);
            }
        }
    }
}
