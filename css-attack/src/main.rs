use std::{sync::{atomic::{AtomicBool, Ordering}, Mutex}, thread::scope};

use css::{Css, Lfsr};
use rand::{rng, Rng};

mod css;

fn main() {
    // let key: [u8; 5] = [0xDE, 0xAD, 0xBE, 0x04, 0x00]; // 30 bits
    // let keystream: Vec<u8> = Css::new(key).take(1024).collect();
    // parallel_brute_force_attack(keystream.as_ref(), 8);

    let key = rng().random();
    println!("Generated key {key:X?}");

    let keystream: Vec<u8> = Css::new(key).take(1024).collect();
    println!("Generated keystream");

    let (_, lfsr2_state) = efficent_attack(&keystream).unwrap();
    brute_force_lfsr2(lfsr2_state).unwrap();
}

fn parallel_brute_force_attack(keystream: &[u8], num_threads: u32) -> Option<[u8; 5]> {
    println!("Brute forcing with {num_threads} threads");
    let stop = AtomicBool::new(false);
    let key_mutex = Mutex::new(None);

    scope(|s| {
        for i in 0..num_threads {
            let stop = &stop;
            let key_mutex = &key_mutex;
            s.spawn(move || {
                for key in (i as u64..(1<<40)).step_by(num_threads as usize) {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let key: [u8; 5] = key.to_le_bytes()[0..5].try_into().unwrap(); // somehow this is a noop

                    let css = Css::new(key);

                    if keystream.iter().cloned().zip(css).all(|(a, b)| a == b) {
                        println!("Found key {key:X?}");
                        stop.store(true, Ordering::Relaxed);
                        key_mutex.lock().unwrap().replace(key);
                    }
                }
            });
        }
    });

    *key_mutex.lock().unwrap()
}

fn efficent_attack(keystream: &[u8]) -> Option<([u8; 2], u32)> {
    println!("Running efficient attack");

    for i in 0u16..u16::MAX {
        let key_2_bytes : [u8;2] = i.to_le_bytes();

        let mut lfsr1 = Lfsr {
            state: ((key_2_bytes[0].reverse_bits() as u32) << 9)
                | (1 << 8)
                | key_2_bytes[1].reverse_bits() as u32,
            bit_size: 17,
            update: |s| (s ^ (s >> 14)) & 1
        };
        lfsr1.step8(); // part of init

        let x1 = lfsr1.step8();
        let x2 = lfsr1.step8();
        let x3 = lfsr1.step8();
        let x4 = lfsr1.step8();

        // y1 = o1 - x1
        let (y1, c1) = keystream[0].overflowing_sub(x1);

        // y2 = o2 - x2 - c1
        let (y2, c2) = double_overflowing_sub(keystream[1], x2, c1 as u8);

        // y3 = o3 - x3 - c2
        let (y3, c3) = double_overflowing_sub(keystream[2], x3, c2 as u8);

        // y4 = o4 - x4 - c3
        let (y4, c4) = double_overflowing_sub(keystream[3], x4, c3 as u8);

        // sanity checks
        debug_assert_eq!(x1.wrapping_add(y1), keystream[0]);
        debug_assert_eq!(x2.wrapping_add(y2).wrapping_add(c1 as u8), keystream[1]);
        debug_assert_eq!(x3.wrapping_add(y3).wrapping_add(c2 as u8), keystream[2]);
        debug_assert_eq!(x4.wrapping_add(y4).wrapping_add(c3 as u8), keystream[3]);

        // construct lfsr2 from the recovered y values
        let state2 = y1.reverse_bits() as u32
            | ((y2.reverse_bits() as u32) << 8)
            | ((y3.reverse_bits() as u32) << 16)
            | ((y4.reverse_bits() as u32 & 1) << 24);

        let mut lfsr2 = Lfsr {
            state: state2,
            bit_size: 25,
            update: |s| (s ^ (s >> 3) ^ (s >> 4) ^ (s >> 12)) & 1
        };

        // sync it with the first lfsr
        let y1_gen = lfsr2.step8(); debug_assert_eq!(y1, y1_gen);
        let y2_gen = lfsr2.step8(); debug_assert_eq!(y2, y2_gen);
        let y3_gen = lfsr2.step8(); debug_assert_eq!(y3, y3_gen);
        let _y4_gen = lfsr2.step8(); //debug_assert_eq!(y4, y4_gen);

        // check the rest of the plaintext
        let css = Css { lfsr1, lfsr2, carry: c4 };

        if keystream.iter().skip(4).cloned().zip(css).all(|(a, b)| a == b) {
            println!("Found the first 2 bytes: {key_2_bytes:X?}");
            return Some((key_2_bytes, state2))
        }
    }

    print!("Failed to find key");
    None
}

fn brute_force_lfsr2(target_state: u32) -> Option<[u8; 3]> {
    println!("Brute forcing LFSR2 state");

    for i in 0u32..(1 << 24) {
        let key_rem: [u8; 3] = i.to_le_bytes()[0..3].try_into().unwrap();
        let mut lfsr2 = Lfsr {
            state: ((key_rem[0].reverse_bits() as u32 & 0b_1110_0000) << 17)
                 | (1 << 21)
                 | ((key_rem[0].reverse_bits() as u32 & 0b_0001_1111) << 16)
                 | ((key_rem[1].reverse_bits() as u32) << 8)
                 |   key_rem[2].reverse_bits() as u32,
            bit_size: 25,
            update: |s| (s ^ (s >> 3) ^ (s >> 4) ^ (s >> 12)) & 1
        };

        lfsr2.step8();
        lfsr2.step8();

        if lfsr2.state == target_state {
            println!("Found the last 3 bytes: {key_rem:X?}");
            return Some(key_rem);
        }
    }

    None
}

// a - b - c
fn double_overflowing_sub(a : u8, b: u8, c: u8) -> (u8, bool) {
    if a >= b {
        (a - b).overflowing_sub(c)
    } else {
        (a.wrapping_sub(b).wrapping_sub(c), true)
    }
}
