// https://web.archive.org/web/20070508145900/http://www.tinyted.net/eddie/css_basic.html
#[derive(Clone, Debug)]
pub struct Css {
    pub(crate) lfsr1: Lfsr,
    pub(crate) lfsr2: Lfsr,
    pub(crate) carry: bool,
}

impl Css {
    pub fn new(key: [u8; 5]) -> Self {
        // initialized with the first two bytes of the key + 1 in 9th position
        let mut lfsr1 = Lfsr {
            state: ((key[0].reverse_bits() as u32) << 9)
                | (1 << 8)
                | key[1].reverse_bits() as u32,
            bit_size: 17,
            update: |s| (s ^ (s >> 14)) & 1
        };

        // initialized with the last three bytes of the key + 1 in 22th position
        // [_|__1_____|__key3__|__key4__]
        //  \ MSB                       \ LSB
        let mut lfsr2 = Lfsr {
            state: ((key[2].reverse_bits() as u32 & 0b_1110_0000) << 17)
                 | (1 << 21)
                 | ((key[2].reverse_bits() as u32 & 0b_0001_1111) << 16)
                 | ((key[3].reverse_bits() as u32) << 8)
                 |   key[4].reverse_bits() as u32,
            bit_size: 25,
            update: |s| (s ^ (s >> 3) ^ (s >> 4) ^ (s >> 12)) & 1
        };

        lfsr1.step8();
        lfsr2.step8();
        lfsr2.step8();

        Css { lfsr1, lfsr2, carry: false }
    }

    pub fn step(&mut self) -> u8 {
        let x = self.lfsr1.step8();
        let y = self.lfsr2.step8();
        let c = self.carry as u8;
        //println!("{:b}", self.lfsr1.state);

        self.carry = x.checked_add(y).is_none();

        x.wrapping_add(y).wrapping_add(c)
    }
}

impl Iterator for Css {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.step())
    }
}

#[derive(Clone, Debug)]
pub struct Lfsr {
    pub state: u32,
    pub bit_size: u8,
    pub update: fn(u32) -> u32 /* 1 or 0 */,
}

impl Lfsr {
    pub fn step8(&mut self) -> u8 {
        let mut output = 0;

        for _ in 0..8 {
            output <<= 1;
            output |= self.state as u8 & 1;
            let next_bit = (self.update)(self.state);
            assert!(next_bit < 2);
            self.state >>= 1;
            self.state |= next_bit << (self.bit_size - 1);
        }

        output
    }
}
