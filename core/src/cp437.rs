//! Minimal CP437 -> Unicode mapping for the high range (0x80..=0xFF).
//!
//! ZIP filenames without the UTF-8 general-purpose flag (bit 11) are CP437. The
//! low range is ASCII; only the 128 high bytes need a table. Kept inline rather
//! than pulling a heavy `encoding` crate (HANDOFF section 2.1).

/// CP437 code points for bytes 0x80..=0xFF (index = byte - 0x80).
const HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', // 0x80
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', // 0x90
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', // 0xA0
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', // 0xB0
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', // 0xC0
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', // 0xD0
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', // 0xE0
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■',
    '\u{00A0}', // 0xF0
];

/// Decode a single CP437 byte to its Unicode character.
pub(crate) fn decode(b: u8) -> char {
    if b < 0x80 {
        b as char
    } else {
        HIGH[(b - 0x80) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_identity() {
        assert_eq!(decode(b'A'), 'A');
        assert_eq!(decode(0x2F), '/');
        assert_eq!(decode(0x00), '\0');
    }

    #[test]
    fn high_range_maps_cp437() {
        assert_eq!(decode(0x80), 'Ç');
        assert_eq!(decode(0xE1), 'ß');
        assert_eq!(decode(0xFF), '\u{00A0}');
    }
}
