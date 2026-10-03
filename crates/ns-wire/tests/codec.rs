//! Canonical CBOR through the public reader and writer: quick-v2 §12.1.

use ns_wire::{CborError, CborReader, CborWriter};

#[test]
fn writer_output_round_trips_through_the_reader() {
    let mut writer = CborWriter::with_capacity(32);
    writer
        .array(6)
        .uint(500)
        .bytes(&[1, 2, 3])
        .text("ns")
        .boolean(false)
        .null()
        .array(1)
        .uint(0);
    let encoded = writer.into_bytes();

    let mut reader = CborReader::new(&encoded, encoded.len()).unwrap();
    reader.array(6).unwrap();
    assert_eq!(reader.uint(), Ok(500));
    assert_eq!(reader.bytes_up_to(3), Ok(&[1, 2, 3][..]));
    assert_eq!(reader.text_up_to(2), Ok("ns"));
    assert_eq!(reader.boolean(), Ok(false));
    assert!(reader.take_null());
    assert!(!reader.take_null());
    assert_eq!(reader.array_up_to(1), Ok(1));
    assert_eq!(reader.uint(), Ok(0));
    assert_eq!(reader.consumed(), &encoded[..]);
    reader.finish().unwrap();

    let mut writer = CborWriter::default();
    writer.bytes(&[7; 4]);
    let encoded = writer.into_bytes();
    let mut reader = CborReader::new(&encoded, 5).unwrap();
    assert_eq!(reader.fixed_bytes::<4>(), Ok([7; 4]));
    reader.finish().unwrap();
}

#[test]
fn reader_rejects_non_canonical_input() {
    // 23 encoded with a one-byte argument instead of inline.
    let mut reader = CborReader::new(&[0x18, 0x17], 2).unwrap();
    assert_eq!(reader.uint(), Err(CborError::NonShortest));

    let mut reader = CborReader::new(&[0x01, 0x02], 2).unwrap();
    assert_eq!(reader.uint(), Ok(1));
    assert_eq!(reader.finish(), Err(CborError::TrailingBytes));

    let mut reader = CborReader::new(&[0xa0], 1).unwrap();
    assert_eq!(reader.array(0), Err(CborError::Map));

    let mut reader = CborReader::new(&[0x82, 0x01], 2).unwrap();
    assert_eq!(
        reader.array(1),
        Err(CborError::ArrayLength {
            expected: 1,
            actual: 2
        })
    );

    assert!(matches!(
        CborReader::new(&[0; 4], 3),
        Err(CborError::TooLarge {
            length: 4,
            maximum: 3
        })
    ));
}
