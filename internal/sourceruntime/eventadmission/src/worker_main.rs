#![deny(unsafe_code)]

#[cfg(not(target_arch = "wasm32"))]
use std::io::{self, Read, Write};

#[cfg(not(target_arch = "wasm32"))]
use cerebro_sourceruntime_eventadmission::{
    MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, evaluate_cbor, evaluate_json,
};

#[cfg(not(target_arch = "wasm32"))]
const FRAME_HEADER_BYTES: usize = 4;
#[cfg(not(target_arch = "wasm32"))]
const ENCODING_JSON: u8 = 0;
#[cfg(not(target_arch = "wasm32"))]
const ENCODING_CBOR: u8 = 1;

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    if let Err(error) = serve(io::stdin().lock(), io::stdout().lock()) {
        let _ = writeln!(io::stderr().lock(), "event admission worker: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn serve(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    loop {
        let Some(frame_length) = read_frame_length(&mut input)? else {
            return Ok(());
        };
        if frame_length == 0 || frame_length > MAX_INPUT_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request frame exceeds the input limit",
            ));
        }
        let mut request = vec![0_u8; frame_length];
        input.read_exact(&mut request)?;
        let (&encoding, payload) = request.split_first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "request encoding is required")
        })?;
        let response = match encoding {
            ENCODING_JSON => evaluate_json(payload).map_err(io::Error::other)?,
            ENCODING_CBOR => evaluate_cbor(payload)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request encoding is not supported",
                ));
            }
        };
        if response.len() > MAX_OUTPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response frame exceeds the output limit",
            ));
        }
        write_frame(&mut output, encoding, &response)?;
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn read_frame_length(input: &mut impl Read) -> io::Result<Option<usize>> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let mut read = 0;
    while read < header.len() {
        match input.read(&mut header[read..])? {
            0 if read == 0 => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial frame header",
                ));
            }
            count => read += count,
        }
    }
    Ok(Some(u32::from_be_bytes(header) as usize))
}

#[cfg(not(target_arch = "wasm32"))]
fn write_frame(output: &mut impl Write, encoding: u8, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len() + 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response frame is too large"))?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(&[encoding])?;
    output.write_all(payload)?;
    output.flush()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn serves_multiple_frames_and_stops_at_clean_eof() {
        let request =
            br#"{"schema_version":"source-event-admission.v2","contracts":[],"events":[]}"#;
        let mut input = Vec::new();
        write_frame(&mut input, ENCODING_JSON, request).expect("first frame");
        write_frame(&mut input, ENCODING_JSON, request).expect("second frame");
        let mut output = Vec::new();

        serve(input.as_slice(), &mut output).expect("worker serves frames");

        let mut output = output.as_slice();
        for _ in 0..2 {
            let length = read_frame_length(&mut output)
                .expect("response header")
                .expect("response frame");
            let mut response = vec![0_u8; length];
            output.read_exact(&mut response).expect("response body");
            assert_eq!(response[0], ENCODING_JSON);
            assert!(response[1..].starts_with(br#"{"outcome":"admitted""#));
        }
        assert_eq!(read_frame_length(&mut output).expect("clean EOF"), None);
    }

    #[test]
    fn rejects_partial_and_oversized_frames() {
        assert_eq!(
            read_frame_length(&mut [0_u8, 1].as_slice())
                .expect_err("partial frame must fail")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let oversized = u32::try_from(MAX_INPUT_BYTES + 2)
            .expect("input limit fits u32")
            .to_be_bytes();
        assert_eq!(
            serve(oversized.as_slice(), Vec::new())
                .expect_err("oversized frame must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
