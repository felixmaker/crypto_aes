use base64::Engine;
use crypto::buffer::{self, BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::md5::Md5;

fn main() {
    let text = "12343453523434";
    let encrypt = aes_encrypt(text, "123123");
    let decrypt = aes_decrypt(&encrypt, "123123");
    assert_eq!(text, &decrypt);
    println!("{}", decrypt);
}

fn aes_encrypt(text: &str, password: &str) -> String {
    let salt: [u8; 8] = [6, 6, 8, 0, 0, 0, 0, 0];

    let (key, iv) = bytes_to_key(password, &salt, 32, 16);
    let mut encryptor = crypto::aes::cbc_encryptor(
        crypto::aes::KeySize::KeySize256,
        &key,
        &iv,
        crypto::blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(text.as_bytes());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    let salted = "Salted__".as_bytes();
    let mut result = Vec::new();
    result.extend(salted);
    result.extend(salt);
    result.extend(final_result);

    let result = base64::engine::general_purpose::STANDARD_NO_PAD.encode(result);
    result
}

fn aes_decrypt(text: &str, password: &str) -> String {
    let origin_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(text)
        .unwrap();
    let salt = &origin_bytes[8..16];
    let text = &origin_bytes[16..];

    let (key, iv) = bytes_to_key(password, salt, 32, 16);
    let mut decryptor = crypto::aes::cbc_decryptor(
        crypto::aes::KeySize::KeySize256,
        &key,
        &iv,
        crypto::blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(text);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    String::from_utf8_lossy(&final_result).to_string()
}

fn bytes_to_key(
    password: &str,
    salt: &[u8],
    key_length: usize,
    iv_length: usize,
) -> (Vec<u8>, Vec<u8>) {
    let password = password.as_bytes();

    let mut key: Vec<u8> = Vec::with_capacity(key_length);
    let mut iv: Vec<u8> = Vec::with_capacity(iv_length);
    let mut tmp: Vec<u8> = Vec::with_capacity(16);

    while key.len() < key_length || iv.len() < iv_length {
        tmp = caculate_md5(&tmp, password, salt);
        let mut md5_tmp = tmp.clone();

        if key.len() < key_length {
            if key_length - key.len() < md5_tmp.len() {
                key.extend(md5_tmp.drain(0..key_length - key.len()));
            } else {
                key.append(&mut md5_tmp);
            }
        }

        if iv.len() < iv_length {
            iv.append(&mut md5_tmp);
        }
    }

    (key[0..key_length].to_vec(), iv[0..iv_length].to_vec())
}

fn caculate_md5(tmp: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.input(tmp);
    hasher.input(password);
    hasher.input(salt);
    let mut result: [u8; 16] = [0; 16];
    hasher.result(&mut result);
    result.to_vec()
}
