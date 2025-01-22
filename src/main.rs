use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

fn main() {
    softhsm();
}

// initialize a new Pkcs11 object using the module from the env variable
fn softhsm() {
    let pkcs11 = Pkcs11::new(
        std::env::var("PKCS11_SOFTHSM2_MODULE")
            .unwrap_or("/usr/local/lib/softhsm/libsofthsm2.so".to_string()),
    )
    .unwrap();

    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

    let slot = pkcs11.get_slots_with_token().unwrap()[0];

    // initialize a test token
    let so_pin = AuthPin::new("abcdef".into());
    pkcs11.init_token(slot, &so_pin, "Test Token").unwrap();

    let user_pin = AuthPin::new("fedcba".into());

    // initialize user PIN
    {
        let session = pkcs11.open_rw_session(slot).unwrap();
        session.login(UserType::So, Some(&so_pin)).unwrap();
        session.init_pin(&user_pin).unwrap();
    }

    // login as a user, the token has to be already initialized
    let session = pkcs11.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&user_pin)).unwrap();

    let aes_key_template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(16_u64.into()),
        Attribute::Token(true),
        Attribute::Extractable(true),
    ];

    // Key to be wrapped
    let aes_key_handle = session
        .generate_key(&Mechanism::AesKeyGen, &aes_key_template)
        .unwrap();
    let aes_key_value = session
        .get_attributes(aes_key_handle, &[AttributeType::Value])
        .unwrap();
    assert!(aes_key_value.len() == 1);
    let aes_key_value = match &aes_key_value[0] {
        Attribute::Value(val) => val,
        _ => panic!("Expected Attribute::Value(_) but got {:#?}", aes_key_value),
    };
    println!("Payload AES key value: {:?}", aes_key_value);

    // Wrapping key
    let wrapping_aes_key_handle = session
        .generate_key(&Mechanism::AesKeyGen, &aes_key_template)
        .unwrap();
    let wrapping_aes_key_value = session
        .get_attributes(wrapping_aes_key_handle, &[AttributeType::Value])
        .unwrap();
    assert!(wrapping_aes_key_value.len() == 1);
    let wrapping_aes_key_value = match &wrapping_aes_key_value[0] {
        Attribute::Value(val) => val,
        _ => panic!(
            "Expected Attribute::Value(_) but got {:#?}",
            wrapping_aes_key_value
        ),
    };
    println!("Wrapping AES key value: {:?}", wrapping_aes_key_value);

    let wrapped_key_iv0 = session
        .wrap_key(
            &Mechanism::AesCbc([0u8; 16]),
            wrapping_aes_key_handle,
            aes_key_handle,
        )
        .unwrap();
    println!("Wrapped key iv 0: {:?}", wrapped_key_iv0);

    let wrapped_key_iv1 = session
        .wrap_key(
            &Mechanism::AesCbc([1u8; 16]),
            wrapping_aes_key_handle,
            aes_key_handle,
        )
        .unwrap();
    println!("Wrapped key iv 1: {:?}", wrapped_key_iv1);

    let encrypted_key_iv0 = session
        .encrypt(
            &Mechanism::AesCbc([0u8; 16]),
            wrapping_aes_key_handle,
            aes_key_value,
        )
        .unwrap();
    println!("Encrypted key iv 0: {:?}", encrypted_key_iv0);

    let encrypted_key_iv1 = session
        .encrypt(
            &Mechanism::AesCbc([1u8; 16]),
            wrapping_aes_key_handle,
            aes_key_value,
        )
        .unwrap();
    println!("Encrypted key iv 1: {:?}", encrypted_key_iv1);

    assert_eq!(
        wrapped_key_iv0, encrypted_key_iv0,
        "Expected wrap and encrypt of key bytes with 0 iv to produce the same result"
    );

    assert_ne!(
        wrapped_key_iv0, wrapped_key_iv1,
        "Expected AES_CBC wrap with different iv to produce different values"
    );

    assert_eq!(
        wrapped_key_iv1, encrypted_key_iv1,
        "Expected wrap and encrypt of key bytes with 1 iv to produce the same result"
    );
}
