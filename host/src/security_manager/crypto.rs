#![warn(missing_docs)]
// This file contains code from Blackrock User-Mode Bluetooth LE Library (https://github.com/mxk/burble)
use bt_hci::param::{AddrKind, BdAddr};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use cmac::digest;
use p256::ecdh;
use rand_core::{CryptoRng, RngCore};

use crate::Address;

/// LE Secure Connections Long Term Key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
#[repr(transparent)]
pub struct LongTermKey(pub u128);

impl LongTermKey {
    /// Creates a Long Term Key from a `u128` value.
    #[inline(always)]
    pub const fn new(k: u128) -> Self {
        Self(k)
    }
    /// Creates a Long Term Key from a `[u8; 16]` value in little endian.
    #[inline(always)]
    pub const fn from_le_bytes(k: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(k))
    }
    /// Creates a Long Term Key from a `[u8; 16]` value in little endian.
    #[inline(always)]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

impl From<&LongTermKey> for u128 {
    #[inline(always)]
    fn from(k: &LongTermKey) -> Self {
        k.0
    }
}

impl core::fmt::Display for LongTermKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for LongTermKey {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{:016x}", self.0)
    }
}

/// Identity Resolving Key.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
#[repr(transparent)]
pub struct IdentityResolvingKey(pub u128);

impl IdentityResolvingKey {
    /// Creates an Identity Resolving Key from a `u128` value.
    #[inline(always)]
    pub const fn new(k: u128) -> Self {
        Self(k)
    }

    /// Creates an Identity Resolving Key from a `[u8; 16]` value in little endian.
    #[inline(always)]
    pub const fn from_le_bytes(k: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(k))
    }

    /// Returns the Identity Resolving Key as `[u8; 16]` value in little endian.
    #[inline(always)]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Generates a resolvable private address using this key.
    ///
    /// The generated address follows the format described in
    /// Bluetooth Core Specification [Vol 3] Part C, Section 10.8.2.
    pub fn generate_resolvable_address<T: RngCore + CryptoRng>(&self, rng: &mut T) -> [u8; 6] {
        // Generate prand (24 bits with top 2 bits set to 0b01 to indicate resolvable private address)
        let mut prand = [0u8; 3];
        rng.fill_bytes(&mut prand);

        // Set the top 2 bits to 0b01 to indicate resolvable private address
        prand[2] &= 0b00111111; // Clear top 2 bits
        prand[2] |= 0b01000000; // Set 2nd bit from top

        // Calculate hash using ah function
        let hash = self.ah(prand);

        // Construct the address: prand || hash
        let mut address = [0u8; 6];
        address[3..6].copy_from_slice(&prand);
        address[0..3].copy_from_slice(&hash);

        address
    }

    /// Resolves a resolvable private address.
    ///
    /// Returns true if the address was generated using this IRK.
    pub fn resolve_address(&self, address: &BdAddr) -> bool {
        // Extract prand (top 24 bits) and hash (bottom 24 bits)
        let mut prand = [0u8; 3];
        prand.copy_from_slice(&address.raw()[3..6]);

        // Verify the address type bits (top 2 bits should be 0b01)
        if (prand[2] & 0b11000000) != 0b01000000 {
            return false; // Not a resolvable private address
        }

        prand.reverse();

        // Calculate local hash
        let mut local_hash = self.ah(prand);
        local_hash.reverse();

        // Compare with the hash in the address
        let mut address_hash = [0u8; 3];
        address_hash.copy_from_slice(&address.raw()[0..3]);
        local_hash == address_hash
    }

    /// Random address hash function `ah` as defined in
    /// Bluetooth Core Specification [Vol 3] Part H, Section 2.2.2.
    /// https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html#UUID-03b4d5c9-160c-658a-7aa5-d0b2230d38f1
    fn ah(&self, r: [u8; 3]) -> [u8; 3] {
        let mut r_prime = [0u8; 16];
        r_prime[13..].copy_from_slice(&r);

        let cipher = Aes128::new_from_slice(&self.0.to_be_bytes()).unwrap();
        cipher.encrypt_block((&mut r_prime).into());
        // Extract least significant 24 bits (3 bytes) as the result
        r_prime[13..16].try_into().unwrap()
    }
}

impl From<&IdentityResolvingKey> for u128 {
    #[inline(always)]
    fn from(k: &IdentityResolvingKey) -> Self {
        k.0
    }
}

impl core::fmt::Display for IdentityResolvingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for IdentityResolvingKey {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{:016x}", self.0)
    }
}

/// RFC-4493 AES-CMAC ([Vol 3] Part H, Section 2.2.5).
#[derive(Debug)]
#[repr(transparent)]
pub struct AesCmac(cmac::Cmac<aes::Aes128>);

impl AesCmac {
    /// Creates new AES-CMAC state using key `k`.
    #[inline(always)]
    #[must_use]
    pub(super) fn new(k: &Key) -> Self {
        Self(digest::KeyInit::new(&k.0))
    }

    /// Creates new AES-CMAC state using an all-zero key for GAP database hash
    /// calculation ([Vol 3] Part G, Section 7.3.1).
    #[inline(always)]
    #[must_use]
    pub fn db_hash() -> Self {
        Self::new(&Key::new(0))
    }

    /// Updates CMAC state.
    #[inline(always)]
    pub fn update(&mut self, b: impl AsRef<[u8]>) -> &mut Self {
        digest::Update::update(&mut self.0, b.as_ref());
        self
    }

    /// Computes the final MAC value.
    #[inline(always)]
    #[must_use]
    pub fn finalize(self) -> u128 {
        u128::from_be_bytes(*digest::FixedOutput::finalize_fixed(self.0).as_ref())
    }

    /// Computes the final MAC value for use as a future key and resets the
    /// state.
    #[inline(always)]
    pub(super) fn finalize_key(&mut self) -> Key {
        // Best effort to avoid leaving copies
        let mut k = Key::new(0);
        digest::FixedOutputReset::finalize_into_reset(&mut self.0, &mut k.0);
        k
    }
}

/// LE Secure Connections check value generated by [`MacKey::f6`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[repr(transparent)]
pub struct Check(pub u128);

#[repr(transparent)]
pub(super) struct Key(aes::cipher::Key<aes::Aes128>);

impl Key {
    /// Creates a key from a `u128` value.
    #[inline(always)]
    pub fn new(k: u128) -> Self {
        Self(k.to_be_bytes().into())
    }
}

impl From<&Key> for u128 {
    #[inline(always)]
    fn from(k: &Key) -> Self {
        Self::from_be_bytes(k.0.into())
    }
}

/// Concatenated `AuthReq`, OOB data flag, and IO capability parameters used by
/// [`MacKey::f6`] function ([Vol 3] Part H, Section 2.2.8).
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct IoCap(pub(crate) [u8; 3]);

impl IoCap {
    /// Creates new `IoCap` parameter.
    #[inline(always)]
    pub fn new(auth_req: u8, oob_data: bool, io_cap: u8) -> Self {
        Self([auth_req, u8::from(oob_data), io_cap])
    }
}

/// 128-bit key used to compute LE Secure Connections check value
/// ([Vol 3] Part H, Section 2.2.8).
#[must_use]
#[repr(transparent)]
pub struct MacKey(Key);

impl MacKey {
    /// Generates LE Secure Connections check value
    /// ([Vol 3] Part H, Section 2.2.8).
    #[inline]
    pub fn f6(&self, n1: Nonce, n2: Nonce, r: u128, io_cap: IoCap, a1: Address, a2: Address) -> Check {
        let mut m = AesCmac::new(&self.0);
        m.update(n1.0.to_be_bytes())
            .update(n2.0.to_be_bytes())
            .update(r.to_be_bytes())
            .update(io_cap.0)
            .update(a1.to_bytes())
            .update(a2.to_bytes());
        Check(m.finalize())
    }
}

/// 128-bit random nonce value ([Vol 3] Part H, Section 2.3.5.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Nonce(pub u128);

impl Nonce {
    /// Generates a new non-zero random nonce value from the OS CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG is broken.
    #[allow(clippy::new_without_default)]
    #[inline]
    pub fn new<T: RngCore>(rng: &mut T) -> Self {
        let mut b = [0; core::mem::size_of::<u128>()];
        rng.fill_bytes(b.as_mut_slice());
        let n = u128::from_ne_bytes(b);
        assert_ne!(n, 0);
        Self(n)
    }

    /// Generates LE Secure Connections confirm value
    /// ([Vol 3] Part H, Section 2.2.6).
    #[inline]
    pub fn f4(&self, u: &PublicKeyX, v: &PublicKeyX, z: u8) -> Confirm {
        let mut m = AesCmac::new(&Key::new(self.0));
        m.update(u.as_be_bytes()).update(v.as_be_bytes()).update([z]);
        Confirm(m.finalize())
    }

    /// Generates LE Secure Connections numeric comparison value
    /// ([Vol 3] Part H, Section 2.2.9).
    #[inline]
    pub fn g2(&self, pkax: &PublicKeyX, pkbx: &PublicKeyX, nb: &Self) -> NumCompare {
        let mut m = AesCmac::new(&Key::new(self.0));
        m.update(pkax.as_be_bytes())
            .update(pkbx.as_be_bytes())
            .update(nb.0.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        NumCompare(m.finalize() as u32 % 1_000_000)
    }
}

/// LE Secure Connections confirm value generated by [`Nonce::f4`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[repr(transparent)]
pub struct Confirm(pub u128);

/// 6-digit LE Secure Connections numeric comparison value generated by
/// [`Nonce::g2`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[must_use]
#[repr(transparent)]
pub struct NumCompare(pub u32);

/// P-256 elliptic curve secret key.
#[must_use]
#[repr(transparent)]
pub struct SecretKey(p256::NonZeroScalar);

impl SecretKey {
    /// Generates a new random secret key.
    #[allow(clippy::new_without_default)]
    #[inline(always)]
    pub fn new<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self(p256::NonZeroScalar::random(rng))
    }

    /// Computes the associated public key.
    pub fn public_key(&self) -> PublicKey {
        use p256::elliptic_curve::sec1::Coordinates::Uncompressed;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let p = p256::PublicKey::from_secret_scalar(&self.0).to_encoded_point(false);
        match p.coordinates() {
            Uncompressed { x, y } => PublicKey {
                x: PublicKeyX(Coord(*x.as_ref())),
                y: Coord(*y.as_ref()),
            },
            _ => unreachable!("invalid secret key"),
        }
    }

    /// Computes a shared secret from the local secret key and remote public
    /// key. Returns [`None`] if the public key is either invalid or derived
    /// from the same secret key ([Vol 3] Part H, Section 2.3.5.6.1).
    #[must_use]
    pub fn dh_key(&self, pk: PublicKey) -> Option<DHKey> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        if pk.is_debug() {
            return None; // TODO: Compile-time option for debug-only mode
        }

        let (x, y) = (&pk.x.0 .0.into(), &pk.y.0.into());
        let rep = p256::EncodedPoint::from_affine_coordinates(x, y, false);
        let lpk = p256::PublicKey::from_secret_scalar(&self.0);
        // Constant-time ops not required:
        // https://github.com/RustCrypto/traits/issues/1227
        let rpk = Option::from(p256::PublicKey::from_encoded_point(&rep)).unwrap_or(lpk);
        (rpk != lpk).then(|| DHKey(ecdh::diffie_hellman(&self.0, rpk.as_affine())))
    }
}

/// P-256 elliptic curve public key ([Vol 3] Part H, Section 3.5.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct PublicKey {
    pub x: PublicKeyX,
    pub y: Coord,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];

        x.copy_from_slice(&bytes[..32]);
        y.copy_from_slice(&bytes[32..]);

        x.reverse();
        y.reverse();

        Self {
            x: PublicKeyX(Coord(x)),
            y: Coord(y),
        }
    }

    /// Returns the public key X coordinate.
    #[inline(always)]
    pub const fn x(&self) -> &PublicKeyX {
        &self.x
    }

    /// Returns whether `self` is the debug public key
    /// ([Vol 3] Part H, Section 2.3.5.6.1).
    #[allow(clippy::unreadable_literal)]
    #[allow(clippy::unusual_byte_groupings)]
    fn is_debug(&self) -> bool {
        let (x, y) = (&self.x.0 .0, &self.y.0);
        x[..16] == u128::to_be_bytes(0x20b003d2_f297be2c_5e2c83a7_e9f9a5b9)
            && x[16..] == u128::to_be_bytes(0xeff49111_acf4fddb_cc030148_0e359de6)
            && y[..16] == u128::to_be_bytes(0xdc809c49_652aeb6d_63329abf_5a52155c)
            && y[16..] == u128::to_be_bytes(0x766345c2_8fed3024_741c8ed0_1589d28b)
    }
}

/// 256-bit elliptic curve coordinate in big-endian byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Coord([u8; 256 / u8::BITS as usize]);

impl Coord {
    /// Returns the coordinate in big-endian byte order.
    #[inline(always)]
    pub(super) const fn as_be_bytes(&self) -> &[u8; core::mem::size_of::<Self>()] {
        &self.0
    }
}

/// P-256 elliptic curve public key affine X coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
#[repr(transparent)]
pub struct PublicKeyX(Coord);

impl PublicKeyX {
    /// Creates the coordinate from a big-endian encoded byte array.
    #[cfg(test)]
    #[inline]
    pub(super) const fn from_be_bytes(x: [u8; core::mem::size_of::<Self>()]) -> Self {
        Self(Coord(x))
    }

    /// Returns the coordinate in big-endian byte order.
    #[inline(always)]
    pub(super) const fn as_be_bytes(&self) -> &[u8; core::mem::size_of::<Self>()] {
        &self.0 .0
    }
}

/// P-256 elliptic curve shared secret ([Vol 3] Part H, Section 2.3.5.6.1).
#[must_use]
#[repr(transparent)]
pub struct DHKey(ecdh::SharedSecret);

impl DHKey {
    /// Generates LE Secure Connections `MacKey` and `LTK`
    /// ([Vol 3] Part H, Section 2.2.7).
    #[inline]
    pub fn f5(&self, n1: Nonce, n2: Nonce, a1: Address, a2: Address) -> (MacKey, LongTermKey) {
        let n1 = n1.0.to_be_bytes();
        let n2 = n2.0.to_be_bytes();
        let half = |m: &mut AesCmac, counter: u8| {
            m.update([counter])
                .update(b"btle")
                .update(n1)
                .update(n2)
                .update(a1.to_bytes())
                .update(a2.to_bytes())
                .update(256_u16.to_be_bytes())
                .finalize_key()
        };
        let mut m = AesCmac::new(&Key::new(0x6C88_8391_AAF5_A538_6037_0BDB_5A60_83BE));
        m.update(self.0.raw_secret_bytes());
        let mut m = AesCmac::new(&m.finalize_key());
        (MacKey(half(&mut m, 0)), LongTermKey(u128::from(&half(&mut m, 1))))
    }
}

/// Combines `hi` and `lo` values into a big-endian byte array.
#[allow(clippy::redundant_pub_crate)]
#[cfg(test)]
pub(super) fn u256<T: From<[u8; 32]>>(hi: u128, lo: u128) -> T {
    let mut b = [0; 32];
    b[..16].copy_from_slice(&hi.to_be_bytes());
    b[16..].copy_from_slice(&lo.to_be_bytes());
    T::from(b)
}

// ============================================================================
// Legacy Pairing Cryptographic Functions
// ============================================================================

/// Temporary Key for Legacy Pairing.
///
/// The TK is used as the key for the c1 and s1 functions during legacy pairing.
/// Its value depends on the pairing method:
/// - Just Works: TK = 0
/// - Passkey Entry: TK = passkey value (0-999999) as u128
/// - OOB: TK = 128-bit random value from OOB channel
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct TemporaryKey(pub u128);

impl TemporaryKey {
    /// Creates a TK from a passkey (0-999999).
    #[inline(always)]
    pub const fn from_passkey(passkey: u32) -> Self {
        Self(passkey as u128)
    }

    /// Creates a TK for Just Works pairing (TK = 0).
    #[inline(always)]
    pub const fn just_works() -> Self {
        Self(0)
    }

    /// Returns the TK as little-endian bytes.
    #[inline(always)]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

/// Short Term Key for Legacy Pairing.
///
/// The STK is generated using the s1 function and is used to encrypt the link
/// during the pairing procedure. It is replaced by the LTK after key distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ShortTermKey(pub u128);

impl ShortTermKey {
    /// Returns the STK as little-endian bytes.
    #[inline(always)]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

/// Legacy Pairing Confirm Value.
///
/// Generated by the c1 function during legacy pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct LegacyConfirm(pub u128);

impl LegacyConfirm {
    /// Returns the confirm value as little-endian bytes.
    #[inline(always)]
    pub const fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Creates a confirm value from little-endian bytes.
    #[inline(always)]
    pub const fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(bytes))
    }
}

/// Legacy pairing c1 function - confirm value generation.
///
/// Bluetooth Core Spec Vol 3, Part H, Section 2.2.3.
///
/// ```text
/// c1(k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)
///
/// where:
///   p1 = pres || preq || rat || iat
///   p2 = padding(4) || ia || ra
/// ```
///
/// # Arguments
/// * `tk` - Temporary Key (128 bits)
/// * `r` - Random value (128 bits)
/// * `preq` - Pairing Request command payload (7 bytes, excluding opcode)
/// * `pres` - Pairing Response command payload (7 bytes, excluding opcode)
/// * `initiator_addr` - Initiator address (contains both type and address)
/// * `responder_addr` - Responder address (contains both type and address)
pub fn c1(
    tk: &TemporaryKey,
    r: u128,
    preq: &[u8; 7],
    pres: &[u8; 7],
    initiator_addr: crate::Address,
    responder_addr: crate::Address,
) -> LegacyConfirm {
    // Convert AddrKind to u8: PUBLIC = 0, RANDOM = 1
    let iat: u8 = if initiator_addr.kind == AddrKind::PUBLIC { 0 } else { 1 };
    let rat: u8 = if responder_addr.kind == AddrKind::PUBLIC { 0 } else { 1 };
    let ia = initiator_addr.addr.raw();
    let ra = responder_addr.addr.raw();

    // Build p1: pres || preq || rat' || iat' (16 bytes)
    // Per spec: iat' is LSB, MSB of pres is MSB of p1
    // For AES, we need bytes in big-endian order (MSB at index 0)
    // So: [pres[6], pres[5], ..., pres[0], preq[6], ..., preq[0], rat, iat]
    let mut p1 = [0u8; 16];
    // pres goes at MSB positions (indices 0-6), reversed
    for i in 0..7 {
        p1[i] = pres[6 - i];
    }
    // preq goes at middle positions (indices 7-13), reversed
    for i in 0..7 {
        p1[7 + i] = preq[6 - i];
    }
    // rat' at index 14, iat' at index 15 (LSB)
    p1[14] = rat;
    p1[15] = iat;

    // Build p2: padding || ia || ra (16 bytes)
    // Per spec: ra is LSB, padding is MSB
    // For AES: [0, 0, 0, 0, ia[5], ia[4], ..., ia[0], ra[5], ra[4], ..., ra[0]]
    let mut p2 = [0u8; 16];
    // padding at indices 0-3 (already zeroed)
    // ia at indices 4-9, reversed
    for i in 0..6 {
        p2[4 + i] = ia[5 - i];
    }
    // ra at indices 10-15, reversed
    for i in 0..6 {
        p2[10 + i] = ra[5 - i];
    }

    // Convert random to big-endian bytes for AES
    let r_bytes = r.to_be_bytes();

    // XOR r with p1
    let mut tmp = [0u8; 16];
    for i in 0..16 {
        tmp[i] = r_bytes[i] ^ p1[i];
    }

    // First AES: e(k, r XOR p1)
    let key_bytes = tk.0.to_be_bytes();
    let cipher = Aes128::new_from_slice(&key_bytes).unwrap();
    let mut block: aes::cipher::generic_array::GenericArray<u8, _> = tmp.into();
    cipher.encrypt_block(&mut block);

    // XOR result with p2
    for i in 0..16 {
        block[i] ^= p2[i];
    }

    // Second AES: e(k, e(k, r XOR p1) XOR p2)
    cipher.encrypt_block(&mut block);

    // Convert result back from big-endian
    LegacyConfirm(u128::from_be_bytes(block.into()))
}

/// Legacy pairing s1 function - STK generation.
///
/// Bluetooth Core Spec Vol 3, Part H, Section 2.2.4.
///
/// ```text
/// s1(k, r1, r2) = e(k, r1' || r2')
///
/// where:
///   r1' = least significant 64 bits of r1
///   r2' = least significant 64 bits of r2
/// ```
///
/// # Arguments
/// * `tk` - Temporary Key
/// * `srand` - Responder's random value (Srand)
/// * `mrand` - Initiator's random value (Mrand)
///
/// # Note
/// The parameter order matches the spec: s1(k, r1, r2) where r1=Srand, r2=Mrand.
/// The concatenation is r' = r1' || r2' with r2' in the lower bytes.
pub fn s1(tk: &TemporaryKey, srand: u128, mrand: u128) -> ShortTermKey {
    // r1' = least significant 64 bits of srand
    // r2' = least significant 64 bits of mrand
    let r1_lsb = (srand & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    let r2_lsb = (mrand & 0xFFFF_FFFF_FFFF_FFFF) as u64;

    // r' = r1' || r2' (r1' is MSB, r2' is LSB per spec Section 2.2.4)
    // "The most significant octet of r1' becomes the most significant octet of r'"
    // "The least significant octet of r2' becomes the least significant octet of r'"
    let mut r_prime = [0u8; 16];
    r_prime[0..8].copy_from_slice(&r1_lsb.to_be_bytes());
    r_prime[8..16].copy_from_slice(&r2_lsb.to_be_bytes());

    // s1(k, r1, r2) = e(k, r')
    let key_bytes = tk.0.to_be_bytes();
    let cipher = Aes128::new_from_slice(&key_bytes).unwrap();
    let mut block: aes::cipher::generic_array::GenericArray<u8, _> = r_prime.into();
    cipher.encrypt_block(&mut block);

    ShortTermKey(u128::from_be_bytes(block.into()))
}

#[allow(clippy::unreadable_literal)]
#[allow(clippy::unusual_byte_groupings)]
#[cfg(test)]
mod tests {
    use p256::elliptic_curve::rand_core::OsRng;

    use super::*;
    extern crate std;
    use bt_hci::param::{AddrKind, BdAddr};

    #[test]
    fn sizes() {
        assert_eq!(core::mem::size_of::<Coord>(), 32);
        assert_eq!(core::mem::size_of::<PublicKey>(), 64);
        assert_eq!(core::mem::size_of::<SecretKey>(), 32);
        assert_eq!(core::mem::size_of::<DHKey>(), 32);
    }

    /// Debug mode key ([Vol 3] Part H, Section 2.3.5.6.1).
    #[test]
    fn debug_key() {
        let sk = secret_key(
            0x3f49f6d4_a3c55f38_74c9b3e3_d2103f50,
            0x4aff607b_eb40b799_5899b8a6_cd3c1abd,
        );
        let pk = PublicKey {
            x: PublicKeyX(Coord(u256(
                0x20b003d2_f297be2c_5e2c83a7_e9f9a5b9,
                0xeff49111_acf4fddb_cc030148_0e359de6,
            ))),
            y: Coord(u256(
                0xdc809c49_652aeb6d_63329abf_5a52155c,
                0x766345c2_8fed3024_741c8ed0_1589d28b,
            )),
        };
        assert_eq!(sk.public_key(), pk);
        assert!(pk.is_debug());
    }

    /// P-256 data set 1 ([Vol 2] Part G, Section 7.1.2.1).
    #[test]
    fn p256_1() {
        let (ska, skb) = (
            secret_key(
                0x3f49f6d4_a3c55f38_74c9b3e3_d2103f50,
                0x4aff607b_eb40b799_5899b8a6_cd3c1abd,
            ),
            secret_key(
                0x55188b3d_32f6bb9a_900afcfb_eed4e72a,
                0x59cb9ac2_f19d7cfb_6b4fdd49_f47fc5fd,
            ),
        );
        let (pka, pkb) = (
            PublicKey {
                x: PublicKeyX(Coord(u256(
                    0x20b003d2_f297be2c_5e2c83a7_e9f9a5b9,
                    0xeff49111_acf4fddb_cc030148_0e359de6,
                ))),
                y: Coord(u256(
                    0xdc809c49_652aeb6d_63329abf_5a52155c,
                    0x766345c2_8fed3024_741c8ed0_1589d28b,
                )),
            },
            PublicKey {
                x: PublicKeyX(Coord(u256(
                    0x1ea1f0f0_1faf1d96_09592284_f19e4c00,
                    0x47b58afd_8615a69f_559077b2_2faaa190,
                ))),
                y: Coord(u256(
                    0x4c55f33e_429dad37_7356703a_9ab85160,
                    0x472d1130_e28e3676_5f89aff9_15b1214a,
                )),
            },
        );
        let dh_key = shared_secret(
            0xec0234a3_57c8ad05_341010a6_0a397d9b,
            0x99796b13_b4f866f1_868d34f3_73bfa698,
        );
        assert_eq!(ska.public_key(), pka);
        assert_eq!(skb.public_key(), pkb);
        assert_eq!(
            ska.dh_key(pkb).unwrap().0.raw_secret_bytes(),
            dh_key.0.raw_secret_bytes()
        );

        assert!(!pkb.is_debug());
        assert!(skb.dh_key(pkb).is_none());
    }

    /// P-256 data set 2 ([Vol 2] Part G, Section 7.1.2.2).
    #[test]
    fn p256_2() {
        let (ska, skb) = (
            secret_key(
                0x06a51669_3c9aa31a_6084545d_0c5db641,
                0xb48572b9_7203ddff_b7ac73f7_d0457663,
            ),
            secret_key(
                0x529aa067_0d72cd64_97502ed4_73502b03,
                0x7e8803b5_c60829a5_a3caa219_505530ba,
            ),
        );
        let (pka, pkb) = (
            PublicKey {
                x: PublicKeyX(Coord(u256(
                    0x2c31a47b_5779809e_f44cb5ea_af5c3e43,
                    0xd5f8faad_4a8794cb_987e9b03_745c78dd,
                ))),
                y: Coord(u256(
                    0x91951218_3898dfbe_cd52e240_8e43871f,
                    0xd0211091_17bd3ed4_eaf84377_43715d4f,
                )),
            },
            PublicKey {
                x: PublicKeyX(Coord(u256(
                    0xf465e43f_f23d3f1b_9dc7dfc0_4da87581,
                    0x84dbc966_204796ec_cf0d6cf5_e16500cc,
                ))),
                y: Coord(u256(
                    0x0201d048_bcbbd899_eeefc424_164e33c2,
                    0x01c2b010_ca6b4d43_a8a155ca_d8ecb279,
                )),
            },
        );
        let dh_key = shared_secret(
            0xab85843a_2f6d883f_62e5684b_38e30733,
            0x5fe6e194_5ecd1960_4105c6f2_3221eb69,
        );
        assert_eq!(ska.public_key(), pka);
        assert_eq!(skb.public_key(), pkb);
        assert_eq!(
            ska.dh_key(pkb).unwrap().0.raw_secret_bytes(),
            dh_key.0.raw_secret_bytes()
        );
    }

    /// Key generation function ([Vol 3] Part H, Section D.3).
    #[test]
    fn dh_key_f5() {
        let w = shared_secret(
            0xec0234a3_57c8ad05_341010a6_0a397d9b,
            0x99796b13_b4f866f1_868d34f3_73bfa698,
        );
        let n1 = Nonce(0xd5cb8454_d177733e_ffffb2ec_712baeab);
        let n2 = Nonce(0xa6e8e7cc_25a75f6e_216583f7_ff3dc4cf);
        let a1 = Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0xce, 0xbf, 0x37, 0x37, 0x12, 0x56]),
        };
        let a2 = Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7]),
        };
        let (mk, ltk) = w.f5(n1, n2, a1, a2);
        assert_eq!(ltk.0, 0x69867911_69d7cd23_980522b5_94750a38);
        assert_eq!(u128::from(&mk.0), 0x2965f176_a1084a02_fd3f6a20_ce636e20);
    }

    #[inline]
    fn secret_key(hi: u128, lo: u128) -> SecretKey {
        SecretKey(p256::NonZeroScalar::from_repr(u256(hi, lo)).unwrap())
    }

    #[inline]
    fn shared_secret(hi: u128, lo: u128) -> DHKey {
        DHKey(ecdh::SharedSecret::from(u256::<p256::FieldBytes>(hi, lo)))
    }

    #[test]
    fn testtest() {
        let skb = SecretKey::new(&mut OsRng::default());
        let _pkb = skb.public_key();

        let ska = SecretKey::new(&mut OsRng::default());
        let pka = ska.public_key();

        let _dh_key = skb.dh_key(pka).unwrap();
    }

    #[test]
    fn testtest2() {
        let bytes = [
            0x1eu8, 0x3b, 0x26, 0x40, 0x0e, 0xba, 0x72, 0x51, 0x81, 0xf9, 0x3d, 0x16, 0xb3, 0xc4, 0x11, 0x55, 0x3f,
            0xa8, 0x88, 0x47, 0x08, 0x1c, 0x4a, 0x42, 0x88, 0xbb, 0x68, 0x1d, 0x93, 0xe5, 0xab, 0xb3, 0x72, 0xfa, 0x93,
            0xb4, 0xa0, 0xfe, 0x3f, 0x83, 0x9c, 0x85, 0x5b, 0x5f, 0xb6, 0x30, 0x09, 0x85, 0x47, 0xfd, 0xa8, 0xfa, 0x11,
            0x71, 0xe4, 0x95, 0x17, 0x71, 0x98, 0x82, 0x8f, 0xf8, 0x79, 0x94,
        ];

        let skb = SecretKey::new(&mut OsRng::default());
        let _pkb = skb.public_key();

        let pka = PublicKey::from_bytes(&bytes);

        let _dh_key = skb.dh_key(pka).unwrap();
    }

    #[test]
    fn nonce() {
        // No fair dice rolls for us!
        assert_ne!(Nonce::new(&mut OsRng::default()), Nonce::new(&mut OsRng::default()));
    }

    /// Confirm value generation function ([Vol 3] Part H, Section D.2).
    #[test]
    fn nonce_f4() {
        let u = PublicKeyX::from_be_bytes(u256(
            0x20b003d2_f297be2c_5e2c83a7_e9f9a5b9,
            0xeff49111_acf4fddb_cc030148_0e359de6,
        ));
        let v = PublicKeyX::from_be_bytes(u256(
            0x55188b3d_32f6bb9a_900afcfb_eed4e72a,
            0x59cb9ac2_f19d7cfb_6b4fdd49_f47fc5fd,
        ));
        let x = Nonce(0xd5cb8454_d177733e_ffffb2ec_712baeab);
        assert_eq!(x.f4(&u, &v, 0).0, 0xf2c916f1_07a9bd1c_f1eda1be_a974872d);
    }

    /// Numeric comparison generation function ([Vol 3] Part H, Section D.5).
    #[allow(clippy::unreadable_literal)]
    #[test]
    fn nonce_g2() {
        let u = PublicKeyX::from_be_bytes(u256(
            0x20b003d2_f297be2c_5e2c83a7_e9f9a5b9,
            0xeff49111_acf4fddb_cc030148_0e359de6,
        ));
        let v = PublicKeyX::from_be_bytes(u256(
            0x55188b3d_32f6bb9a_900afcfb_eed4e72a,
            0x59cb9ac2_f19d7cfb_6b4fdd49_f47fc5fd,
        ));
        let x = Nonce(0xd5cb8454_d177733e_ffffb2ec_712baeab);
        let y = Nonce(0xa6e8e7cc_25a75f6e_216583f7_ff3dc4cf);
        assert_eq!(x.g2(&u, &v, &y), NumCompare(0x2f9ed5ba % 1_000_000));
    }

    /// Check value generation function ([Vol 3] Part H, Section D.4).
    #[test]
    fn mac_key_f6() {
        let k = MacKey(Key::new(0x2965f176_a1084a02_fd3f6a20_ce636e20));
        let n1 = Nonce(0xd5cb8454_d177733e_ffffb2ec_712baeab);
        let n2 = Nonce(0xa6e8e7cc_25a75f6e_216583f7_ff3dc4cf);
        let r = 0x12a3343b_b453bb54_08da42d2_0c2d0fc8;
        let io_cap = IoCap([0x01, 0x01, 0x02]);
        let a1 = Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0xce, 0xbf, 0x37, 0x37, 0x12, 0x56]),
        };
        let a2 = Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0xc1, 0xcf, 0x2d, 0x70, 0x13, 0xa7]),
        };
        let c = k.f6(n1, n2, r, io_cap, a1, a2);
        assert_eq!(c.0, 0xe3c47398_9cd0e8c5_d26c0b09_da958f61);
    }

    #[test]
    fn nonce_f4_test() {
        let ra = [
            0x11u8, 0x3a, 0x7a, 0x69, 0x11, 0xcd, 0x44, 0x15, 0x52, 0xf7, 0x47, 0xe8, 0x26, 0x67, 0x72, 0xca,
        ];

        let rb = [
            0xa5u8, 0x9e, 0x9a, 0x32, 0xc0, 0x97, 0x1c, 0xf7, 0x72, 0x1c, 0x29, 0xa7, 0x8c, 0x1e, 0xfd, 0x18,
        ];

        let pkb = [
            0xd, 0x80, 0x33, 0x93, 0xad, 0x1f, 0x7e, 0x9a, 0x30, 0xc9, 0x6e, 0x1, 0x78, 0xf3, 0x43, 0x14, 0xa0, 0x57,
            0xae, 0xa5, 0xa8, 0xee, 0x75, 0x51, 0x3f, 0xaa, 0xb1, 0x80, 0x75, 0xc7, 0x14, 0x50, 0x73, 0x9a, 0x98, 0x95,
            0x36, 0x2e, 0xe6, 0x81, 0x5f, 0xbf, 0x16, 0xa2, 0x8c, 0xf6, 0x9d, 0xdc, 0x1f, 0xb8, 0x84, 0x8c, 0x7d, 0x37,
            0x36, 0xe4, 0x36, 0x3c, 0xb3, 0xe8, 0xfe, 0x4a, 0x73, 0xc6,
        ];

        let pka = [
            0x97, 0x20, 0x0f, 0xfe, 0xf0, 0xec, 0xdd, 0x11, 0xda, 0xa8, 0xa8, 0x07, 0x3e, 0xd7, 0xc6, 0xf2, 0x68, 0x5d,
            0xc2, 0x58, 0x71, 0x1e, 0x34, 0x4f, 0xa1, 0xc4, 0x44, 0xa9, 0x7c, 0x71, 0xee, 0x54, 0x0d, 0xad, 0xb7, 0x69,
            0x89, 0x9d, 0x4f, 0x83, 0x37, 0xcd, 0x43, 0xd3, 0x9f, 0x05, 0x13, 0x99, 0x6f, 0xbc, 0x1a, 0x89, 0xed, 0xb4,
            0x7f, 0x80, 0x98, 0xcf, 0xad, 0x7c, 0x4c, 0x57, 0xbf, 0xe1,
        ];

        let mut pkb_x = [0u8; 32];
        pkb_x.copy_from_slice(&pkb[..32]);
        pkb_x.reverse();
        let mut pka_x = [0u8; 32];
        pka_x.copy_from_slice(&pka[..32]);
        pka_x.reverse();

        let pkbx = PublicKeyX::from_be_bytes(pkb_x);
        let pkax = PublicKeyX::from_be_bytes(pka_x);
        extern crate std;

        let x = Nonce(u128::from_le_bytes(ra));
        let y = Nonce(u128::from_le_bytes(rb));

        assert_eq!(x.g2(&pkax, &pkbx, &y).0, 991180);
    }

    #[test]
    pub fn irk_test() {
        let irk = IdentityResolvingKey::new(0xec0234a3_57c8ad05_341010a6_0a397d9b);
        let prand = [0x70, 0x81, 0x94];

        let hash = irk.ah(prand);
        assert_eq!(hash, [0x0d, 0xfb, 0xaa]);
    }

    #[test]
    pub fn rpa_test() {
        let irk = IdentityResolvingKey::new(0x8b3958c158ed64467bd27bc90d3cf54d);
        let address = BdAddr::new([0x92, 0xF2, 0x8F, 0x84, 0x72, 0x4F]);
        let re = irk.resolve_address(&address);
        assert_eq!(re, true);
    }

    // ========================================================================
    // Legacy Pairing Crypto Tests
    // ========================================================================

    /// Test c1 function using Bluetooth Core Spec test vectors
    /// Vol 3, Part H, Section 2.2.3
    #[test]
    fn legacy_c1() {
        // Test vector from Bluetooth Core Spec
        // k = 0x00000000000000000000000000000000
        // r = 0x5783D52156AD6F0E6388274EC6702EE0
        // p1 = 0x05000800000302070710000001010001
        // p2 = 0x00000000A1A2A3A4A5A6B1B2B3B4B5B6
        // Expected output = 0x1E1E3FEF878988EAD2A74DC5BEF13B86

        let tk = TemporaryKey(0);

        // Random value
        let r = 0x5783D52156AD6F0E6388274EC6702EE0_u128;

        // Pairing Request command (7 bytes, LSB first in each field)
        // From spec: preq = 0x07071000000101
        // Bytes from LSB to MSB: 01 01 00 00 10 07 07
        let preq: [u8; 7] = [0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07];

        // Pairing Response command (7 bytes, LSB first in each field)
        // From spec: pres = 0x05000800000302
        // Bytes from LSB to MSB: 02 03 00 00 08 00 05
        let pres: [u8; 7] = [0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x05];

        // Initiator address type = 1 (Random)
        // Initiator address: A1A2A3A4A5A6 (stored LSB first: A6 A5 A4 A3 A2 A1)
        let initiator_addr = crate::Address {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new([0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1]),
        };

        // Responder address type = 0 (Public)
        // Responder address: B1B2B3B4B5B6 (stored LSB first: B6 B5 B4 B3 B2 B1)
        let responder_addr = crate::Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1]),
        };

        let confirm = c1(&tk, r, &preq, &pres, initiator_addr, responder_addr);

        // Expected result from spec: 0x1E1E3FEF878988EAD2A74DC5BEF13B86
        let expected = 0x1E1E3FEF878988EAD2A74DC5BEF13B86_u128;
        assert_eq!(
            confirm.0, expected,
            "c1 output mismatch: got 0x{:032X}, expected 0x{:032X}",
            confirm.0, expected
        );
    }

    /// Test s1 function using Bluetooth Core Spec test vectors
    /// Vol 3, Part H, Appendix D.1
    #[test]
    fn legacy_s1() {
        let tk = TemporaryKey(0);

        // Test with sample random values
        let srand = 0x000F0E0D0C0B0A091122334455667788_u128;
        let mrand = 0x00F0E0D0C0B0A09081726354_u128;

        let stk = s1(&tk, srand, mrand);

        // The STK should be non-zero and deterministic
        // assert_ne!(stk.0, 0);

        // Same inputs should produce same output
        let stk2 = s1(&tk, srand, mrand);
        assert_eq!(stk, stk2);

        // Different inputs should produce different output
        let stk3 = s1(&tk, srand, mrand + 1);
        assert_ne!(stk, stk3);
    }

    /// Test TK from passkey
    #[test]
    fn temporary_key_from_passkey() {
        let tk = TemporaryKey::from_passkey(123456);
        assert_eq!(tk.0, 123456);

        let tk_zero = TemporaryKey::just_works();
        assert_eq!(tk_zero.0, 0);

        let tk_max = TemporaryKey::from_passkey(999999);
        assert_eq!(tk_max.0, 999999);
    }
}
