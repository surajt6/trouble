use bt_hci::param::AddrKind;

use crate::pdu::Pdu;
use crate::prelude::SecurityLevel;
use crate::security_manager::crypto::{Check, Confirm, DHKey, LegacyConfirm, MacKey, Nonce, PublicKey};
use crate::security_manager::types::{Command, Ediv, KeyDistributionFlags, PairingFeatures, Rand, UseOutOfBand};
use crate::security_manager::{Reason, TxPacket};
use crate::{Address, Error, IdentityResolvingKey, IoCapabilities, LongTermKey, PacketPool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PassKeyEntryAction {
    Display,
    Input,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairingMethod {
    JustWorks,
    NumericComparison,
    PassKeyEntry {
        central: PassKeyEntryAction,
        peripheral: PassKeyEntryAction,
    },
    OutOfBand,
}

impl PairingMethod {
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            PairingMethod::JustWorks => SecurityLevel::Encrypted,
            _ => SecurityLevel::EncryptedAuthenticated,
        }
    }
}

pub fn choose_pairing_method(central: PairingFeatures, peripheral: PairingFeatures) -> PairingMethod {
    if !central.security_properties.man_in_the_middle() && !peripheral.security_properties.man_in_the_middle() {
        PairingMethod::JustWorks
    } else if matches!(central.use_oob, UseOutOfBand::Present) || matches!(peripheral.use_oob, UseOutOfBand::Present) {
        PairingMethod::OutOfBand
    } else if peripheral.io_capabilities == IoCapabilities::DisplayOnly {
        match central.io_capabilities {
            IoCapabilities::KeyboardOnly | IoCapabilities::KeyboardDisplay => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Display,
            },
            _ => PairingMethod::JustWorks,
        }
    } else if peripheral.io_capabilities == IoCapabilities::DisplayYesNo {
        match central.io_capabilities {
            IoCapabilities::DisplayYesNo | IoCapabilities::KeyboardDisplay => PairingMethod::NumericComparison,
            IoCapabilities::KeyboardOnly => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Display,
            },
            _ => PairingMethod::JustWorks,
        }
    } else if peripheral.io_capabilities == IoCapabilities::KeyboardOnly {
        match central.io_capabilities {
            IoCapabilities::NoInputNoOutput => PairingMethod::JustWorks,
            IoCapabilities::KeyboardOnly => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Input,
            },
            _ => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Display,
                peripheral: PassKeyEntryAction::Input,
            },
        }
    } else if peripheral.io_capabilities == IoCapabilities::NoInputNoOutput {
        PairingMethod::JustWorks
    } else {
        // Local io == keyboard display
        match central.io_capabilities {
            IoCapabilities::DisplayOnly => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Display,
                peripheral: PassKeyEntryAction::Input,
            },
            IoCapabilities::KeyboardDisplay => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Display,
            },
            IoCapabilities::NoInputNoOutput => PairingMethod::JustWorks,
            _ => PairingMethod::NumericComparison,
        }
    }
}

// ============================================================================
// Legacy Pairing Method Selection
// ============================================================================

/// Determines if legacy pairing should be used based on both devices' features.
///
/// Legacy pairing is used when either device does NOT have the Secure Connections
/// bit set in their AuthReq field.
pub fn is_legacy_pairing(central: &PairingFeatures, peripheral: &PairingFeatures) -> bool {
    !central.security_properties.secure_connection() || !peripheral.security_properties.secure_connection()
}

/// IO action for legacy pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LegacyIoAction {
    /// No action required (Just Works)
    None,
    /// Display passkey to user
    Display,
    /// User must input passkey
    Input,
}

/// Legacy pairing method (no Numeric Comparison in legacy)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LegacyPairingMethod {
    /// Just Works - TK = 0, no MITM protection
    JustWorks,
    /// Passkey Entry - TK = passkey, MITM protection
    PasskeyEntry {
        /// Action for the central/initiator
        central: LegacyIoAction,
        /// Action for the peripheral/responder
        peripheral: LegacyIoAction,
    },
}

impl LegacyPairingMethod {
    /// Returns the security level achieved by this pairing method
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            LegacyPairingMethod::JustWorks => SecurityLevel::Encrypted,
            LegacyPairingMethod::PasskeyEntry { .. } => SecurityLevel::EncryptedAuthenticated,
        }
    }

    /// Returns true if this method provides MITM protection
    pub fn is_authenticated(&self) -> bool {
        !matches!(self, LegacyPairingMethod::JustWorks)
    }
}

/// Legacy pairing IO capability matrix for initiator actions.
///
/// Bluetooth Core Spec Vol 3, Part H, Table 2.8
/// Index: [responder_io_cap][initiator_io_cap]
const LEGACY_INITIATOR_IO: [[LegacyIoAction; 5]; 5] = [
    // Responder: DisplayOnly (0)
    //            InitDisp    InitDispYN  InitKbd     InitNoIO    InitKbdDisp
    [
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::Input,
        LegacyIoAction::None,
        LegacyIoAction::Input,
    ],
    // Responder: DisplayYesNo (1)
    [
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::Input,
        LegacyIoAction::None,
        LegacyIoAction::Input,
    ],
    // Responder: KeyboardOnly (2)
    [
        LegacyIoAction::Display,
        LegacyIoAction::Display,
        LegacyIoAction::Input,
        LegacyIoAction::None,
        LegacyIoAction::Display,
    ],
    // Responder: NoInputNoOutput (3)
    [
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::None,
    ],
    // Responder: KeyboardDisplay (4)
    [
        LegacyIoAction::Display,
        LegacyIoAction::Display,
        LegacyIoAction::Input,
        LegacyIoAction::None,
        LegacyIoAction::Display,
    ],
];

/// Legacy pairing IO capability matrix for responder actions.
///
/// Bluetooth Core Spec Vol 3, Part H, Table 2.8
/// Index: [responder_io_cap][initiator_io_cap]
const LEGACY_RESPONDER_IO: [[LegacyIoAction; 5]; 5] = [
    // Responder: DisplayOnly (0)
    //            InitDisp    InitDispYN  InitKbd     InitNoIO    InitKbdDisp
    [
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::Display,
        LegacyIoAction::None,
        LegacyIoAction::Display,
    ],
    // Responder: DisplayYesNo (1)
    [
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::Display,
        LegacyIoAction::None,
        LegacyIoAction::Display,
    ],
    // Responder: KeyboardOnly (2)
    [
        LegacyIoAction::Input,
        LegacyIoAction::Input,
        LegacyIoAction::Input,
        LegacyIoAction::None,
        LegacyIoAction::Input,
    ],
    // Responder: NoInputNoOutput (3)
    [
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::None,
        LegacyIoAction::None,
    ],
    // Responder: KeyboardDisplay (4)
    [
        LegacyIoAction::Input,
        LegacyIoAction::Input,
        LegacyIoAction::Display,
        LegacyIoAction::None,
        LegacyIoAction::Input,
    ],
];

/// Chooses the legacy pairing method based on IO capabilities.
///
/// Note: Legacy pairing does NOT support Numeric Comparison - that's LESC only.
/// OOB is also handled separately (not implemented in this version).
///
/// # Arguments
/// * `central` - Central/Initiator's pairing features
/// * `peripheral` - Peripheral/Responder's pairing features
pub fn choose_legacy_pairing_method(central: &PairingFeatures, peripheral: &PairingFeatures) -> LegacyPairingMethod {
    // No MITM required from either side = Just Works
    if !central.security_properties.man_in_the_middle() && !peripheral.security_properties.man_in_the_middle() {
        return LegacyPairingMethod::JustWorks;
    }

    // Look up in IO capability tables
    let init_cap = central.io_capabilities as usize;
    let resp_cap = peripheral.io_capabilities as usize;

    // Bounds check (should never fail with valid IoCapabilities)
    if init_cap >= 5 || resp_cap >= 5 {
        return LegacyPairingMethod::JustWorks;
    }

    let init_action = LEGACY_INITIATOR_IO[resp_cap][init_cap];
    let resp_action = LEGACY_RESPONDER_IO[resp_cap][init_cap];

    // If both actions are None, use Just Works
    if init_action == LegacyIoAction::None && resp_action == LegacyIoAction::None {
        LegacyPairingMethod::JustWorks
    } else {
        LegacyPairingMethod::PasskeyEntry {
            central: init_action,
            peripheral: resp_action,
        }
    }
}

/// Returns the IO action for a specific role in legacy pairing.
///
/// # Arguments
/// * `method` - The legacy pairing method
/// * `is_central` - True if asking for central's action, false for peripheral's
pub fn legacy_io_action_for_role(method: &LegacyPairingMethod, is_central: bool) -> LegacyIoAction {
    match method {
        LegacyPairingMethod::JustWorks => LegacyIoAction::None,
        LegacyPairingMethod::PasskeyEntry { central, peripheral } => {
            if is_central {
                *central
            } else {
                *peripheral
            }
        }
    }
}

// ============================================================================
// Packet Construction Helpers
// ============================================================================

pub fn prepare_packet<P: PacketPool>(command: Command) -> Result<TxPacket<P>, Error> {
    let packet = P::allocate().ok_or(Error::OutOfMemory)?;
    TxPacket::new(packet, command)
}

pub fn make_pairing_random<P: PacketPool>(nonce: &Nonce) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingRandom)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&nonce.0.to_le_bytes());
    Ok(packet)
}

pub fn make_public_key_packet<P: PacketPool>(public_key: &PublicKey) -> Result<TxPacket<P>, Error> {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(public_key.x.as_be_bytes());
    y.copy_from_slice(public_key.y.as_be_bytes());
    x.reverse();
    y.reverse();
    let mut packet = prepare_packet(Command::PairingPublicKey)?;

    let response = packet.payload_mut();

    response[..x.len()].copy_from_slice(&x);
    response[x.len()..y.len() + x.len()].copy_from_slice(&y);
    Ok(packet)
}

pub fn make_dhkey_check_packet<P: PacketPool>(check: &Check) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet(Command::PairingDhKeyCheck)?;
    let response = packet.payload_mut();
    let bytes = check.0.to_le_bytes();
    response[..bytes.len()].copy_from_slice(&bytes);
    Ok(packet)
}

pub fn make_mac_and_ltk(
    dh_key: &DHKey,
    central_nonce: &Nonce,
    peripheral_nonce: &Nonce,
    central_address: Address,
    peripheral_address: Address,
) -> (MacKey, LongTermKey) {
    dh_key.f5(*central_nonce, *peripheral_nonce, central_address, peripheral_address)
}

pub fn make_confirm_packet<P: PacketPool>(confirm: &Confirm) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingConfirm)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&confirm.0.to_le_bytes());
    Ok(packet)
}

/// Creates a legacy pairing confirm packet.
pub fn make_legacy_confirm_packet<P: PacketPool>(confirm: &LegacyConfirm) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingConfirm)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&confirm.to_le_bytes());
    Ok(packet)
}

/// Creates a legacy pairing random packet.
pub fn make_legacy_random_packet<P: PacketPool>(random: u128) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingRandom)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&random.to_le_bytes());
    Ok(packet)
}

// ============================================================================
// Key Distribution Packet Construction Helpers
// ============================================================================

/// Count the number of keys to be distributed based on flags.
///
/// For LESC pairing, EncryptionKey flag typically results in 0 additional packets
/// since both sides derive the same LTK. For legacy pairing, it's 2 packets
/// (EncryptionInformation + CentralIdentification).
///
/// This function returns the count assuming legacy pairing semantics where
/// each key type may have associated packets.
pub fn count_keys_to_distribute(flags: KeyDistributionFlags, is_legacy: bool) -> i32 {
    let mut count = 0;
    if flags.encryption_key() {
        if is_legacy {
            count += 2; // EncryptionInformation + CentralIdentification
        }
        // For LESC, encryption key is typically not distributed (both derive same LTK)
    }
    if flags.identity_key() {
        count += 2; // IdentityInformation + IdentityAddressInformation
    }
    if flags.signing_key() {
        count += 1; // SigningInformation
    }
    // Link key is for BR/EDR, ignored for LE-only
    count
}

/// Create EncryptionInformation packet (LTK distribution).
/// Payload: 16 bytes LTK in little-endian.
pub fn make_encryption_information_packet<P: PacketPool>(ltk: &LongTermKey) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::EncryptionInformation)?;
    let payload = packet.payload_mut();
    payload.copy_from_slice(&ltk.0.to_le_bytes());
    Ok(packet)
}

/// Create CentralIdentification packet (EDIV + Rand for legacy LTK identification).
/// Payload: 2 bytes EDIV + 8 bytes Rand, both little-endian.
pub fn make_central_identification_packet<P: PacketPool>(ediv: Ediv, rand: Rand) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::CentralIdentification)?;
    let payload = packet.payload_mut();
    payload[0..2].copy_from_slice(&ediv.to_le_bytes());
    payload[2..10].copy_from_slice(&rand.to_le_bytes());
    Ok(packet)
}

/// Create IdentityInformation packet (IRK distribution).
/// Payload: 16 bytes IRK in little-endian.
pub fn make_identity_information_packet<P: PacketPool>(irk: &IdentityResolvingKey) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::IdentityInformation)?;
    let payload = packet.payload_mut();
    payload.copy_from_slice(&irk.0.to_le_bytes());
    Ok(packet)
}

/// Create IdentityAddressInformation packet (BD_ADDR distribution).
/// Payload: 1 byte address type (0x00=public, 0x01=random) + 6 bytes BD_ADDR.
pub fn make_identity_address_information_packet<P: PacketPool>(address: &Address) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::IdentityAddressInformation)?;
    let payload = packet.payload_mut();
    payload[0] = match address.kind {
        AddrKind::PUBLIC => 0x00,
        AddrKind::RANDOM => 0x01,
        _ => 0x00, // Default to public for other types
    };
    payload[1..7].copy_from_slice(address.addr.raw());
    Ok(packet)
}

/// Create SigningInformation packet (CSRK distribution).
/// Payload: 16 bytes CSRK in little-endian.
pub fn make_signing_information_packet<P: PacketPool>(csrk: u128) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::SigningInformation)?;
    let payload = packet.payload_mut();
    payload.copy_from_slice(&csrk.to_le_bytes());
    Ok(packet)
}

#[derive(Debug, Clone)]
pub struct CommandAndPayload<'a> {
    pub command: Command,
    pub payload: &'a [u8],
}

impl<'a> CommandAndPayload<'a> {
    pub fn try_parse<P: PacketPool>(pdu: Pdu<P::Packet>, buffer: &'a mut [u8]) -> Result<Self, Error> {
        let size = {
            let size = pdu.len().min(buffer.len());
            buffer[..size].copy_from_slice(&pdu.as_ref()[..size]);
            size
        };
        if size < 2 {
            error!("[security manager] Payload size too small {}", size);
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let payload = &buffer[1..size];
        let command = buffer[0];

        let command = match Command::try_from(command) {
            Ok(command) => {
                if usize::from(command.payload_size()) != payload.len() {
                    error!("[security manager] Payload size mismatch for command {}", command);
                    return Err(Error::Security(Reason::InvalidParameters));
                }
                command
            }
            Err(_) => return Err(Error::Security(Reason::CommandNotSupported)),
        };

        Ok(Self { command, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_manager::types::{AuthReq, BondingFlag};

    #[test]
    fn oob_used() {
        for p_oob in 0..1 {
            for c_oob in 0..1 {
                let p_oob = if p_oob == 1 {
                    UseOutOfBand::Present
                } else {
                    UseOutOfBand::NotPresent
                };
                let c_oob = if c_oob == 1 {
                    UseOutOfBand::Present
                } else {
                    UseOutOfBand::NotPresent
                };
                for p in 0u8..5 {
                    for c in 0u8..5 {
                        let peripheral = PairingFeatures {
                            io_capabilities: p.try_into().unwrap(),
                            use_oob: p_oob,
                            security_properties: AuthReq::new(BondingFlag::NoBonding),
                            initiator_key_distribution: 0.into(),
                            responder_key_distribution: 0.into(),
                            maximum_encryption_key_size: 16,
                        };
                        let mut central = peripheral.clone();
                        central.use_oob = c_oob;
                        central.io_capabilities = c.try_into().unwrap();
                        if p_oob == UseOutOfBand::NotPresent && c_oob == UseOutOfBand::NotPresent {
                            assert_ne!(choose_pairing_method(central, peripheral), PairingMethod::OutOfBand);
                        } else {
                            assert_eq!(choose_pairing_method(central, peripheral), PairingMethod::OutOfBand);
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Legacy Pairing Tests
    // ========================================================================

    #[test]
    fn is_legacy_when_no_sc_bit() {
        // Both have SC bit = not legacy
        let central_sc = PairingFeatures {
            io_capabilities: IoCapabilities::NoInputNoOutput,
            use_oob: UseOutOfBand::NotPresent,
            security_properties: AuthReq::new(BondingFlag::NoBonding), // Has SC bit
            initiator_key_distribution: 0.into(),
            responder_key_distribution: 0.into(),
            maximum_encryption_key_size: 16,
        };
        let peripheral_sc = central_sc.clone();
        assert!(!is_legacy_pairing(&central_sc, &peripheral_sc));

        // Central without SC = legacy
        let central_no_sc = PairingFeatures {
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, true),
            ..central_sc.clone()
        };
        assert!(is_legacy_pairing(&central_no_sc, &peripheral_sc));

        // Peripheral without SC = legacy
        let peripheral_no_sc = PairingFeatures {
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, true),
            ..peripheral_sc.clone()
        };
        assert!(is_legacy_pairing(&central_sc, &peripheral_no_sc));

        // Both without SC = legacy
        assert!(is_legacy_pairing(&central_no_sc, &peripheral_no_sc));
    }

    #[test]
    fn legacy_just_works_when_no_mitm() {
        // Neither requests MITM = Just Works
        let central = PairingFeatures {
            io_capabilities: IoCapabilities::KeyboardDisplay,
            use_oob: UseOutOfBand::NotPresent,
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, false), // No MITM
            initiator_key_distribution: 0.into(),
            responder_key_distribution: 0.into(),
            maximum_encryption_key_size: 16,
        };
        let peripheral = central.clone();

        let method = choose_legacy_pairing_method(&central, &peripheral);
        assert_eq!(method, LegacyPairingMethod::JustWorks);
    }

    #[test]
    fn legacy_just_works_when_no_io() {
        // Both NoInputNoOutput with MITM = Just Works (can't do passkey)
        let central = PairingFeatures {
            io_capabilities: IoCapabilities::NoInputNoOutput,
            use_oob: UseOutOfBand::NotPresent,
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, true), // MITM requested
            initiator_key_distribution: 0.into(),
            responder_key_distribution: 0.into(),
            maximum_encryption_key_size: 16,
        };
        let peripheral = central.clone();

        let method = choose_legacy_pairing_method(&central, &peripheral);
        assert_eq!(method, LegacyPairingMethod::JustWorks);
    }

    #[test]
    fn legacy_passkey_central_displays() {
        // Central: DisplayOnly, Peripheral: KeyboardOnly with MITM
        // Central should display, Peripheral should input
        let central = PairingFeatures {
            io_capabilities: IoCapabilities::DisplayOnly,
            use_oob: UseOutOfBand::NotPresent,
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, true),
            initiator_key_distribution: 0.into(),
            responder_key_distribution: 0.into(),
            maximum_encryption_key_size: 16,
        };
        let peripheral = PairingFeatures {
            io_capabilities: IoCapabilities::KeyboardOnly,
            ..central.clone()
        };

        let method = choose_legacy_pairing_method(&central, &peripheral);
        assert_eq!(
            method,
            LegacyPairingMethod::PasskeyEntry {
                central: LegacyIoAction::Display,
                peripheral: LegacyIoAction::Input,
            }
        );
    }

    #[test]
    fn legacy_passkey_central_inputs() {
        // Central: KeyboardOnly, Peripheral: DisplayOnly with MITM
        // Central should input, Peripheral should display
        let central = PairingFeatures {
            io_capabilities: IoCapabilities::KeyboardOnly,
            use_oob: UseOutOfBand::NotPresent,
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, true),
            initiator_key_distribution: 0.into(),
            responder_key_distribution: 0.into(),
            maximum_encryption_key_size: 16,
        };
        let peripheral = PairingFeatures {
            io_capabilities: IoCapabilities::DisplayOnly,
            ..central.clone()
        };

        let method = choose_legacy_pairing_method(&central, &peripheral);
        assert_eq!(
            method,
            LegacyPairingMethod::PasskeyEntry {
                central: LegacyIoAction::Input,
                peripheral: LegacyIoAction::Display,
            }
        );
    }

    #[test]
    fn legacy_passkey_both_keyboard() {
        // Both KeyboardOnly with MITM = both input same passkey
        let central = PairingFeatures {
            io_capabilities: IoCapabilities::KeyboardOnly,
            use_oob: UseOutOfBand::NotPresent,
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding, true),
            initiator_key_distribution: 0.into(),
            responder_key_distribution: 0.into(),
            maximum_encryption_key_size: 16,
        };
        let peripheral = central.clone();

        let method = choose_legacy_pairing_method(&central, &peripheral);
        assert_eq!(
            method,
            LegacyPairingMethod::PasskeyEntry {
                central: LegacyIoAction::Input,
                peripheral: LegacyIoAction::Input,
            }
        );
    }

    #[test]
    fn legacy_io_action_helper() {
        let method = LegacyPairingMethod::PasskeyEntry {
            central: LegacyIoAction::Display,
            peripheral: LegacyIoAction::Input,
        };

        assert_eq!(legacy_io_action_for_role(&method, true), LegacyIoAction::Display);
        assert_eq!(legacy_io_action_for_role(&method, false), LegacyIoAction::Input);

        let just_works = LegacyPairingMethod::JustWorks;
        assert_eq!(legacy_io_action_for_role(&just_works, true), LegacyIoAction::None);
        assert_eq!(legacy_io_action_for_role(&just_works, false), LegacyIoAction::None);
    }
}
