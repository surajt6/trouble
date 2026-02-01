use core::cell::RefCell;
use core::ops::{Deref, DerefMut};

use embassy_time::Instant;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
use crate::security_manager::crypto::{
    c1, s1, Confirm, DHKey, LegacyConfirm, MacKey, Nonce, PublicKey, SecretKey, ShortTermKey, TemporaryKey,
};
use crate::security_manager::pairing::util::{
    choose_legacy_pairing_method, choose_pairing_method, count_keys_to_distribute, is_legacy_pairing,
    legacy_io_action_for_role, make_central_identification_packet, make_confirm_packet, make_dhkey_check_packet,
    make_encryption_information_packet, make_identity_address_information_packet, make_identity_information_packet,
    make_legacy_confirm_packet, make_legacy_random_packet, make_pairing_random, make_public_key_packet,
    make_signing_information_packet, prepare_packet, CommandAndPayload, LegacyIoAction, LegacyPairingMethod,
    PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingOps};
use crate::security_manager::types::{AuthReq, BondingFlag, Command, Ediv, PairingFeatures, Rand};
use crate::security_manager::{PassKey, Reason};
use crate::{
    AddrKind, Address, BdAddr, BondInformation, Error, IdentityResolvingKey, IoCapabilities, LongTermKey, PacketPool,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Step {
    Idle,
    WaitingPairingResponse(PairingRequestSentTag),
    WaitingPublicKey,
    // Numeric comparison (LESC)
    WaitingNumericComparisonConfirm,
    WaitingNumericComparisonRandom,
    WaitingNumericComparisonResult,
    // Pass key entry (LESC)
    WaitingPassKeyInput,
    WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag),
    WaitingPassKeyEntryRandom(i32),
    // TODO add OOB
    WaitingDHKeyEb(DHKeyEaSentTag),
    // Legacy pairing states
    /// Waiting for TK input from user (legacy passkey entry)
    LegacyWaitingTkInput,
    /// Waiting for peer's confirm value (legacy)
    LegacyWaitingConfirm(LegacyConfirmSentTag),
    /// Waiting for peer's random value (legacy)
    LegacyWaitingRandom,
    // Common states
    WaitingLinkEncrypted,
    WaitingBondedLinkEncryption,
    ReceivingKeys(i32),
    SendingKeys(i32),
    Success,
    Error(Error),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct PairingRequestSentTag {}

impl PairingRequestSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>>(pairing_data: &mut PairingData, ops: &mut OPS) -> Result<Self, Error> {
        let mut packet = prepare_packet::<P>(Command::PairingRequest)?;

        let payload = packet.payload_mut();
        pairing_data
            .local_features
            .encode(payload)
            .map_err(|_| Error::InvalidValue)?;

        match ops.try_send_packet(packet) {
            Ok(_) => {}
            Err(error) => {
                error!("[smp] Failed to respond to request {:?}", error);
                return Err(error);
            }
        }

        Ok(Self {})
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct PassKeyEntryConfirmSentTag(i32);

impl PassKeyEntryConfirmSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        round: i32,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<PassKeyEntryConfirmSentTag, Error> {
        pairing_data.local_nonce = Nonce::new(rng);
        let rai = 0x80u8 | (((pairing_data.local_secret_ra & (1 << round as u128)) >> (round as u128)) as u8);
        let cai = pairing_data.local_nonce.f4(
            pairing_data.local_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            pairing_data.peer_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            rai,
        );
        let confirm = make_confirm_packet(&cai)?;
        ops.try_send_packet(confirm)?;
        Ok(PassKeyEntryConfirmSentTag(round))
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DHKeyEaSentTag {}

impl DHKeyEaSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<DHKeyEaSentTag, Error> {
        let (mac, ltk) = {
            let dh_key = pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?;
            dh_key.f5(
                pairing_data.local_nonce,
                pairing_data.peer_nonce,
                pairing_data.local_address,
                pairing_data.peer_address,
            )
        };

        let ea = mac.f6(
            pairing_data.local_nonce,
            pairing_data.peer_nonce,
            pairing_data.peer_secret_rb,
            pairing_data.local_features.as_io_cap(),
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        let check = make_dhkey_check_packet(&ea)?;
        ops.try_send_packet(check)?;
        pairing_data.mac_key = Some(mac);
        pairing_data.ltk = Some(ltk);
        Ok(DHKeyEaSentTag {})
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct LegacyConfirmSentTag {}

impl LegacyConfirmSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let legacy = pairing_data.legacy_data.as_mut().ok_or(Error::InvalidValue)?;

        // Generate our random value (Mrand for central/initiator)
        let mut rand_bytes = [0u8; 16];
        rng.fill_bytes(&mut rand_bytes);
        legacy.local_rand = u128::from_le_bytes(rand_bytes);
        info!("Confirm value Rand bytes: {:?}", legacy.local_rand);

        // Calculate confirm value using c1 function
        let confirm = c1(
            &legacy.tk,
            legacy.local_rand,
            &legacy.pairing_request,
            &legacy.pairing_response,
            pairing_data.local_address,
            pairing_data.peer_address,
        );
        info!("legacy.pairing_request: {:?}", &legacy.pairing_request);
        info!("legacy.pairing_response: {:?}", &legacy.pairing_response);
        // info!("Confirm value: {:?}", confirm);

        // Send confirm packet
        let packet = make_legacy_confirm_packet::<P>(&confirm)?;
        ops.try_send_packet(packet)?;

        Ok(Self {})
    }
}

/// Legacy pairing specific data
#[derive(Debug, Clone)]
struct LegacyPairingData {
    /// Temporary Key (from passkey or zero for Just Works)
    tk: TemporaryKey,
    /// Our random value (Mrand for central)
    local_rand: u128,
    /// Peer's random value (Srand from peripheral)
    peer_rand: u128,
    /// Stored pairing request payload (for c1 calculation)
    pairing_request: [u8; 7],
    /// Stored pairing response payload (for c1 calculation)
    pairing_response: [u8; 7],
    /// Peer's confirm value
    peer_confirm: LegacyConfirm,
    /// Generated STK
    stk: Option<ShortTermKey>,
    /// Legacy pairing method
    method: LegacyPairingMethod,
    /// LTK to be distributed to peer (generated randomly, different from STK)
    distributed_ltk: Option<LongTermKey>,
    /// EDIV for the distributed LTK (generated randomly)
    distributed_ediv: Option<Ediv>,
    /// Rand for the distributed LTK (generated randomly)
    distributed_rand: Option<Rand>,
}

impl Default for LegacyPairingData {
    fn default() -> Self {
        Self {
            tk: TemporaryKey::just_works(),
            local_rand: 0,
            peer_rand: 0,
            pairing_request: [0; 7],
            pairing_response: [0x02, 0, 0, 0, 0, 0, 0],
            peer_confirm: LegacyConfirm(0),
            stk: None,
            method: LegacyPairingMethod::JustWorks,
            distributed_ltk: None,
            distributed_ediv: None,
            distributed_rand: None,
        }
    }
}

struct PairingData {
    local_address: Address,
    peer_address: Address,
    local_features: PairingFeatures,
    peer_features: PairingFeatures,
    pairing_method: PairingMethod,
    local_public_key: Option<PublicKey>,
    private_key: Option<SecretKey>,
    peer_public_key: Option<PublicKey>,
    dh_key: Option<DHKey>,
    local_secret_ra: u128,
    peer_secret_rb: u128,
    confirm: Confirm,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    mac_key: Option<MacKey>,
    ltk: Option<LongTermKey>,
    timeout_at: Instant,
    bond_information: Option<BondInformation>,
    /// Legacy pairing data (only used for legacy pairing)
    legacy_data: Option<LegacyPairingData>,
    /// Whether this is a legacy pairing session
    is_legacy: bool,
}

impl PairingData {
    fn want_bonding(&self) -> bool {
        matches!(self.local_features.security_properties.bond(), BondingFlag::Bonding)
            && matches!(self.peer_features.security_properties.bond(), BondingFlag::Bonding)
    }
}

pub struct Pairing {
    current_step: RefCell<Step>,
    pairing_data: RefCell<PairingData>,
}

impl Pairing {
    pub fn timeout_at(&self) -> Instant {
        let step = self.current_step.borrow();
        if matches!(step.deref(), Step::Success | Step::Error(_)) {
            Instant::now() + crate::security_manager::constants::TIMEOUT_DISABLE
        } else {
            self.pairing_data.borrow().timeout_at
        }
    }

    pub fn reset_timeout(&self) {
        let mut pairing_data = self.pairing_data.borrow_mut();
        pairing_data.timeout_at = Instant::now() + crate::security_manager::constants::TIMEOUT;
    }

    pub(crate) fn mark_timeout(&self) {
        let mut current_step = self.current_step.borrow_mut();
        if matches!(current_step.deref(), Step::Idle | Step::Success | Step::Error(_)) {
            return;
        }
        *current_step = Step::Error(Error::Timeout);
    }

    pub(crate) fn new_idle(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        let pairing_data = PairingData {
            pairing_method: PairingMethod::JustWorks,
            local_address,
            peer_address,
            peer_public_key: None,
            local_public_key: None,
            local_secret_ra: 0,
            peer_secret_rb: 0,
            peer_features: PairingFeatures::default(),
            mac_key: None,
            local_features: PairingFeatures {
                io_capabilities: local_io,
                ..Default::default()
            },
            peer_nonce: Nonce(0),
            local_nonce: Nonce(0),
            dh_key: None,
            confirm: Confirm(0),
            ltk: None,
            private_key: None,
            timeout_at: Instant::now() + crate::security_manager::constants::TIMEOUT_DISABLE,
            bond_information: None,
            legacy_data: None,
            is_legacy: false,
        };
        Self {
            pairing_data: RefCell::new(pairing_data),
            current_step: RefCell::new(Step::Idle),
        }
    }

    pub(crate) fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        local_address: Address,
        peer_address: Address,
        ops: &mut OPS,
        local_io: IoCapabilities,
    ) -> Result<Pairing, Error> {
        let ret = Self::new_idle(local_address, peer_address, local_io);
        {
            let mut pairing_data = ret.pairing_data.borrow_mut();
            pairing_data.local_features.security_properties = AuthReq::new(ops.bonding_flag());
            let next_step = if let Some(bond) = ops.try_enable_bonded_encryption()? {
                pairing_data.bond_information = Some(bond);
                Step::WaitingBondedLinkEncryption
            } else {
                Step::WaitingPairingResponse(PairingRequestSentTag::new(pairing_data.deref_mut(), ops)?)
            };
            ret.current_step.replace(next_step);
        }
        ret.reset_timeout();
        Ok(ret)
    }

    pub fn peer_address(&self) -> Address {
        self.pairing_data.borrow().peer_address
    }

    pub fn security_level(&self) -> SecurityLevel {
        let step = self.current_step.borrow();
        match step.deref() {
            Step::SendingKeys(_) | Step::ReceivingKeys(_) | Step::Success => self
                .pairing_data
                .borrow()
                .bond_information
                .as_ref()
                .map(|x| x.security_level)
                .unwrap_or(SecurityLevel::NoEncryption),
            _ => SecurityLevel::NoEncryption,
        }
    }

    pub fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &self,
        command: Command,
        payload: &[u8],
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        match self.handle_impl(CommandAndPayload { payload, command }, ops, rng) {
            Ok(()) => Ok(()),
            Err(error) => {
                error!("[smp] Failed to handle command {:?}, {:?}", command, error);
                self.current_step.replace(Step::Error(error.clone()));
                Err(error)
            }
        }
    }

    pub fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &self,
        event: Event,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_state = self.current_step.borrow().clone();
        let next_state = match (current_state, event) {
            (Step::WaitingLinkEncrypted, Event::LinkEncryptedResult(res)) => {
                if res {
                    info!("Link encrypted!");
                    // Check if peripheral will send keys (responder sends first per BT spec)
                    let mut pairing_data = self.pairing_data.borrow_mut();

                    // Generate legacy distribution keys if we need to send encryption keys
                    if pairing_data.is_legacy {
                        let initiator_keys = pairing_data.local_features.initiator_key_distribution;
                        if initiator_keys.encryption_key() {
                            Self::generate_legacy_distribution_keys(pairing_data.deref_mut(), rng)?;
                        }
                    }

                    let responder_keys = pairing_data.peer_features.responder_key_distribution;
                    let is_legacy = pairing_data.is_legacy;
                    drop(pairing_data);

                    let key_count = count_keys_to_distribute(responder_keys, is_legacy);
                    if key_count > 0 {
                        info!("[smp] Waiting to receive {} keys from peripheral", key_count);
                        Step::ReceivingKeys(key_count)
                    } else {
                        // No keys from peripheral, check if we need to send keys
                        self.transition_to_sending_or_success(ops)?
                    }
                } else {
                    error!("Link encryption failed!");
                    Step::Error(Error::Security(Reason::KeyRejected))
                }
            }
            (Step::WaitingBondedLinkEncryption, Event::LinkEncryptedResult(res)) => {
                if res {
                    info!("Link encrypted using bonded key!");
                    Step::Success
                } else {
                    error!("Link encryption with bonded key failed!");
                    Step::Error(Error::Security(Reason::KeyRejected))
                }
            }
            (Step::WaitingNumericComparisonResult, Event::PassKeyConfirm) => {
                Step::WaitingDHKeyEb(DHKeyEaSentTag::new(self.pairing_data.borrow_mut().deref_mut(), ops)?)
            }
            (Step::WaitingNumericComparisonResult, Event::PassKeyCancel) => {
                Step::Error(Error::Security(Reason::NumericComparisonFailed))
            }
            (Step::WaitingPassKeyInput, Event::PassKeyInput(input)) => {
                let mut pairing_data = self.pairing_data.borrow_mut();
                pairing_data.local_secret_ra = input as u128;
                pairing_data.peer_secret_rb = pairing_data.local_secret_ra;
                Step::WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag::new(
                    0,
                    pairing_data.deref_mut(),
                    ops,
                    rng,
                )?)
            }
            // Legacy pairing: TK input for passkey entry
            (Step::LegacyWaitingTkInput, Event::PassKeyInput(input)) => {
                let mut pairing_data = self.pairing_data.borrow_mut();
                if let Some(legacy) = pairing_data.legacy_data.as_mut() {
                    legacy.tk = TemporaryKey::from_passkey(input);
                }
                // Now send our confirm value
                Step::LegacyWaitingConfirm(LegacyConfirmSentTag::new(pairing_data.deref_mut(), ops, rng)?)
            }
            (x, Event::PassKeyConfirm | Event::PassKeyCancel) => x,
            _ => Step::Error(Error::InvalidState),
        };

        match next_state {
            Step::Error(x) => {
                self.current_step.replace(Step::Error(x.clone()));
                ops.try_send_connection_event(ConnectionEvent::PairingFailed(x.clone()))?;
                Err(x)
            }
            x => {
                let is_success = matches!(x, Step::Success);
                self.current_step.replace(x);
                if is_success {
                    let pairing_data = self.pairing_data.borrow();
                    if let Some(bond) = pairing_data.bond_information.as_ref() {
                        // If we received peer's IRK, add device to controller's resolving list
                        if let Some(peer_irk) = bond.identity.irk {
                            let local_irk = ops.get_local_irk().unwrap_or_else(|| IdentityResolvingKey::new(0));

                            if let Err(e) = ops.try_add_device_to_resolving_list(
                                pairing_data.peer_address.kind,
                                pairing_data.peer_address.addr,
                                peer_irk.0.to_le_bytes(),
                                local_irk.0.to_le_bytes(),
                            ) {
                                warn!("[smp] Failed to add device to resolving list: {:?}", e);
                            }
                        }

                        let pairing_bond = if pairing_data.want_bonding() {
                            Some(bond.clone())
                        } else {
                            None
                        };
                        ops.try_send_connection_event(ConnectionEvent::PairingComplete {
                            security_level: bond.security_level,
                            bond: pairing_bond,
                        })?;
                    } else {
                        error!("[smp] No bond information stored");
                    }
                }
                Ok(())
            }
        }
    }

    /// Transition to sending keys or success after receiving keys (or if no keys to receive).
    fn transition_to_sending_or_success<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        ops: &mut OPS,
    ) -> Result<Step, Error> {
        let mut pairing_data = self.pairing_data.borrow_mut();
        let initiator_keys = pairing_data.local_features.initiator_key_distribution;
        let is_legacy = pairing_data.is_legacy;
        let key_count = count_keys_to_distribute(initiator_keys, is_legacy);

        if key_count > 0 {
            info!("[smp] Starting to send {} keys to peripheral", key_count);
            // Send all keys at once
            Self::send_next_key::<P, OPS>(&mut pairing_data, ops)
        } else {
            info!("[smp] No keys to send, pairing complete");
            Ok(Step::Success)
        }
    }

    fn handle_impl<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_step = self.current_step.borrow().clone();
        let mut pairing_data = self.pairing_data.borrow_mut();
        let pairing_data = pairing_data.deref_mut();
        let next_step = {
            trace!("Handling {:?}, step {:?}", command.command, current_step);
            match (current_step, command.command) {
                (Step::Idle, Command::SecurityRequest) => {
                    pairing_data.local_features.security_properties = AuthReq::new(ops.bonding_flag());
                    if let Some(bond) = ops.try_enable_bonded_encryption()? {
                        pairing_data.bond_information = Some(bond);
                        Step::WaitingBondedLinkEncryption
                    } else {
                        Step::WaitingPairingResponse(PairingRequestSentTag::new(pairing_data, ops)?)
                    }
                }
                (Step::WaitingPairingResponse(x), Command::SecurityRequest) => {
                    // SM test spec SM/CEN/PIS/BV-03-C, security requests while waiting for pairing respsonse shall be ignored
                    Step::WaitingPairingResponse(x)
                }
                (Step::WaitingPairingResponse(_), Command::PairingResponse) => {
                    trace!("pairing response payload {:?}", command.payload);
                    let is_legacy = Self::handle_pairing_response(command.payload, ops, pairing_data)?;

                    if is_legacy {
                        // Legacy pairing path
                        Self::start_legacy_pairing(pairing_data, ops, rng)?
                    } else {
                        // LESC pairing path
                        Self::generate_private_public_key_pair(pairing_data, rng)?;
                        Self::send_public_key(ops, pairing_data.local_public_key.as_ref().unwrap())?;
                        Step::WaitingPublicKey
                    }
                }
                (Step::WaitingPublicKey, Command::PairingPublicKey) => {
                    Self::handle_public_key(command.payload, pairing_data)?;
                    match pairing_data.pairing_method {
                        PairingMethod::OutOfBand => todo!("OOB not implemented"),
                        PairingMethod::PassKeyEntry { central, .. } => {
                            if central == PassKeyEntryAction::Display {
                                pairing_data.local_secret_ra =
                                    rng.sample(rand::distributions::Uniform::new_inclusive(0, 999999));
                                pairing_data.peer_secret_rb = pairing_data.local_secret_ra;
                                ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(
                                    pairing_data.local_secret_ra as u32,
                                )))?;
                                Step::WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag::new(
                                    0,
                                    pairing_data,
                                    ops,
                                    rng,
                                )?)
                            } else {
                                ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                                Step::WaitingPassKeyInput
                            }
                        }
                        _ => Step::WaitingNumericComparisonConfirm,
                    }
                }
                (Step::WaitingNumericComparisonConfirm, Command::PairingConfirm) => {
                    Self::handle_numeric_compare_confirm(command.payload, pairing_data, rng)?;
                    Self::send_nonce(ops, &pairing_data.local_nonce)?;
                    Step::WaitingNumericComparisonRandom
                }
                (Step::WaitingNumericComparisonRandom, Command::PairingRandom) => {
                    Self::handle_numeric_compare_random(command.payload, pairing_data, ops)?
                }
                (Step::WaitingPassKeyEntryConfirm(round), Command::PairingConfirm) => {
                    Self::handle_pass_key_confirm(command.payload, pairing_data)?;
                    Self::send_nonce(ops, &pairing_data.local_nonce)?;
                    Step::WaitingPassKeyEntryRandom(round.0)
                }

                (Step::WaitingPassKeyEntryRandom(round), Command::PairingRandom) => {
                    Self::handle_pass_key_random(round, command.payload, ops, pairing_data)?;
                    if round == 19 {
                        Step::WaitingDHKeyEb(DHKeyEaSentTag::new(pairing_data, ops)?)
                    } else {
                        Step::WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag::new(
                            round + 1,
                            pairing_data,
                            ops,
                            rng,
                        )?)
                    }
                }
                (Step::WaitingDHKeyEb(_), Command::PairingDhKeyCheck) => {
                    Self::handle_dhkey_eb(command.payload, ops, pairing_data)?;
                    Step::WaitingLinkEncrypted
                }
                // Legacy pairing states
                (Step::LegacyWaitingConfirm(_), Command::PairingConfirm) => {
                    Self::handle_legacy_confirm(command.payload, pairing_data)?;
                    // Send our random value
                    Self::send_legacy_random(ops, pairing_data)?;
                    Step::LegacyWaitingRandom
                }
                (Step::LegacyWaitingRandom, Command::PairingRandom) => {
                    Self::handle_legacy_random(command.payload, ops, pairing_data)?
                }

                // Key distribution - receiving keys from peripheral
                (Step::ReceivingKeys(remaining), Command::EncryptionInformation) => {
                    Self::handle_encryption_information(command.payload, pairing_data)?;
                    Self::decrement_receiving_keys_or_transition(remaining, pairing_data, ops)?
                }
                (Step::ReceivingKeys(remaining), Command::CentralIdentification) => {
                    Self::handle_central_identification(command.payload, pairing_data)?;
                    Self::decrement_receiving_keys_or_transition(remaining, pairing_data, ops)?
                }
                (Step::ReceivingKeys(remaining), Command::IdentityInformation) => {
                    Self::handle_identity_information(command.payload, pairing_data)?;
                    Self::decrement_receiving_keys_or_transition(remaining, pairing_data, ops)?
                }
                (Step::ReceivingKeys(remaining), Command::IdentityAddressInformation) => {
                    Self::handle_identity_address_information(command.payload, pairing_data)?;
                    Self::decrement_receiving_keys_or_transition(remaining, pairing_data, ops)?
                }
                (Step::ReceivingKeys(remaining), Command::SigningInformation) => {
                    Self::handle_signing_information(command.payload, pairing_data)?;
                    Self::decrement_receiving_keys_or_transition(remaining, pairing_data, ops)?
                }

                (x, Command::KeypressNotification) => x,

                _ => return Err(Error::InvalidState),
            }
        };

        self.current_step.replace(next_step);

        Ok(())
    }

    fn handle_pairing_response<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<bool, Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }

        pairing_data.peer_features = peer_features;
        // Check if this should be legacy pairing
        let is_legacy = is_legacy_pairing(&pairing_data.local_features, &peer_features);
        pairing_data.is_legacy = is_legacy;

        if is_legacy {
            info!("[smp] Using legacy pairing (peer does not support Secure Connections)");

            // Initialize legacy pairing data
            let mut legacy = LegacyPairingData::default();

            // Store pairing request/response for c1 calculation
            // Pairing request was already sent, we need to reconstruct it
            let mut preq = [0u8; 7];
            preq[0] = 1 as u8;
            preq[1] = pairing_data.local_features.io_capabilities as u8;
            preq[2] = pairing_data.local_features.use_oob as u8;
            preq[3] = u8::from(pairing_data.local_features.security_properties);
            preq[4] = pairing_data.local_features.maximum_encryption_key_size;
            preq[5] = u8::from(pairing_data.local_features.initiator_key_distribution);
            preq[6] = u8::from(pairing_data.local_features.responder_key_distribution);
            legacy.pairing_request = preq;

            let copy_len = payload.len();
            legacy.pairing_response[1..copy_len + 1].copy_from_slice(&payload[..copy_len]);

            // Determine legacy pairing method
            legacy.method = choose_legacy_pairing_method(&pairing_data.local_features, &peer_features);
            info!("[smp] Legacy pairing method: {:?}", legacy.method);

            pairing_data.legacy_data = Some(legacy);

            Ok(true) // Return true for legacy pairing
        } else {
            // LESC pairing
            pairing_data.pairing_method =
                choose_pairing_method(pairing_data.local_features, pairing_data.peer_features);
            info!("[smp] LESC pairing method: {:?}", pairing_data.pairing_method);

            Ok(false) // Return false for LESC pairing
        }
    }

    fn generate_private_public_key_pair<RNG: CryptoRng + RngCore>(
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let secret_key = SecretKey::new(rng);
        let public_key = secret_key.public_key();
        pairing_data.local_public_key = Some(public_key);
        pairing_data.private_key = Some(secret_key);

        Ok(())
    }

    fn send_public_key<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, public_key: &PublicKey) -> Result<(), Error> {
        let packet = make_public_key_packet::<P>(public_key).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to send public key {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn handle_public_key(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let peer_public_key = PublicKey::from_bytes(payload);
        let secret_key = pairing_data.private_key.as_ref().ok_or(Error::InvalidValue)?;
        pairing_data.dh_key = Some(
            secret_key
                .dh_key(peer_public_key)
                .ok_or(Error::Security(Reason::InvalidParameters))?,
        );

        pairing_data.peer_public_key = Some(peer_public_key);

        Ok(())
    }

    fn handle_numeric_compare_confirm<RNG: CryptoRng + RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        pairing_data.confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        pairing_data.local_nonce = Nonce::new(rng);
        Ok(())
    }

    fn send_nonce<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, nonce: &Nonce) -> Result<(), Error> {
        let packet = make_pairing_random::<P>(nonce).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to send pairing random {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn handle_numeric_compare_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<Step, Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        let expected_cb = peer_nonce.f4(
            pairing_data.peer_public_key.ok_or(Error::InvalidValue)?.x(),
            pairing_data.local_public_key.ok_or(Error::InvalidValue)?.x(),
            0,
        );
        if pairing_data.confirm != expected_cb {
            return Err(Error::Security(Reason::NumericComparisonFailed));
        }
        pairing_data.peer_nonce = peer_nonce;
        let va = pairing_data.local_nonce.g2(
            pairing_data.local_public_key.ok_or(Error::InvalidValue)?.x(),
            pairing_data.peer_public_key.ok_or(Error::InvalidValue)?.x(),
            &pairing_data.peer_nonce,
        );

        if pairing_data.pairing_method == PairingMethod::JustWorks {
            info!("[smp] Just works pairing with compare {}", va.0);
            Ok(Step::WaitingDHKeyEb(DHKeyEaSentTag::new(pairing_data, ops)?))
        } else {
            info!("[smp] Numeric comparison pairing with compare {}", va.0);
            ops.try_send_connection_event(ConnectionEvent::PassKeyConfirm(PassKey(va.0)))?;
            Ok(Step::WaitingNumericComparisonResult)
        }
    }

    fn handle_dhkey_eb<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let expected_eb = {
            let mac_key = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?;
            mac_key
                .f6(
                    pairing_data.peer_nonce,
                    pairing_data.local_nonce,
                    pairing_data.local_secret_ra,
                    pairing_data.peer_features.as_io_cap(),
                    pairing_data.peer_address,
                    pairing_data.local_address,
                )
                .0
                .to_le_bytes()
        };
        if payload != expected_eb {
            return Err(Error::Security(Reason::DHKeyCheckFailed));
        }

        let bond = ops.try_enable_encryption(
            &pairing_data.ltk.ok_or(Error::InvalidValue)?,
            pairing_data.pairing_method.security_level(),
            pairing_data.want_bonding(),
        )?;
        pairing_data.bond_information = Some(bond);
        Ok(())
    }

    fn handle_pass_key_confirm(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        pairing_data.confirm = confirm;
        Ok(())
    }

    fn handle_pass_key_random<P: PacketPool, OPS: PairingOps<P>>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        let rai = 0x80u8 | (((pairing_data.local_secret_ra & (1 << round as u128)) >> (round as u128)) as u8);
        let cbi = peer_nonce.f4(
            pairing_data.peer_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            pairing_data.local_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            rai,
        );
        if cbi != pairing_data.confirm {
            return Err(Error::Security(Reason::NumericComparisonFailed));
        }
        pairing_data.peer_nonce = peer_nonce;
        Ok(())
    }

    // ========================================================================
    // Legacy Pairing Helper Functions
    // ========================================================================

    /// Generate LTK, EDIV, and Rand for legacy pairing key distribution.
    /// These are different from the STK used to encrypt the link during pairing.
    fn generate_legacy_distribution_keys<RNG: RngCore>(
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        if let Some(ref mut legacy) = pairing_data.legacy_data {
            // Generate random LTK (16 bytes)
            let mut ltk_bytes = [0u8; 16];
            rng.fill_bytes(&mut ltk_bytes);
            legacy.distributed_ltk = Some(LongTermKey::new(u128::from_le_bytes(ltk_bytes)));

            // Generate random EDIV (2 bytes)
            let ediv = rng.next_u32() as u16;
            legacy.distributed_ediv = Some(Ediv::new(ediv));

            // Generate random Rand (8 bytes)
            let rand = rng.next_u64();
            legacy.distributed_rand = Some(Rand::new(rand));

            info!("[smp] Generated legacy distribution keys: EDIV={}, Rand={}", ediv, rand);
        }
        Ok(())
    }

    /// Start legacy pairing after receiving pairing response
    fn start_legacy_pairing<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
        let legacy = pairing_data.legacy_data.as_ref().ok_or(Error::InvalidValue)?;
        let method = legacy.method;
        let our_action = legacy_io_action_for_role(&method, true); // true = central

        match method {
            LegacyPairingMethod::JustWorks => {
                info!("[smp] Legacy Just Works pairing");
                // TK = 0 (already set by default)
                // Send our confirm value
                Ok(Step::LegacyWaitingConfirm(LegacyConfirmSentTag::new(
                    pairing_data,
                    ops,
                    rng,
                )?))
            }
            LegacyPairingMethod::PasskeyEntry { central, peripheral } => {
                info!("[smp] Legacy Passkey Entry pairing");
                match our_action {
                    LegacyIoAction::Display => {
                        // Generate and display passkey
                        let passkey: u32 = rng.gen_range(0..1_000_000);
                        if let Some(legacy) = pairing_data.legacy_data.as_mut() {
                            legacy.tk = TemporaryKey::from_passkey(passkey);
                        }
                        ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(passkey)))?;
                        // Send our confirm value
                        Ok(Step::LegacyWaitingConfirm(LegacyConfirmSentTag::new(
                            pairing_data,
                            ops,
                            rng,
                        )?))
                    }
                    LegacyIoAction::Input => {
                        // Wait for user to input passkey
                        ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                        Ok(Step::LegacyWaitingTkInput)
                    }
                    LegacyIoAction::None => {
                        // Should not happen for PasskeyEntry
                        error!("[smp] Invalid IO action for PasskeyEntry");
                        Err(Error::InvalidValue)
                    }
                }
            }
        }
    }

    /// Handle peer's legacy confirm value
    fn handle_legacy_confirm(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let legacy = pairing_data.legacy_data.as_mut().ok_or(Error::InvalidValue)?;

        // Store peer's confirm value
        let confirm_bytes: [u8; 16] = payload
            .try_into()
            .map_err(|_| Error::Security(Reason::InvalidParameters))?;
        legacy.peer_confirm = LegacyConfirm::from_le_bytes(confirm_bytes);

        info!("[smp] Received legacy confirm from peer");
        Ok(())
    }

    /// Send our random value for legacy pairing
    fn send_legacy_random<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &PairingData,
    ) -> Result<(), Error> {
        let legacy = pairing_data.legacy_data.as_ref().ok_or(Error::InvalidValue)?;

        let packet = make_legacy_random_packet::<P>(legacy.local_rand)?;
        info!("Random value sent: {:?}", legacy.local_rand);
        ops.try_send_packet(packet)?;

        info!("[smp] Sent legacy random (Mrand)");
        Ok(())
    }

    /// Handle peer's `random` value and verify confirm, then generate STK
    fn handle_legacy_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<Step, Error> {
        let legacy = pairing_data.legacy_data.as_mut().ok_or(Error::InvalidValue)?;

        // Extract peer's random value (Srand)
        let rand_bytes: [u8; 16] = payload
            .try_into()
            .map_err(|_| Error::Security(Reason::InvalidParameters))?;
        legacy.peer_rand = u128::from_le_bytes(rand_bytes);

        info!("[smp] Received legacy random (Srand) from peer");

        // Verify peer's confirm value by recalculating c1 with their random
        let expected_confirm = c1(
            &legacy.tk,
            legacy.peer_rand,
            &legacy.pairing_request,
            &legacy.pairing_response,
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        if expected_confirm != legacy.peer_confirm {
            error!("[smp] Legacy confirm value mismatch!");
            return Err(Error::Security(Reason::ConfirmValueFailed));
        }

        info!("[smp] Legacy confirm value verified");

        // Generate STK using s1 function
        // s1(TK, Srand, Mrand) - note: Srand is peer's rand, Mrand is our rand
        let stk = s1(&legacy.tk, legacy.peer_rand, legacy.local_rand);
        legacy.stk = Some(stk);

        info!("[smp] Generated STK");

        // As central/initiator, start encryption with the STK
        // For STK: ediv = 0, rand = 0
        let ltk = LongTermKey::new(stk.0);
        let security_level = legacy.method.security_level();
        let want_bonding = pairing_data.want_bonding();

        let bond = ops.try_enable_encryption(&ltk, security_level, want_bonding)?;
        pairing_data.bond_information = Some(bond);

        info!("Move to next step - waiting for link to be encrypted");
        Ok(Step::WaitingLinkEncrypted)
    }

    // ========================================================================
    // Key Reception Handlers (receiving keys from peripheral)
    // ========================================================================

    fn handle_encryption_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let ltk_bytes: [u8; 16] = payload.try_into().map_err(|_| Error::InvalidValue)?;
        let ltk = LongTermKey::new(u128::from_le_bytes(ltk_bytes));

        info!("[smp] Received EncryptionInformation (LTK) from peripheral");
        if let Some(ref mut bond) = pairing_data.bond_information {
            bond.peer_ltk = Some(ltk);
        }
        Ok(())
    }

    fn handle_central_identification(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let ediv = Ediv::from_le_bytes([payload[0], payload[1]]);
        let rand_bytes: [u8; 8] = payload[2..10].try_into().map_err(|_| Error::InvalidValue)?;
        let rand = Rand::from_le_bytes(rand_bytes);

        info!(
            "[smp] Received CentralIdentification (EDIV={}, Rand) from peripheral",
            ediv.0
        );
        if let Some(ref mut bond) = pairing_data.bond_information {
            bond.peer_ediv = Some(ediv);
            bond.peer_rand = Some(rand);
        }
        Ok(())
    }

    fn handle_identity_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let irk_bytes: [u8; 16] = payload.try_into().map_err(|_| Error::InvalidValue)?;
        let irk = IdentityResolvingKey::new(u128::from_le_bytes(irk_bytes));

        info!("[smp] Received IdentityInformation (IRK) from peripheral");
        if let Some(ref mut bond) = pairing_data.bond_information {
            bond.identity.irk = Some(irk);
        }
        Ok(())
    }

    fn handle_identity_address_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let addr_type = payload[0];
        let kind = if addr_type == 0 {
            AddrKind::PUBLIC
        } else if addr_type == 1 {
            AddrKind::RANDOM
        } else {
            return Err(Error::InvalidValue);
        };
        let addr = BdAddr::new(payload[1..7].try_into().map_err(|_| Error::InvalidValue)?);

        info!(
            "[smp] Received IdentityAddressInformation: type={}, addr={:?}",
            addr_type, addr
        );

        // Update peer address to identity address
        pairing_data.peer_address = Address { kind, addr };
        if let Some(ref mut bond) = pairing_data.bond_information {
            bond.identity.bd_addr = addr;
        }
        Ok(())
    }

    fn handle_signing_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let csrk_bytes: [u8; 16] = payload.try_into().map_err(|_| Error::InvalidValue)?;
        let csrk = u128::from_le_bytes(csrk_bytes);

        info!("[smp] Received SigningInformation (CSRK) from peripheral");
        if let Some(ref mut bond) = pairing_data.bond_information {
            bond.peer_csrk = Some(csrk);
        }
        Ok(())
    }

    /// Helper to decrement remaining keys count and transition to next state.
    fn decrement_receiving_keys_or_transition<P: PacketPool, OPS: PairingOps<P>>(
        remaining: i32,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<Step, Error> {
        let new_remaining = remaining - 1;
        if new_remaining > 0 {
            Ok(Step::ReceivingKeys(new_remaining))
        } else {
            // All keys received from peripheral, now check if we need to send keys
            let initiator_keys = pairing_data.local_features.initiator_key_distribution;
            let is_legacy = pairing_data.is_legacy;
            let key_count = count_keys_to_distribute(initiator_keys, is_legacy);

            if key_count > 0 {
                info!("[smp] Starting to send {} keys to peripheral", key_count);
                Self::send_next_key::<P, OPS>(pairing_data, ops)
            } else {
                info!("[smp] No keys to send, pairing complete");
                Ok(Step::Success)
            }
        }
    }

    // ========================================================================
    // Key Distribution Functions (sending keys to peripheral)
    // ========================================================================

    /// Send all keys to the peripheral in the correct order.
    /// In SMP, keys are sent consecutively without waiting for acknowledgments.
    /// Returns Step::Success when all keys have been sent.
    fn send_next_key<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<Step, Error> {
        let flags = pairing_data.local_features.initiator_key_distribution;
        let is_legacy = pairing_data.is_legacy;

        // Keys must be sent in order: EncryptionKey (LTK+EDIV/Rand), IdentityKey (IRK+Addr), SigningKey (CSRK)

        // For legacy pairing: EncryptionInformation + CentralIdentification
        if is_legacy && flags.encryption_key() {
            Self::send_encryption_information::<P, OPS>(pairing_data, ops)?;
            Self::send_central_identification::<P, OPS>(pairing_data, ops)?;
        }

        // IdentityInformation + IdentityAddressInformation
        if flags.identity_key() {
            Self::send_identity_information::<P, OPS>(pairing_data, ops)?;
            Self::send_identity_address_information::<P, OPS>(pairing_data, ops)?;
        }

        // SigningInformation
        if flags.signing_key() {
            Self::send_signing_information::<P, OPS>(pairing_data, ops)?;
        }

        // All keys sent
        Ok(Step::Success)
    }

    fn send_encryption_information<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        let ltk = if pairing_data.is_legacy {
            // For legacy pairing, use the distributed LTK (not the STK)
            pairing_data
                .legacy_data
                .as_ref()
                .and_then(|l| l.distributed_ltk)
                .ok_or_else(|| {
                    error!("[smp] No distributed LTK for legacy pairing");
                    Error::InvalidValue
                })?
        } else {
            // For LESC, use pairing_data.ltk
            pairing_data.ltk.ok_or_else(|| {
                error!("[smp] No LTK found");
                Error::InvalidValue
            })?
        };

        let packet = make_encryption_information_packet::<P>(&ltk)?;
        ops.try_send_packet(packet)?;

        // Update bond information with the distributed LTK
        if let Some(ref mut bond) = pairing_data.bond_information {
            bond.ltk = ltk;
        }

        info!("[smp] Sent EncryptionInformation (LTK)");
        Ok(())
    }

    fn send_central_identification<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        let (ediv, rand) = if pairing_data.is_legacy {
            // For legacy pairing, use generated EDIV/Rand
            let legacy = pairing_data.legacy_data.as_ref();
            (
                legacy.and_then(|l| l.distributed_ediv).unwrap_or(Ediv::new(0)),
                legacy.and_then(|l| l.distributed_rand).unwrap_or(Rand::new(0)),
            )
        } else {
            // For LESC, EDIV=0 and Rand=0
            (Ediv::new(0), Rand::new(0))
        };

        let packet = make_central_identification_packet::<P>(ediv, rand)?;
        ops.try_send_packet(packet)?;
        info!("[smp] Sent CentralIdentification (EDIV={}, Rand={})", ediv.0, rand.0);
        Ok(())
    }

    fn send_identity_information<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        // Send our IRK - get from ops if available, otherwise use a placeholder
        // TODO: Get local IRK from PairingOps or generate one
        let local_irk = ops.get_local_irk().unwrap_or_else(|| IdentityResolvingKey::new(0));

        let packet = make_identity_information_packet::<P>(&local_irk)?;
        ops.try_send_packet(packet)?;
        info!("[smp] Sent IdentityInformation (IRK)");
        Ok(())
    }

    fn send_identity_address_information<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        let packet = make_identity_address_information_packet::<P>(&pairing_data.local_address)?;
        ops.try_send_packet(packet)?;
        info!("[smp] Sent IdentityAddressInformation");
        Ok(())
    }

    fn send_signing_information<P: PacketPool, OPS: PairingOps<P>>(
        _pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        // TODO: Generate or use stored CSRK
        let csrk: u128 = 0; // Placeholder

        let packet = make_signing_information_packet::<P>(csrk)?;
        ops.try_send_packet(packet)?;
        info!("[smp] Sent SigningInformation (CSRK)");
        Ok(())
    }
}
