//! # YubiKey PIV & Smartcard PC/SC Hardware Token Driver
//!
//! Provides direct interaction with physical smartcards and hardware tokens (e.g. YubiKey 5 Series)
//! implementing NIST SP 800-73-4 (PIV: Personal Identity Verification) over standard PC/SC interfaces.
//!
//! Keys generated or held in physical hardware slots (Slot 9C for Digital Signatures,
//! Slot 9D for Key Management / ECDH unwrap) never touch host RAM or disk.

use crate::error::CryptoError;
use crate::hsm::{HardwareSecurityModule, HsmSlot, HsmSlotInfo};
use std::sync::{Arc, Mutex};

/// PIV Application AID (NIST SP 800-73-4): A0 00 00 03 08 00 00 10 00 01 00
pub const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// PIV Algorithm Identifiers
pub const ALG_ECCP256: u8 = 0x11;
pub const ALG_ED25519: u8 = 0x22;
pub const ALG_X25519: u8 = 0x23;

/// PIV Slot Identifiers (as raw bytes)
pub const PIV_SLOT_AUTHENTICATION: u8 = 0x9A;
pub const PIV_SLOT_SIGNATURE: u8 = 0x9C;
pub const PIV_SLOT_KEY_MANAGEMENT: u8 = 0x9D;
pub const PIV_SLOT_CARD_AUTH: u8 = 0x9E;

/// Encodes a BER-TLV tag and length with value.
pub fn encode_ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len());
    out.push(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push((value.len() & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

/// ISO 7816-4 Command APDU
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

impl CommandApdu {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: Option<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        }
    }

    /// Serializes the APDU into standard ISO 7816-4 short or extended format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(7 + self.data.len() + 2);
        bytes.push(self.cla);
        bytes.push(self.ins);
        bytes.push(self.p1);
        bytes.push(self.p2);

        if !self.data.is_empty() {
            if self.data.len() <= 255 {
                bytes.push(self.data.len() as u8);
                bytes.extend_from_slice(&self.data);
            } else {
                bytes.push(0x00);
                bytes.push((self.data.len() >> 8) as u8);
                bytes.push((self.data.len() & 0xFF) as u8);
                bytes.extend_from_slice(&self.data);
            }
        }

        if let Some(le) = self.le {
            bytes.push(le);
        }

        bytes
    }

    /// APDU to select the NIST PIV application.
    pub fn select_piv() -> Self {
        Self::new(0x00, 0xA4, 0x04, 0x00, PIV_AID.to_vec(), Some(0x00))
    }

    /// APDU to verify PIV user PIN (padded to 8 bytes with 0xFF).
    pub fn verify_pin(pin: &[u8]) -> Self {
        let mut padded = pin.to_vec();
        while padded.len() < 8 {
            padded.push(0xFF);
        }
        Self::new(0x00, 0x20, 0x00, 0x80, padded, None)
    }

    /// APDU to retrieve metadata for a PIV slot (YubiKey proprietary INS 0xF7).
    pub fn get_slot_metadata(slot: u8) -> Self {
        Self::new(0x00, 0xF7, 0x00, slot, Vec::new(), Some(0x00))
    }

    /// APDU for Dynamic Authentication signing on Slot 9C.
    pub fn general_authenticate_sign(alg_id: u8, slot: u8, challenge: &[u8]) -> Self {
        // Tag 7C (Dynamic Authentication Template)
        //   Tag 82 00 (Empty response indicator)
        //   Tag 81 <len> <challenge>
        let mut inner = vec![0x82, 0x00];
        inner.extend_from_slice(&encode_ber_tlv(0x81, challenge));

        let data = encode_ber_tlv(0x7C, &inner);
        Self::new(0x00, 0x87, alg_id, slot, data, Some(0x00))
    }

    /// APDU for Dynamic Authentication ECDH Key Agreement on Slot 9D.
    pub fn general_authenticate_ecdh(alg_id: u8, slot: u8, peer_pk: &[u8]) -> Self {
        // Tag 7C (Dynamic Authentication Template)
        //   Tag 85 00 (Empty shared secret response indicator)
        //   Tag 86 <len> <peer_public_key>
        let mut inner = vec![0x85, 0x00, 0x86, peer_pk.len() as u8];
        inner.extend_from_slice(peer_pk);

        let mut data = Vec::new();
        data.push(0x7C);
        data.push(inner.len() as u8);
        data.extend_from_slice(&inner);

        Self::new(0x00, 0x87, alg_id, slot, data, Some(0x00))
    }
}

/// ISO 7816-4 Response APDU
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ResponseApdu {
    pub fn parse(raw: &[u8]) -> Result<Self, CryptoError> {
        if raw.len() < 2 {
            return Err(CryptoError::HsmError(format!(
                "APDU response too short: {} bytes",
                raw.len()
            )));
        }
        let data = raw[..raw.len() - 2].to_vec();
        let sw1 = raw[raw.len() - 2];
        let sw2 = raw[raw.len() - 1];
        Ok(Self { data, sw1, sw2 })
    }

    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    pub fn is_touch_timeout(&self) -> bool {
        self.sw1 == 0x69 && (self.sw2 == 0x85 || self.sw2 == 0x82)
    }

    pub fn is_pin_required(&self) -> bool {
        self.sw1 == 0x69 && self.sw2 == 0x82
    }

    pub fn status_hex(&self) -> String {
        format!("{:02X}{:02X}", self.sw1, self.sw2)
    }

    pub fn error_description(&self) -> String {
        match (self.sw1, self.sw2) {
            (0x90, 0x00) => "Success".to_string(),
            (0x69, 0x82) => "Security status not satisfied (PIN required or locked)".to_string(),
            (0x69, 0x85) => {
                "Conditions of use not satisfied (User touch presence timeout or cancelled)"
                    .to_string()
            }
            (0x6A, 0x80) => "Incorrect data parameters".to_string(),
            (0x6A, 0x82) => "PIV Applet or Object not found".to_string(),
            (0x6A, 0x88) => "Referenced key slot not provisioned".to_string(),
            _ => format!("APDU Status Error 0x{:02X}{:02X}", self.sw1, self.sw2),
        }
    }

    /// Extracts the inner signature or shared secret bytes from a Tag 7C template response.
    pub fn extract_dynamic_auth_response(&self, tag: u8) -> Result<Vec<u8>, CryptoError> {
        if !self.is_success() {
            return Err(CryptoError::HsmError(self.error_description()));
        }
        // Template format: 7C <len> <tag> <len> <payload...>
        let mut idx = 0;
        let d = &self.data;
        if d.len() < 4 || d[0] != 0x7C {
            // Some tokens return raw payload if not wrapped in 7C
            return Ok(self.data.clone());
        }
        idx += 2; // skip 7C <len>
        while idx < d.len() {
            let item_tag = d[idx];
            idx += 1;
            if idx >= d.len() {
                break;
            }
            let item_len = d[idx] as usize;
            idx += 1;
            if idx + item_len > d.len() {
                break;
            }
            if item_tag == tag {
                return Ok(d[idx..idx + item_len].to_vec());
            }
            idx += item_len;
        }
        // If not found in tag search, return whole data
        Ok(self.data.clone())
    }
}

// ---------------------------------------------------------------------------
// Platform PC/SC Driver Bindings
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub const SCARD_SCOPE_USER: u32 = 0;
    pub const SCARD_SHARE_SHARED: u32 = 2;
    pub const SCARD_PROTOCOL_T0: u32 = 1;
    pub const SCARD_PROTOCOL_T1: u32 = 2;
    pub const SCARD_LEAVE_CARD: u32 = 0;
    pub const SCARD_S_SUCCESS: i32 = 0;

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(non_snake_case)]
    pub struct SCARD_IO_REQUEST {
        pub dwProtocol: u32,
        pub cbPciLength: u32,
    }

    #[link(name = "winscard")]
    extern "system" {
        pub fn SCardEstablishContext(
            dwScope: u32,
            pvReserved1: *const c_void,
            pvReserved2: *const c_void,
            phContext: *mut usize,
        ) -> i32;

        pub fn SCardReleaseContext(hContext: usize) -> i32;

        pub fn SCardListReadersA(
            hContext: usize,
            mszGroups: *const u8,
            mszReaders: *mut u8,
            pcchReaders: *mut u32,
        ) -> i32;

        pub fn SCardConnectA(
            hContext: usize,
            szReader: *const u8,
            dwShareMode: u32,
            dwPreferredProtocols: u32,
            phCard: *mut usize,
            pdwActiveProtocol: *mut u32,
        ) -> i32;

        pub fn SCardDisconnect(hCard: usize, dwDisposition: u32) -> i32;

        pub fn SCardTransmit(
            hCard: usize,
            pioSendPci: *const SCARD_IO_REQUEST,
            pbSendBuffer: *const u8,
            cbSendLength: u32,
            pioRecvPci: *mut SCARD_IO_REQUEST,
            pbRecvBuffer: *mut u8,
            pcbRecvLength: *mut u32,
        ) -> i32;
    }
}

/// Native PC/SC Low-Level Transport
struct NativePcscTransport {
    #[cfg(windows)]
    context: usize,
    #[cfg(windows)]
    card: usize,
    #[cfg(windows)]
    protocol: u32,
}

impl NativePcscTransport {
    #[cfg(windows)]
    fn connect(reader: &str) -> Result<Self, CryptoError> {
        let mut ctx: usize = 0;
        let res = unsafe {
            ffi::SCardEstablishContext(
                ffi::SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut ctx,
            )
        };
        if res != ffi::SCARD_S_SUCCESS {
            return Err(CryptoError::HsmError(format!(
                "Failed to establish PC/SC context: error 0x{:08X}",
                res
            )));
        }

        let mut c_reader = reader.as_bytes().to_vec();
        c_reader.push(0);

        let mut card: usize = 0;
        let mut protocol: u32 = 0;
        let connect_res = unsafe {
            ffi::SCardConnectA(
                ctx,
                c_reader.as_ptr(),
                ffi::SCARD_SHARE_SHARED,
                ffi::SCARD_PROTOCOL_T0 | ffi::SCARD_PROTOCOL_T1,
                &mut card,
                &mut protocol,
            )
        };

        if connect_res != ffi::SCARD_S_SUCCESS {
            unsafe { ffi::SCardReleaseContext(ctx) };
            return Err(CryptoError::HsmError(format!(
                "Failed to connect to smartcard reader '{}': error 0x{:08X}",
                reader, connect_res
            )));
        }

        Ok(Self {
            context: ctx,
            card,
            protocol,
        })
    }

    #[cfg(not(windows))]
    fn connect(_reader: &str) -> Result<Self, CryptoError> {
        Err(CryptoError::HsmError(
            "PC/SC hardware driver not supported on this platform configuration".into(),
        ))
    }

    #[cfg(windows)]
    fn transmit(&self, apdu: &CommandApdu) -> Result<ResponseApdu, CryptoError> {
        let send_bytes = apdu.to_bytes();
        let mut recv_buf = vec![0u8; 1024];
        let mut recv_len = recv_buf.len() as u32;

        let io_send = ffi::SCARD_IO_REQUEST {
            dwProtocol: self.protocol,
            cbPciLength: std::mem::size_of::<ffi::SCARD_IO_REQUEST>() as u32,
        };

        let res = unsafe {
            ffi::SCardTransmit(
                self.card,
                &io_send,
                send_bytes.as_ptr(),
                send_bytes.len() as u32,
                std::ptr::null_mut(),
                recv_buf.as_mut_ptr(),
                &mut recv_len,
            )
        };

        if res != ffi::SCARD_S_SUCCESS {
            return Err(CryptoError::HsmError(format!(
                "SCardTransmit failed: error 0x{:08X}",
                res
            )));
        }

        recv_buf.truncate(recv_len as usize);
        ResponseApdu::parse(&recv_buf)
    }

    #[cfg(not(windows))]
    fn transmit(&self, _apdu: &CommandApdu) -> Result<ResponseApdu, CryptoError> {
        Err(CryptoError::HsmError("PC/SC transport inactive".into()))
    }
}

impl Drop for NativePcscTransport {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            if self.card != 0 {
                ffi::SCardDisconnect(self.card, ffi::SCARD_LEAVE_CARD);
            }
            if self.context != 0 {
                ffi::SCardReleaseContext(self.context);
            }
        }
    }
}

/// Enumerates connected PC/SC smartcard readers.
pub fn list_pcsc_readers() -> Result<Vec<String>, CryptoError> {
    #[cfg(windows)]
    {
        let mut ctx: usize = 0;
        let res = unsafe {
            ffi::SCardEstablishContext(
                ffi::SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut ctx,
            )
        };
        if res != ffi::SCARD_S_SUCCESS {
            return Ok(Vec::new());
        }

        let mut len: u32 = 0;
        let list_len_res = unsafe {
            ffi::SCardListReadersA(ctx, std::ptr::null(), std::ptr::null_mut(), &mut len)
        };
        if list_len_res != ffi::SCARD_S_SUCCESS || len == 0 {
            unsafe { ffi::SCardReleaseContext(ctx) };
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; len as usize];
        let list_res =
            unsafe { ffi::SCardListReadersA(ctx, std::ptr::null(), buf.as_mut_ptr(), &mut len) };
        unsafe { ffi::SCardReleaseContext(ctx) };

        if list_res != ffi::SCARD_S_SUCCESS {
            return Ok(Vec::new());
        }

        let mut readers = Vec::new();
        for chunk in buf.split(|b| *b == 0) {
            if !chunk.is_empty() {
                if let Ok(name) = std::str::from_utf8(chunk) {
                    readers.push(name.to_string());
                }
            }
        }
        Ok(readers)
    }

    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Physical Hardware Token / YubiKey Implementation
// ---------------------------------------------------------------------------

/// Physical Hardware Token / YubiKey PIV Controller
pub struct PcscHardwareToken {
    reader_name: String,
    transport: Arc<Mutex<Option<NativePcscTransport>>>,
    cached_9c_pk: Arc<Mutex<Option<[u8; 32]>>>,
    cached_9d_pk: Arc<Mutex<Option<[u8; 32]>>>,
}

impl PcscHardwareToken {
    /// Attempts to auto-detect and connect to an attached YubiKey or PIV token.
    pub fn probe() -> Result<Option<Self>, CryptoError> {
        let readers = list_pcsc_readers()?;
        if readers.is_empty() {
            return Ok(None);
        }

        // Prefer readers containing "Yubico" or "YubiKey"
        let selected_reader = readers
            .iter()
            .find(|r| r.to_lowercase().contains("yubi"))
            .or_else(|| readers.first())
            .cloned();

        let reader_name = match selected_reader {
            Some(r) => r,
            None => return Ok(None),
        };

        match NativePcscTransport::connect(&reader_name) {
            Ok(transport) => {
                // Verify PIV applet exists
                let select_apdu = CommandApdu::select_piv();
                let resp = transport.transmit(&select_apdu)?;
                if !resp.is_success() {
                    return Ok(None);
                }

                Ok(Some(Self {
                    reader_name,
                    transport: Arc::new(Mutex::new(Some(transport))),
                    cached_9c_pk: Arc::new(Mutex::new(None)),
                    cached_9d_pk: Arc::new(Mutex::new(None)),
                }))
            }
            Err(_) => Ok(None),
        }
    }

    /// Creates a hardware token controller bound to a specific reader.
    pub fn connect_to_reader(reader: &str) -> Result<Self, CryptoError> {
        let transport = NativePcscTransport::connect(reader)?;
        let select_apdu = CommandApdu::select_piv();
        let resp = transport.transmit(&select_apdu)?;
        if !resp.is_success() {
            return Err(CryptoError::HsmError(format!(
                "Connected to reader '{}' but card rejected PIV applet selection (Status: {})",
                reader,
                resp.status_hex()
            )));
        }

        Ok(Self {
            reader_name: reader.to_string(),
            transport: Arc::new(Mutex::new(Some(transport))),
            cached_9c_pk: Arc::new(Mutex::new(None)),
            cached_9d_pk: Arc::new(Mutex::new(None)),
        })
    }

    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    /// Verifies the card PIN (standard default '123456' for testing or user-provided).
    pub fn verify_pin(&self, pin: &[u8]) -> Result<(), CryptoError> {
        let guard = self.transport.lock().unwrap();
        let transport = guard.as_ref().ok_or_else(|| {
            CryptoError::HsmError("Physical hardware token transport is disconnected".into())
        })?;

        let apdu = CommandApdu::verify_pin(pin);
        let resp = transport.transmit(&apdu)?;
        if resp.is_success() {
            Ok(())
        } else {
            Err(CryptoError::HsmError(format!(
                "PIN verification failed: {}",
                resp.error_description()
            )))
        }
    }

    /// Reads slot metadata and public key bytes via YubiKey metadata command.
    fn query_slot_metadata(&self, slot_byte: u8) -> Result<(u8, Vec<u8>, u8), CryptoError> {
        let guard = self.transport.lock().unwrap();
        let transport = guard.as_ref().ok_or_else(|| {
            CryptoError::HsmError("Physical hardware token transport is disconnected".into())
        })?;

        let apdu = CommandApdu::get_slot_metadata(slot_byte);
        let resp = transport.transmit(&apdu)?;
        if !resp.is_success() {
            return Err(CryptoError::HsmError(format!(
                "Failed to query slot 0x{:02X} metadata: {}",
                slot_byte,
                resp.error_description()
            )));
        }

        // Parse TLV tags according to Yubico PIV metadata specification:
        // Tag 01: Algorithm (1 byte)
        // Tag 02: PIN/Touch policy (PIN policy: 1 byte, Touch policy: 1 byte)
        // Tag 03: Origin (1 byte)
        // Tag 04: Public key bytes
        let mut alg: u8 = ALG_ED25519;
        let mut pk = Vec::new();
        let mut touch_policy: u8 = 0x01; // Default Never

        let d = &resp.data;
        let mut idx = 0;
        while idx < d.len() {
            let tag = d[idx];
            idx += 1;
            if idx >= d.len() {
                break;
            }
            let len = d[idx] as usize;
            idx += 1;
            if idx + len > d.len() {
                break;
            }
            match tag {
                0x01 if len >= 1 => {
                    alg = d[idx];
                }
                0x02 if len >= 2 => {
                    // Tag 02: byte 0 is PIN policy, byte 1 is touch policy
                    touch_policy = d[idx + 1];
                }
                0x02 if len == 1 => {
                    touch_policy = d[idx];
                }
                0x04 => {
                    pk = d[idx..idx + len].to_vec();
                }
                _ => {}
            }
            idx += len;
        }

        // Fallback: if pk was not found in tag 04, check if legacy source encoded pk in tag 02 (len 32)
        if pk.is_empty() {
            let mut scan_idx = 0;
            while scan_idx < d.len() {
                let tag = d[scan_idx];
                scan_idx += 1;
                if scan_idx >= d.len() {
                    break;
                }
                let len = d[scan_idx] as usize;
                scan_idx += 1;
                if scan_idx + len > d.len() {
                    break;
                }
                if tag == 0x02 && len == 32 {
                    pk = d[scan_idx..scan_idx + len].to_vec();
                    break;
                }
                scan_idx += len;
            }
        }

        Ok((alg, pk, touch_policy))
    }
}

impl HardwareSecurityModule for PcscHardwareToken {
    fn is_connected(&self) -> bool {
        let guard = self.transport.lock().unwrap();
        guard.is_some()
    }

    fn get_public_key(&self, slot: HsmSlot) -> Result<Vec<u8>, CryptoError> {
        let slot_byte = match slot {
            HsmSlot::DigitalSignature => PIV_SLOT_SIGNATURE,
            HsmSlot::KeyManagement => PIV_SLOT_KEY_MANAGEMENT,
            HsmSlot::Authentication => PIV_SLOT_AUTHENTICATION,
            HsmSlot::CardAuthentication => PIV_SLOT_CARD_AUTH,
        };

        if slot == HsmSlot::DigitalSignature {
            let cache = self.cached_9c_pk.lock().unwrap();
            if let Some(pk) = *cache {
                return Ok(pk.to_vec());
            }
        } else if slot == HsmSlot::KeyManagement {
            let cache = self.cached_9d_pk.lock().unwrap();
            if let Some(pk) = *cache {
                return Ok(pk.to_vec());
            }
        }

        let (_, pk, _) = self.query_slot_metadata(slot_byte)?;
        if pk.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk);
            if slot == HsmSlot::DigitalSignature {
                *self.cached_9c_pk.lock().unwrap() = Some(arr);
            } else if slot == HsmSlot::KeyManagement {
                *self.cached_9d_pk.lock().unwrap() = Some(arr);
            }
        }

        Ok(pk)
    }

    fn get_slot_info(&self, slot: HsmSlot) -> Result<HsmSlotInfo, CryptoError> {
        let slot_byte = match slot {
            HsmSlot::DigitalSignature => PIV_SLOT_SIGNATURE,
            HsmSlot::KeyManagement => PIV_SLOT_KEY_MANAGEMENT,
            HsmSlot::Authentication => PIV_SLOT_AUTHENTICATION,
            HsmSlot::CardAuthentication => PIV_SLOT_CARD_AUTH,
        };

        let (alg_id, pk, touch_raw) = self.query_slot_metadata(slot_byte)?;

        let algo_name = match alg_id {
            ALG_ED25519 => "Ed25519 (Pure-Rust / YubiKey 5.7+)".to_string(),
            ALG_X25519 => "X25519 (ECDH Key Management)".to_string(),
            ALG_ECCP256 => "ECCP256 (NIST P-256)".to_string(),
            _ => format!("Algorithm ID 0x{:02X}", alg_id),
        };

        let touch_str = match touch_raw {
            0x01 => "Never (Direct Hardware Sign)".to_string(),
            0x02 => "Always (Capacitive Finger Touch Required)".to_string(),
            0x03 => "Cached (15s Capacitive Touch Window)".to_string(),
            _ => "Hardware Default".to_string(),
        };

        Ok(HsmSlotInfo {
            slot,
            algorithm: algo_name,
            public_key_hex: hex::encode(&pk),
            touch_policy: touch_str,
            pin_policy: "PIN Always / Session Cached".into(),
        })
    }

    fn sign_digest(
        &self,
        slot: HsmSlot,
        domain: &[u8],
        digest: &[u8; 32],
    ) -> Result<[u8; 64], CryptoError> {
        self.sign_message(slot, domain, digest)
    }

    fn sign_message(
        &self,
        slot: HsmSlot,
        domain: &[u8],
        message: &[u8],
    ) -> Result<[u8; 64], CryptoError> {
        if slot != HsmSlot::DigitalSignature && slot != HsmSlot::Authentication {
            return Err(CryptoError::HsmError(format!(
                "Slot {:?} cannot perform digital signatures",
                slot
            )));
        }

        // Domain-separated challenge binding matching sign_with_domain
        let mut payload = Vec::with_capacity(
            crate::signatures::SIGNATURE_DOMAIN_PREFIX.len() + domain.len() + 1 + message.len(),
        );
        payload.extend_from_slice(crate::signatures::SIGNATURE_DOMAIN_PREFIX);
        payload.extend_from_slice(domain);
        payload.push(b':');
        payload.extend_from_slice(message);

        let guard = self.transport.lock().unwrap();
        let transport = guard.as_ref().ok_or_else(|| {
            CryptoError::HsmError("Physical hardware token is not connected".into())
        })?;

        let apdu =
            CommandApdu::general_authenticate_sign(ALG_ED25519, PIV_SLOT_SIGNATURE, &payload);

        let resp = transport.transmit(&apdu)?;
        if resp.is_touch_timeout() {
            return Err(CryptoError::HsmError(
                "Hardware touch timed out: user presence not detected on YubiKey token".to_string(),
            ));
        }

        let sig_bytes = resp.extract_dynamic_auth_response(0x82)?;
        if sig_bytes.len() != 64 {
            return Err(CryptoError::HsmError(format!(
                "Invalid signature length from hardware token: expected 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        Ok(sig)
    }

    fn ecdh_key_agreement(
        &self,
        slot: HsmSlot,
        peer_public_key: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        if slot != HsmSlot::KeyManagement && slot != HsmSlot::CardAuthentication {
            return Err(CryptoError::HsmError(format!(
                "Slot {:?} cannot perform ECDH key agreement",
                slot
            )));
        }

        let guard = self.transport.lock().unwrap();
        let transport = guard.as_ref().ok_or_else(|| {
            CryptoError::HsmError("Physical hardware token is not connected".into())
        })?;

        let apdu = CommandApdu::general_authenticate_ecdh(
            ALG_X25519,
            PIV_SLOT_KEY_MANAGEMENT,
            peer_public_key,
        );

        let resp = transport.transmit(&apdu)?;
        if resp.is_touch_timeout() {
            return Err(CryptoError::HsmError(
                "Hardware touch timed out during key agreement on YubiKey".to_string(),
            ));
        }

        let secret_bytes = resp.extract_dynamic_auth_response(0x85)?;
        if secret_bytes.len() != 32 {
            return Err(CryptoError::HsmError(format!(
                "Invalid shared secret length from hardware token: expected 32 bytes, got {}",
                secret_bytes.len()
            )));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apdu_serialization_select_piv() {
        let apdu = CommandApdu::select_piv();
        let bytes = apdu.to_bytes();

        assert_eq!(bytes[0], 0x00); // CLA
        assert_eq!(bytes[1], 0xA4); // INS
        assert_eq!(bytes[2], 0x04); // P1
        assert_eq!(bytes[3], 0x00); // P2
        assert_eq!(bytes[4], 11); // Lc
        assert_eq!(&bytes[5..16], &PIV_AID);
        assert_eq!(bytes[16], 0x00); // Le
    }

    #[test]
    fn test_apdu_serialization_verify_pin() {
        let apdu = CommandApdu::verify_pin(b"123456");
        let bytes = apdu.to_bytes();

        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x20);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x80);
        assert_eq!(bytes[4], 8); // 8 bytes padded
        assert_eq!(&bytes[5..11], b"123456");
        assert_eq!(bytes[11], 0xFF);
        assert_eq!(bytes[12], 0xFF);
    }

    #[test]
    fn test_apdu_dynamic_auth_sign_template() {
        let challenge = [0x55u8; 32];
        let apdu = CommandApdu::general_authenticate_sign(ALG_ED25519, 0x9C, &challenge);
        let bytes = apdu.to_bytes();

        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x87); // GENERAL AUTHENTICATE
        assert_eq!(bytes[2], ALG_ED25519);
        assert_eq!(bytes[3], 0x9C); // Slot 9C

        // Tag 7C is present
        assert_eq!(bytes[5], 0x7C);
    }

    #[test]
    fn test_response_apdu_parsing_and_status() {
        let raw_success = [0x01, 0x02, 0x03, 0x90, 0x00];
        let resp = ResponseApdu::parse(&raw_success).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.data, vec![0x01, 0x02, 0x03]);
        assert_eq!(resp.status_hex(), "9000");

        let raw_touch_timeout = [0x69, 0x85];
        let resp_timeout = ResponseApdu::parse(&raw_touch_timeout).unwrap();
        assert!(!resp_timeout.is_success());
        assert!(resp_timeout.is_touch_timeout());

        let raw_pin_req = [0x69, 0x82];
        let resp_pin = ResponseApdu::parse(&raw_pin_req).unwrap();
        assert!(resp_pin.is_pin_required());
    }

    #[test]
    fn test_dynamic_auth_tag_extraction() {
        // Tag 7C, len 8, Tag 82, len 4, [0xAA, 0xBB, 0xCC, 0xDD], Tag 81, len 0, SW: 90 00
        let payload = [0x7C, 0x06, 0x82, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x00];
        let resp = ResponseApdu::parse(&payload).unwrap();
        let sig = resp.extract_dynamic_auth_response(0x82).unwrap();
        assert_eq!(sig, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_list_readers_graceful_handling() {
        // On any system (with or without readers plugged in), list_pcsc_readers must not panic
        let readers = list_pcsc_readers();
        assert!(readers.is_ok());
    }

    #[test]
    fn test_slot_metadata_tlv_parsing() {
        // Tag 01 (alg, 1 byte): 0x22 (ALG_ED25519)
        // Tag 02 (PIN/touch, 2 bytes): 0x02 (PIN once), 0x02 (Touch cached)
        // Tag 03 (Origin, 1 byte): 0x01 (Generated)
        // Tag 04 (PK, 32 bytes): [0x42; 32]
        let mut raw = vec![
            0x01,
            0x01,
            ALG_ED25519,
            0x02,
            0x02,
            0x02,
            0x02,
            0x03,
            0x01,
            0x01,
            0x04,
            0x20,
        ];
        raw.extend_from_slice(&[0x42u8; 32]);
        raw.extend_from_slice(&[0x90, 0x00]); // SW: 9000

        let resp = ResponseApdu::parse(&raw).unwrap();
        assert!(resp.is_success());

        let d = &resp.data;
        let mut alg: u8 = 0;
        let mut pk = Vec::new();
        let mut touch: u8 = 0;
        let mut idx = 0;
        while idx < d.len() {
            let tag = d[idx];
            idx += 1;
            if idx >= d.len() {
                break;
            }
            let len = d[idx] as usize;
            idx += 1;
            if idx + len > d.len() {
                break;
            }
            match tag {
                0x01 if len >= 1 => alg = d[idx],
                0x02 if len >= 2 => touch = d[idx + 1],
                0x04 => pk = d[idx..idx + len].to_vec(),
                _ => {}
            }
            idx += len;
        }

        assert_eq!(alg, ALG_ED25519);
        assert_eq!(touch, 0x02);
        assert_eq!(pk, vec![0x42u8; 32]);
    }
}
