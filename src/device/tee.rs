// Copyright 2022, Qingdao IotPi Information Technology, Ltd.,
// All rights reserved

use crate::{
    anyhow,
    device::{
        test::{self, TestResult},
        DeviceArgs,
    },
    Result,
};
use bytes::Bytes;
use helium_crypto::{
    tee::{
        self,
        iotpi_helium_optee::{del_ecc_keypair, gen_ecc_keypair},
    },
    KeyTag, KeyType, Keypair, Network, Sign, Verify,
};
use http::Uri;
use rand::rngs::OsRng;
use serde::{Serialize, Serializer};
use std::{
    fmt,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct Device {
    pub slot: u8,
}

impl Device {
    // tz://iotpi-optee?slot=0
    pub fn from_url(url: &Uri) -> Result<Self> {
        let args = DeviceArgs::from_uri(url)?;
        let address = url.port_u16().unwrap_or(96);
        let slot = args.get("slot", 0)?;

        Ok(Self { slot })
    }

    pub fn get_info(&self) -> Result<Info> {
        let info = Info { slot: self.slot };
        Ok(info)
    }

    pub fn get_keypair(&self, create: bool) -> Result<Keypair> {
        let keypair: Keypair = if create {
            generate_compact_key_in_slot(self.slot)?
        } else {
            compact_key_in_slot(self.slot)?
        };
        Ok(keypair)
    }

    pub fn provision(&self) -> Result<Keypair> {
        self.get_keypair(true)
    }

    pub fn get_config(&self) -> Result<Config> {
        Ok(Config {})
    }

    pub fn get_tests(&self) -> Vec<Test> {
        vec![
            Test::MinerKey(self.slot),
            Test::Sign(self.slot),
            Test::Ecdh(self.slot),
        ]
    }
}

fn compact_key_in_slot(slot: u8) -> Result<Keypair> {
    let keypair = tee::Keypair::keypair(slot, Network::MainNet)?;
    Ok(keypair.into())
}

fn generate_compact_key_in_slot(slot: u8) -> Result<Keypair> {
    let mut try_count = 10;
    loop {
        gen_ecc_keypair(slot)?;

        match compact_key_in_slot(slot) {
            Ok(keypair) => return Ok(keypair),
            Err(err) if try_count == 0 => return Err(err),
            Err(_) => {
                try_count -= 1;
                del_ecc_keypair(slot)?;
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Info {
    slot: u8,
}

#[derive(Debug, Serialize)]
pub struct Config {}

#[derive(Debug)]
pub enum Test {
    MinerKey(u8),
    Sign(u8),
    Ecdh(u8),
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinerKey(slot) => f.write_fmt(format_args!("miner_key({})", slot)),
            Self::Sign(slot) => f.write_fmt(format_args!("sign({})", slot)),
            Self::Ecdh(slot) => f.write_fmt(format_args!("ecdh({})", slot)),
        }
    }
}

impl Test {
    pub fn run(&self) -> TestResult {
        match self {
            Self::MinerKey(slot) => check_miner_key(*slot),
            Self::Sign(slot) => check_sign(*slot),
            Self::Ecdh(slot) => check_ecdh(*slot),
        }
    }
}
fn check_miner_key(slot: u8) -> TestResult {
    let keypair = compact_key_in_slot(slot)?;
    test::pass(keypair.public_key()).into()
}

fn check_sign(slot: u8) -> TestResult {
    const DATA: &[u8] = b"hello world";
    let keypair = compact_key_in_slot(slot)?;
    let signature = keypair.sign(DATA)?;
    keypair.public_key().verify(DATA, &signature)?;
    test::pass("ok").into()
}

fn check_ecdh(slot: u8) -> TestResult {
    use rand::rngs::OsRng;
    let keypair = compact_key_in_slot(slot)?;
    let other_keypair = Keypair::generate(
        KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        },
        &mut OsRng,
    );
    let ecc_shared_secret = keypair.ecdh(other_keypair.public_key())?;
    let other_shared_secret = other_keypair.ecdh(&keypair.public_key())?;

    if ecc_shared_secret.as_bytes() != other_shared_secret.as_bytes() {
        return test::expected(
            format!("{:#02x}", ecc_shared_secret.as_bytes()),
            format!("{:#02x}", other_shared_secret.as_bytes()),
        )
        .into();
    }
    test::pass("ok").into()
}
