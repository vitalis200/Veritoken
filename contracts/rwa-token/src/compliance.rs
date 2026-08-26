#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use soroban_sdk::{contracttype, Address, Env, String, Symbol};

use crate::storage_types::{
    DataKey, BALANCE_BUMP_AMOUNT, BALANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT,
    INSTANCE_LIFETIME_THRESHOLD,
};
use crate::RwaError;

#[contracttype]
#[derive(Clone)]
struct ComplianceRulesMirror {
    max_transfer_amount: i128,
    min_holding_period: u64,
    max_holders: u32,
    require_same_jurisdiction: bool,
    paused: bool,
    allowlist_mode: bool,
    max_holding_period: u64,
}

pub fn read_compliance_engine(env: &Env) -> Address {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    env.storage()
        .instance()
        .get(&DataKey::ComplianceEngine)
        .expect("compliance engine must be set")
}

pub fn write_compliance_engine(env: &Env, engine: &Address) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    env.storage()
        .instance()
        .set(&DataKey::ComplianceEngine, engine);
}

pub fn write_metadata(env: &Env, key: Symbol, value: String) {
    env.storage()
        .instance()
        .set(&DataKey::ComplianceMeta(key), &value);
}

pub fn read_metadata(env: &Env, key: Symbol) -> String {
    env.storage()
        .instance()
        .get(&DataKey::ComplianceMeta(key))
        .unwrap_or_else(|| String::from_str(env, ""))
}

/// Cross-contract call to the compliance engine to validate a transfer.
///
/// Uses `evaluate_transfer` so that KYC-related denials are mapped to
/// `KycNotApproved` instead of the generic `TransferBlocked`, and all
/// missing/expired/revoked/rejected KYC records produce a deterministic deny
/// rather than a host trap.
///
/// Error propagation:
/// - Engine call failure (contract unavailable, host trap) → `ComplianceEngineUnavailable`.
/// - KYC-related deny reason → `KycNotApproved`.
/// - Any other deny reason → `TransferBlocked`.
///
/// Called before any state mutation so no partial state can be written on denial.
pub fn check_transfer(env: &Env, from: &Address, to: &Address, amount: i128) {
    let engine = read_compliance_engine(env);
    let client = ComplianceEngineClient::new(env, &engine);
    match client.try_evaluate_transfer(from, to, &amount) {
        Ok(Ok(compliance_interface::TransferDecision::Allow)) => {}
        Ok(Ok(compliance_interface::TransferDecision::Deny(ref reason))) => {
            use compliance_interface::DenyReason;
            match reason {
                DenyReason::FromKycMissing
                | DenyReason::ToKycMissing
                | DenyReason::FromKycExpired
                | DenyReason::ToKycExpired
                | DenyReason::FromKycRevoked
                | DenyReason::ToKycRevoked
                | DenyReason::FromKycRejected
                | DenyReason::ToKycRejected
                | DenyReason::FromKycPending
                | DenyReason::ToKycPending => {
                    soroban_sdk::panic_with_error!(env, RwaError::KycNotApproved)
                }
                _ => soroban_sdk::panic_with_error!(env, RwaError::TransferBlocked),
            }
        }
        Ok(Err(_)) | Err(_) => {
            soroban_sdk::panic_with_error!(env, RwaError::ComplianceEngineUnavailable)
        }
    }
}

/// Cross-contract call to the compliance engine to validate an inbound mint.
///
/// Minting has no real holder on the sending side — evaluating it with the
/// recipient as both `from` and `to` (a self-transfer) lets the engine's
/// `from`-side checks pass or fail based on the recipient's own state rather
/// than the mint itself, and requiring `from` to hold KYC (as `evaluate_transfer`
/// does) is meaningless for a synthetic sender. `to`'s KYC is already verified
/// by `kyc::require_kyc` before this is called, so `can_transfer` (which skips
/// the KYC check) is used with the token contract's own address as `from`,
/// still enforcing every other rule (blocklist, pause, holding period, tier,
/// holder cap) against a distinct, non-recipient address.
pub fn check_mint(env: &Env, to: &Address, amount: i128) {
    let engine = read_compliance_engine(env);
    let client = ComplianceEngineClient::new(env, &engine);
    match client.try_can_transfer(&env.current_contract_address(), to, &amount) {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => soroban_sdk::panic_with_error!(env, RwaError::TransferBlocked),
        Ok(Err(_)) | Err(_) => {
            soroban_sdk::panic_with_error!(env, RwaError::ComplianceEngineUnavailable)
        }
    }
}

/// Validates the final holder count for a transfer plan before its first
/// mutation.
///
/// `can_transfer` evaluates each recipient against the current holder count.
/// That is sufficient for a single transfer, but a batch with multiple new
/// recipients can otherwise have every leg pass against the same stale count
/// and exceed `max_holders` during execution.
pub fn ensure_holder_capacity(env: &Env, new_holder_count: u32, sender_will_leave: bool) {
    if new_holder_count == 0 {
        return;
    }

    let engine = read_compliance_engine(env);
    let client = ComplianceEngineClient::new(env, &engine);
    let rules = match client.try_get_rules() {
        Ok(Ok(rules)) => rules,
        Ok(Err(_)) | Err(_) => {
            soroban_sdk::panic_with_error!(env, RwaError::ComplianceEngineUnavailable)
        }
    };
    if rules.max_holders == 0 {
        return;
    }

    let current_count = match client.try_holder_count() {
        Ok(Ok(count)) => count,
        Ok(Err(_)) | Err(_) => {
            soroban_sdk::panic_with_error!(env, RwaError::ComplianceEngineUnavailable)
        }
    };
    let released_slots = u32::from(sender_will_leave);
    let projected_count = current_count
        .saturating_sub(released_slots)
        .saturating_add(new_holder_count);

    if projected_count > rules.max_holders {
        soroban_sdk::panic_with_error!(env, RwaError::HolderLimitExceeded);
    }
}

/// Cross-contract call to register a new holder in the compliance engine.
///
/// Failure panics with `ComplianceEngineUnavailable` so the outer transfer
/// is rolled back atomically — no partial state is persisted.
pub fn register_holder(env: &Env, addr: &Address) {
    let engine = read_compliance_engine(env);
    let client = ComplianceEngineClient::new(env, &engine);
    match client.try_register_holder(addr) {
        Ok(_) => {}
        Err(_) => soroban_sdk::panic_with_error!(env, RwaError::ComplianceEngineUnavailable),
    }
}

pub fn is_frozen(env: &Env, addr: &Address) -> bool {
    let key = DataKey::Frozen(addr.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

pub fn set_frozen(env: &Env, addr: &Address, frozen: bool) {
    let key = DataKey::Frozen(addr.clone());
    env.storage().persistent().set(&key, &frozen);
    env.storage()
        .persistent()
        .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);
}

/// Cross-contract call to remove a holder from the compliance engine.
///
/// Failure panics with `ComplianceEngineUnavailable` so the outer transfer
/// is rolled back atomically — no partial state is persisted.
pub fn unregister_holder(env: &Env, addr: &Address) {
    let engine = read_compliance_engine(env);
    let client = ComplianceEngineClient::new(env, &engine);
    match client.try_unregister_holder(addr) {
        Ok(_) => {}
        Err(_) => soroban_sdk::panic_with_error!(env, RwaError::ComplianceEngineUnavailable),
    }
}

mod compliance_interface {
    use soroban_sdk::{contractclient, contracttype, Address};

    /// Mirrors `compliance_engine::DenyReason` — variant names must stay
    /// identical for XDR round-tripping across the contract boundary.
    #[contracttype]
    #[derive(Clone, Debug, PartialEq)]
    pub enum DenyReason {
        CompliancePaused,
        FromBlocklisted,
        ToBlocklisted,
        FromKycMissing,
        ToKycMissing,
        FromKycExpired,
        ToKycExpired,
        FromKycRevoked,
        ToKycRevoked,
        FromKycRejected,
        ToKycRejected,
        FromKycPending,
        ToKycPending,
        FromJurisdictionBlocked,
        ToJurisdictionBlocked,
        SameJurisdictionRequired,
        AmountExceeded,
        HoldingPeriodNotMet,
        MaxHoldersReached,
        RecipientHoldingPeriodExceeded,
        TierPolicyBlocked,
        TierFromBelowMin,
        TierToBelowMin,
        TierAmountExceeded,
        RiskScoreTooHigh,
    }

    /// Mirrors `compliance_engine::TransferDecision`.
    #[contracttype]
    #[derive(Clone, Debug, PartialEq)]
    pub enum TransferDecision {
        Allow,
        Deny(DenyReason),
    }

    #[contractclient(name = "ComplianceEngineClient")]
    #[allow(dead_code)]
    pub trait ComplianceEngineInterface {
        fn can_transfer(env: soroban_sdk::Env, from: Address, to: Address, amount: i128) -> bool;
        /// Evaluates a transfer against all compliance rules including KYC state.
        /// Returns `TransferDecision::Allow` or `TransferDecision::Deny(reason)`.
        fn evaluate_transfer(
            env: soroban_sdk::Env,
            from: Address,
            to: Address,
            amount: i128,
        ) -> TransferDecision;
        fn get_rules(env: soroban_sdk::Env) -> super::ComplianceRulesMirror;
        fn register_holder(env: soroban_sdk::Env, addr: &Address);
        fn unregister_holder(env: soroban_sdk::Env, addr: &Address);
        fn holder_count(env: soroban_sdk::Env) -> u32;
    }
}
use compliance_interface::ComplianceEngineClient;
