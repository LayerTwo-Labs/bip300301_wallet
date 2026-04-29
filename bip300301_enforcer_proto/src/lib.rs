//! Generated gRPC types for the mainchain validator service, exposed under the historical
//! `bip300301_enforcer_proto::validator::*` module path.
//!
//! Prost emits `super::super::common::v1::…` from `cusf::mainchain::v1`, so we mirror the same
//! `cusf::{common,mainchain}::v1` tree as `bip300301_enforcer::proto`.

#[allow(clippy::large_enum_variant)]
#[allow(clippy::enum_variant_names)]
#[allow(missing_docs)]
pub mod cusf {
    pub mod common {
        pub mod v1 {
            tonic::include_proto!("cusf.common.v1");
        }
    }
    pub mod mainchain {
        pub mod v1 {
            tonic::include_proto!("cusf.mainchain.v1");
        }
    }
}

/// Convenience re-export for callers that need hex-wrapped bitcoin types from protos.
pub use cusf::common::v1 as enforcer_common;

/// Legacy module layout expected by `bip300301_wallet` and `cusf_sidechain`.
pub mod validator {
    pub use super::cusf::mainchain::v1::*;

    /// Historical name: maps to `ValidatorServiceClient` from `ValidatorService`.
    pub mod validator_client {
        pub use super::validator_service_client::ValidatorServiceClient as ValidatorClient;
    }
}
