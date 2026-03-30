//! Compatibility traits for converting between consensus and RPC transaction types.
//!
//! This crate provides trait definitions for:
//! - [`SignableTxRequest`]: Building and signing transaction requests.
//! - [`FromConsensusTx`] / [`IntoRpcTx`]: Converting consensus transactions to RPC responses.
//! - [`TryIntoSimTx`]: Converting transaction requests to simulated transactions.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_consensus::{
    error::ValueError, transaction::Recovered, EthereumTxEnvelope, SignableTransaction, TxEip4844,
};
use alloy_network::TxSigner;
use alloy_primitives::{Address, Signature};
use alloy_rpc_types_eth::{Transaction, TransactionInfo, TransactionRequest};
use core::{convert::Infallible, error, fmt::Debug, future::Future};

/// Error for [`SignableTxRequest`] trait.
#[derive(Debug, thiserror::Error)]
pub enum SignTxRequestError {
    /// The transaction request is invalid.
    #[error("invalid transaction request")]
    InvalidTransactionRequest,

    /// The signer is not supported.
    #[error(transparent)]
    SignerNotSupported(#[from] alloy_signer::Error),
}

/// An abstraction over transaction requests that can be signed.
pub trait SignableTxRequest<T>: Send + Sync + 'static {
    /// Attempts to build a transaction request and sign it with the given signer.
    fn try_build_and_sign(
        self,
        signer: impl TxSigner<Signature> + Send,
    ) -> impl Future<Output = Result<T, SignTxRequestError>> + Send;
}

impl SignableTxRequest<EthereumTxEnvelope<TxEip4844>> for TransactionRequest {
    async fn try_build_and_sign(
        self,
        signer: impl TxSigner<Signature> + Send,
    ) -> Result<EthereumTxEnvelope<TxEip4844>, SignTxRequestError> {
        let mut tx =
            self.build_typed_tx().map_err(|_| SignTxRequestError::InvalidTransactionRequest)?;
        let signature = signer.sign_transaction(&mut tx).await?;
        Ok(tx.into_signed(signature).into())
    }
}

/// Converts `self` into `T`. The opposite of [`FromConsensusTx`].
///
/// Should create an RPC transaction response object based on a consensus transaction, its signer
/// [`Address`] and an additional context [`IntoRpcTx::TxInfo`].
///
/// Avoid implementing [`IntoRpcTx`] and use [`FromConsensusTx`] instead. Implementing it
/// automatically provides an implementation of [`IntoRpcTx`] thanks to the blanket implementation
/// in this crate.
///
/// Prefer using [`IntoRpcTx`] over [`FromConsensusTx`] when specifying trait bounds on a generic
/// function to ensure that types that only implement [`IntoRpcTx`] can be used as well.
pub trait IntoRpcTx<T> {
    /// An additional context, usually [`TransactionInfo`] in a wrapper that carries some
    /// implementation specific extra information.
    type TxInfo;
    /// An associated RPC conversion error.
    type Err: error::Error;

    /// Performs the conversion consuming `self` with `signer` and `tx_info`. See [`IntoRpcTx`]
    /// for details.
    fn into_rpc_tx(self, signer: Address, tx_info: Self::TxInfo) -> Result<T, Self::Err>;
}

/// Converts `T` into `self`. It is reciprocal of [`IntoRpcTx`].
///
/// Should create an RPC transaction response object based on a consensus transaction, its signer
/// [`Address`] and an additional context [`FromConsensusTx::TxInfo`].
///
/// Prefer implementing [`FromConsensusTx`] over [`IntoRpcTx`] because it automatically provides an
/// implementation of [`IntoRpcTx`] thanks to the blanket implementation in this crate.
///
/// Prefer using [`IntoRpcTx`] over using [`FromConsensusTx`] when specifying trait bounds on a
/// generic function. This way, types that directly implement [`IntoRpcTx`] can be used as arguments
/// as well.
pub trait FromConsensusTx<T>: Sized {
    /// An additional context, usually [`TransactionInfo`] in a wrapper that carries some
    /// implementation specific extra information.
    type TxInfo;
    /// An associated RPC conversion error.
    type Err: error::Error;

    /// Performs the conversion consuming `tx` with `signer` and `tx_info`. See [`FromConsensusTx`]
    /// for details.
    fn from_consensus_tx(tx: T, signer: Address, tx_info: Self::TxInfo) -> Result<Self, Self::Err>;
}

impl<ConsensusTx, RpcTx> IntoRpcTx<RpcTx> for ConsensusTx
where
    ConsensusTx: alloy_consensus::Transaction,
    RpcTx: FromConsensusTx<Self>,
    <RpcTx as FromConsensusTx<ConsensusTx>>::Err: Debug,
{
    type TxInfo = RpcTx::TxInfo;
    type Err = <RpcTx as FromConsensusTx<ConsensusTx>>::Err;

    fn into_rpc_tx(self, signer: Address, tx_info: Self::TxInfo) -> Result<RpcTx, Self::Err> {
        RpcTx::from_consensus_tx(self, signer, tx_info)
    }
}

impl<TxIn: alloy_consensus::Transaction, T: alloy_consensus::Transaction + From<TxIn>>
    FromConsensusTx<TxIn> for Transaction<T>
{
    type TxInfo = TransactionInfo;
    type Err = Infallible;

    fn from_consensus_tx(
        tx: TxIn,
        signer: Address,
        tx_info: Self::TxInfo,
    ) -> Result<Self, Self::Err> {
        Ok(Self::from_transaction(Recovered::new_unchecked(tx.into(), signer), tx_info))
    }
}

/// Converts `self` into `T`.
///
/// Should create a fake transaction for simulation using a transaction request.
pub trait TryIntoSimTx<T>
where
    Self: Sized,
{
    /// Performs the conversion.
    ///
    /// Should return a signed typed transaction envelope for the [`eth_simulateV1`] endpoint with a
    /// dummy signature or an error if required fields are missing.
    ///
    /// [`eth_simulateV1`]: <https://github.com/ethereum/execution-apis/pull/484>
    fn try_into_sim_tx(self) -> Result<T, ValueError<Self>>;
}

impl TryIntoSimTx<EthereumTxEnvelope<TxEip4844>> for TransactionRequest {
    fn try_into_sim_tx(self) -> Result<EthereumTxEnvelope<TxEip4844>, ValueError<Self>> {
        Self::build_typed_simulate_transaction(self)
    }
}
