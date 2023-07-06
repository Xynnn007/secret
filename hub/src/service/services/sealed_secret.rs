// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::Context;
use log::{debug, error};
use tonic::{Response, Status};

use crate::service::Server;

use self::keyprovider::{
    sealed_secret_service_server::SealedSecretService, UnSealSecretInput, UnSealSecretOutput,
};

pub mod keyprovider {
    tonic::include_proto!("sealed_secret");
}

#[tonic::async_trait]
impl SealedSecretService for Arc<Server> {
    async fn unseal_secret(
        &self,
        request: tonic::Request<UnSealSecretInput>,
    ) -> Result<Response<UnSealSecretOutput>, Status> {
        debug!("The UnsealSecret API is called...");

        let secret = request.into_inner();
        let secret = serde_json::from_slice(&secret.secret)
            .context("parse SealedSecret")
            .map_err(|e| {
                error!("Parse request failed: {}", e);
                Status::internal(format!("[ERROR] Parse request failed: {e}",))
            })?;

        debug!("Starting to unseal...");
        let plaintext = self.core.unseal_secret(secret).await.map_err(|e| {
            error!("Unseal Secret failed: {}", e);
            Status::internal(format!("[ERROR] Unseal Secret failed: {e}",))
        })?;

        debug!("Unsealing succeeded.");
        let reply = UnSealSecretOutput { plaintext };

        Ok(Response::new(reply))
    }
}
