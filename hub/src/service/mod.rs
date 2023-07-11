// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod services;

use std::sync::Arc;

use anyhow::*;
use tonic::transport::Server as TonicServer;

use crate::{Args, DataHub};

use self::services::{
    getresource::getresource_proto::get_resource_service_server::GetResourceServiceServer,
    keyprovider::keyprovider_proto::key_provider_service_server::KeyProviderServiceServer,
    sealed_secret::keyprovider::sealed_secret_service_server::SealedSecretServiceServer,
};

pub struct Server {
    core: DataHub,
    args: Args,
}

impl Server {
    pub async fn new(args: Args) -> Result<Self> {
        let core = DataHub::start(args.kbs_addr.clone())
            .await
            .context("launch datahub")?;
        Ok(Self { core, args })
    }

    pub async fn serve(self) -> Result<()> {
        let socket = self.args.socket;
        let s = Arc::new(self);
        TonicServer::builder()
            .add_service(KeyProviderServiceServer::new(s.clone()))
            .add_service(GetResourceServiceServer::new(s.clone()))
            .add_service(SealedSecretServiceServer::new(s))
            .serve(socket)
            .await?;

        Ok(())
    }
}
