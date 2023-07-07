// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use log::{debug, error};
use tonic::{Response, Status};

use crate::service::Server;

use self::getresource_proto::{
    get_resource_service_server::GetResourceService, GetResourceRequest, GetResourceResponse,
};

pub mod getresource_proto {
    tonic::include_proto!("getresource");
}

#[tonic::async_trait]
impl GetResourceService for Arc<Server> {
    async fn get_resource(
        &self,
        request: tonic::Request<GetResourceRequest>,
    ) -> Result<Response<GetResourceResponse>, Status> {
        debug!("The GetResource API is called...");

        let req = request.into_inner();
        debug!(
            "KBS URI and KBC type are ignored.. request for {}",
            req.resource_path
        );

        let resource = self
            .core
            .get_resource(req.resource_path)
            .await
            .map_err(|e| {
                error!("Call CDH to get resource failed: {}", e);
                Status::internal(format!("[ERROR] CDH get resource failed: {e}",))
            })?;

        debug!("Resource retrieved.");

        debug!("Unsealing succeeded.");
        let reply = GetResourceResponse { resource };

        Ok(Response::new(reply))
    }
}
