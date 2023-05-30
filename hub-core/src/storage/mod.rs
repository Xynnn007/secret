// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, sync::Arc};

use anyhow::*;
use log::info;
use storage::{Type, Provider};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct StorageManager {
    /// This implies that we only maintain one client for each type of Storage.
    clients: HashMap<Type, Arc<Mutex<dyn Provider>>>,
}

impl StorageManager {
    pub async fn get_blob(&mut self, provider: &str, path: &str) -> Result<Vec<u8>> {
        let typ = Type::try_from(provider)?;
        if !self.clients.contains_key(&typ) {
            info!("init a client for {}", AsRef::<str>::as_ref(provider));
            let client = typ.to_client()?;
            self.clients.insert(typ.clone(), client);
        }

        let mut client = self
            .clients
            .get_mut(&typ)
            .expect("Unexpected uninitialized")
            .lock()
            .await;
        client.get_blob(path).await
    }
}
