use mongodb::bson;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDTO {
    pub username: String,
    pub password: String,
}

impl UserDTO {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub salt: String,
}

impl User {
    pub fn new(username: String, password: String, salt: String) -> Self {
        Self { username, password, salt }
    }
}
