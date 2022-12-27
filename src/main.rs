use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, response::Html, Router, routing::{get, post}};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse};
use mongodb::{Client, Database};
use mongodb::bson::{doc, Document};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::user::{User, UserDTO};

mod user;

struct SharedState {
    db: Database,
    rng: SystemRandom,
}

trait DatabaseType: Clone + DeserializeOwned + Send + Serialize + Sync + Unpin {}

impl<T> DatabaseType for T where T: Clone + DeserializeOwned + Send + Serialize + Sync + Unpin {}

async fn get_from_database<T>(state: &Arc<SharedState>, name: &str, query: Option<Document>) -> Option<T> where T: DatabaseType {
    state.db
        .collection::<T>(name)
        .find_one(query, None)
        .await
        .unwrap()
}

async fn insert_into_database<T>(state: &Arc<SharedState>, name: &str, insertion: T) where T: DatabaseType {
    state
        .db
        .collection::<T>(name)
        .insert_one(insertion, None)
        .await
        .unwrap();
}

fn get_hash_string(to_hash: &String, salt: &String) -> String {
    format!(
        "{:x}",
        Sha256::new()
            .chain_update(to_hash)
            .chain_update(salt)
            .finalize()
    )
}

#[tokio::main]
async fn main() {
    let client = Client::with_uri_str("mongodb://localhost:27017")
        .await
        .unwrap();

    let shared_state = Arc::new(SharedState {
        db: client.database("rust_db"),
        rng: SystemRandom::new(),
    });

    let app = Router::new()
        .route("/", get(handler))
        .route("/user/:username", get(get_user))
        .route("/user", post(create_user))
        .route("/login", post(login))
        .with_state(shared_state);

    let address = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("listening on {}", address);
    axum::Server::bind(&address)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler() -> Html<&'static str> {
    Html("<h1>Hello, World!</h1>")
}

fn get_user_response(user: Option<User>, username: String) -> impl IntoResponse {
    match user {
        Some(_) => (StatusCode::OK, format!("Found user \"{}\".", username)),
        None => (StatusCode::BAD_REQUEST, format!("The username \"{}\" does not exist.", username))
    }
}

async fn get_user(State(state): State<Arc<SharedState>>, Path(username): Path<String>) -> impl IntoResponse {
    let lowercase_username = str::to_lowercase(&username);
    let user: Option<User> = get_from_database(&state,"users",Some(doc! { "username": lowercase_username, })).await;

    get_user_response(user, username)
}

fn get_salt_hash_string(state: &SharedState) -> String {
    let mut salt = [0u8; 64];
    state.rng.fill(&mut salt).expect("There was an error creating the salt.");
    base64::encode(salt)
}

async fn create_user(State(state): State<Arc<SharedState>>, Json(dto): Json<UserDTO>, ) -> impl IntoResponse {
    let lowercase_username = str::to_lowercase(&dto.username);

    let user: Option<User> = get_from_database(&state, "users", Some(doc! { "username": &lowercase_username, })).await;

    if user.is_some() {
        return (StatusCode::CONFLICT, format!("Username \"{}\" already exists.", &dto.username));
    }

    let salt_string = get_salt_hash_string(&state);

    let hashed_password = get_hash_string(&dto.password, &salt_string);

    insert_into_database(
        &state,
        "users",
        User {
            username: lowercase_username,
            password: hashed_password,
            display_name: dto.username.clone(),
            salt: salt_string,
        }
    ).await;

    (StatusCode::OK, format!("Created user \"{}\".", &dto.username))
}

fn get_login_response(user: Option<User>, dto: UserDTO) -> impl IntoResponse {
    let db_user = match user {
        Some(user) => user,
        None => return (StatusCode::BAD_REQUEST, format!("The username \"{}\" does not exist.", &dto.username))
    };

    let hashed_password = get_hash_string(&dto.password, &db_user.salt);

    if hashed_password.eq(&db_user.password) {
        return (StatusCode::OK, format!("Successfully logged in as \"{}\".", db_user.display_name));
    }

    (StatusCode::UNAUTHORIZED, "The submitted password was incorrect.".to_string())
}

async fn login(State(state): State<Arc<SharedState>>, Json(dto): Json<UserDTO>) -> impl IntoResponse {
    let lowercase_username = str::to_lowercase(&dto.username);

    let user: Option<User> = get_from_database(&state, "users", Some(doc! { "username": &lowercase_username, })).await;

    get_login_response(user, dto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_user_none_user_returns_400() {
        let response = get_user_response(None, "Example".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"The username \"Example\" does not exist.");
    }

    #[tokio::test]
    async fn some_user_returns_200() {
        let username = "Aenimus".to_string();
        let lowercase_username = str::to_lowercase(&username);
        let user = User {
            username: lowercase_username,
            password: "".to_string(),
            display_name: username.clone(),
            salt: "".to_string(),
        };
        let response = get_user_response(Some(user), username).into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"Found user \"Aenimus\".");
    }

    #[test]
    fn password_and_salt_return_correct_hash() {
        let hash_string = get_hash_string(&"password".to_string(), &"salt".to_string());
        assert_eq!(hash_string, "7a37b85c8918eac19a9089c0fa5a2ab4dce3f90528dcdeec108b23ddf3607b99")
    }

    #[tokio::test]
    async fn login_none_user_returns_400() {
        let response = get_login_response(
            None,
            UserDTO {
                username: "Aenimus".to_string(),
                password: "".to_string()
            }).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"The username \"Aenimus\" does not exist.");
    }

    #[tokio::test]
    async fn login_incorrect_password_returns_401() {
        let username = "Aenimus".to_string();
        let lowercase_username = str::to_lowercase(&username);
        let response = get_login_response(
            Some(User {
                username: lowercase_username.clone(),
                password: "password".to_string(),
                display_name: username.clone(),
                salt: "".to_string(),
            }),
            UserDTO {
                username,
                password: "passwor".to_string()
            }).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"The submitted password was incorrect.");
    }

    #[tokio::test]
    async fn login_correct_password_returns_200() {
        let username = "Aenimus".to_string();
        let lowercase_username = str::to_lowercase(&username);
        let response = get_login_response(
            Some(User {
                username: lowercase_username.clone(),
                password: "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7".to_string(),
                display_name: username.clone(),
                salt: "".to_string(),
            }),
            UserDTO {
                username,
                password: "hunter2".to_string()
            }).into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"Successfully logged in as \"Aenimus\".");
    }
}