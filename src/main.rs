use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::Path;
use axum::{
    response::Html,
    routing::{get, post},
    Json, Router,
};
use base64::encode;
use mongodb::bson::doc;
use mongodb::{options::ClientOptions, Client, Database};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use axum::body::{Bytes, Full};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::sync::OnceCell;

use crate::user::{User, UserDTO};

mod user;

struct State {
    db: Database,
    rng: SystemRandom,
}

async fn client() -> Client {
    Client::with_uri_str("mongodb://localhost:27017")
        .await
        .unwrap()
}

#[tokio::main]
async fn main() {
    let client = Client::with_uri_str("mongodb://localhost:27017")
        .await
        .unwrap();

    let shared_state = Arc::new(State {
        db: client.database("rust_db"),
        rng: SystemRandom::new(),
    });

    let app = Router::new()
        .route("/", get(handler))
        .route(
            "/user",
            get({
                let shared_state = Arc::clone(&shared_state);
                move || get_user(Arc::clone(&shared_state))
            }),
        )
        .route(
            "/user",
            post({
                let shared_state = Arc::clone(&shared_state);
                move |dto| create_user(dto, Arc::clone(&shared_state))
            }),
        )
        .route(
            "/login",
            post({
                let shared_state = Arc::clone(&shared_state);
                move |dto| login(dto, Arc::clone(&shared_state))
            }),
        );

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

async fn get_user(state: Arc<State>) -> impl IntoResponse {
    let user = state
        .db
        .collection::<User>("users")
        .find_one(Some(doc! { "username": "Aen", }), None)
        .await;

    match user.unwrap() {
        Some(user) => (StatusCode::OK, user.username),
        None => (StatusCode::BAD_REQUEST, "The username does not exist.")
    }
}

async fn create_user(Json(dto): Json<UserDTO>, state: Arc<State>) -> impl IntoResponse {
    let user = state
        .db
        .collection::<User>("users")
        .find_one(Some(doc! { "username": dto.username.clone(), }), None)
        .await;

    if let Some(_) = user.unwrap() {
        return "User already exists".to_string();
    }

    let mut salt = [0u8; 64];
    state.rng.fill(&mut salt).expect("Salt failure");
    let salt_string = base64::encode(salt);

    let hashed_password = format!(
        "{:x}",
        Sha256::new()
            .chain_update(dto.password)
            .chain_update(&salt_string)
            .finalize()
    );

    state
        .db
        .collection::<User>("users")
        .insert_one(
            User {
                username: dto.username,
                password: hashed_password,
                salt: salt_string,
            },
            None,
        )
        .await
        .unwrap();
    "Created user.".to_string()
}

async fn login(Json(dto): Json<UserDTO>, state: Arc<State>) -> impl IntoResponse {
    let user = state
        .db
        .collection::<User>("users")
        .find_one(Some(doc! { "username": dto.username.clone(), }), None)
        .await;

    let db_user = match user.unwrap() {
        Some(user) => user,
        None => return (StatusCode::BAD_REQUEST, "The submitted username does not exist.")
    };

    let hashed_password = format!(
        "{:x}",
        Sha256::new()
            .chain_update(dto.password)
            .chain_update(db_user.salt)
            .finalize()
    );

    if hashed_password.eq(&db_user.password) {
        return (StatusCode::OK, "Successfully logged in as ".to_owned() + &db_user.username)
    }

    (StatusCode::UNAUTHORIZED,"The submitted password was incorrect.")
}