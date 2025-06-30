
use poem::{
    handler, middleware::Cors, web::Json, EndpointExt, Route, Server,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use spl_associated_token_account::get_associated_token_address;
use bs58;
use base64::{Engine as _, engine::general_purpose};
use std::str::FromStr;

// Common response format
fn success_response(data: Value) -> Json<Value> {
    Json(json!({
        "success": true,
        "data": data
    }))
}

fn error_response(message: &str) -> Json<Value> {
    Json(json!({
        "success": false,
        "error": message
    }))
}

// Request structures
#[derive(Deserialize)]
struct TokenCreationRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct TokenMintingRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct MessageSigningRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct MessageVerificationRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SolTransferRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct TokenTransferRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// Helper functions
fn parse_public_key(key_string: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(key_string).map_err(|_| "Invalid public key format".to_string())
}

fn parse_secret_key(secret_string: &str) -> Result<Keypair, String> {
    let decoded_bytes = bs58::decode(secret_string)
        .into_vec()
        .map_err(|_| "Invalid secret key format".to_string())?;

    if decoded_bytes.len() != 64 {
        return Err("Secret key must be 64 bytes".to_string());
    }

    Keypair::from_bytes(&decoded_bytes)
        .map_err(|_| "Cannot create keypair from secret".to_string())
}

// Endpoint handlers
#[handler]
async fn create_new_keypair() -> Json<Value> {
    let new_keypair = Keypair::new();
    let public_key_b58 = bs58::encode(new_keypair.pubkey().to_bytes()).into_string();
    let secret_key_b58 = bs58::encode(new_keypair.to_bytes()).into_string();

    success_response(json!({
        "pubkey": public_key_b58,
        "secret": secret_key_b58
    }))
}

#[handler]
async fn handle_token_creation(Json(request): Json<TokenCreationRequest>) -> Json<Value> {
    let mint_authority_key = match parse_public_key(&request.mint_authority) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let mint_key = match parse_public_key(&request.mint) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let token_program = spl_token::id();
    let mint_instruction = initialize_mint(
        &token_program,
        &mint_key,
        &mint_authority_key,
        None,
        request.decimals,
    ).unwrap();

    let accounts: Vec<Value> = mint_instruction.accounts
        .iter()
        .map(|acc| json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        }))
        .collect();

    success_response(json!({
        "program_id": mint_instruction.program_id.to_string(),
        "accounts": accounts,
        "instruction_data": general_purpose::STANDARD.encode(&mint_instruction.data)
    }))
}

#[handler]
async fn handle_token_minting(Json(request): Json<TokenMintingRequest>) -> Json<Value> {
    let mint_key = match parse_public_key(&request.mint) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let destination_key = match parse_public_key(&request.destination) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let authority_key = match parse_public_key(&request.authority) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let token_program = spl_token::id();
    let minting_instruction = mint_to(
        &token_program,
        &mint_key,
        &destination_key,
        &authority_key,
        &[],
        request.amount,
    ).unwrap();

    let accounts: Vec<Value> = minting_instruction.accounts
        .iter()
        .map(|acc| json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable
        }))
        .collect();

    success_response(json!({
        "program_id": minting_instruction.program_id.to_string(),
        "accounts": accounts,
        "instruction_data": general_purpose::STANDARD.encode(&minting_instruction.data)
    }))
}

#[handler]
async fn sign_user_message(Json(request): Json<MessageSigningRequest>) -> Json<Value> {
    if request.message.is_empty() || request.secret.is_empty() {
        return error_response("Missing required fields");
    }

    let user_keypair = match parse_secret_key(&request.secret) {
        Ok(keypair) => keypair,
        Err(e) => return error_response(&e),
    };

    let message_bytes = request.message.as_bytes();
    let message_signature = user_keypair.sign_message(message_bytes);
    let signature_b64 = general_purpose::STANDARD.encode(message_signature.as_ref());
    let public_key_b58 = bs58::encode(user_keypair.pubkey().to_bytes()).into_string();

    success_response(json!({
        "signature": signature_b64,
        "public_key": public_key_b58,
        "message": request.message
    }))
}

#[handler]
async fn verify_user_message(Json(request): Json<MessageVerificationRequest>) -> Json<Value> {
    if request.message.is_empty() || request.signature.is_empty() || request.pubkey.is_empty() {
        return error_response("Missing required fields");
    }

    let public_key = match parse_public_key(&request.pubkey) {
        Ok(key) => key,
        Err(_) => return error_response("Invalid public key format"),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&request.signature) {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid signature format"),
    };

    let is_signature_valid = if signature_bytes.len() == 64 {
        match Signature::try_from(signature_bytes.as_slice()) {
            Ok(signature) => signature.verify(public_key.as_ref(), request.message.as_bytes()),
            Err(_) => false,
        }
    } else {
        false
    };

    success_response(json!({
        "valid": is_signature_valid,
        "message": request.message,
        "pubkey": request.pubkey
    }))
}

#[handler]
async fn transfer_sol(Json(request): Json<SolTransferRequest>) -> Json<Value> {
    if request.lamports == 0 {
        return error_response("Amount must be greater than 0");
    }

    let sender_key = match parse_public_key(&request.from) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let recipient_key = match parse_public_key(&request.to) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    if sender_key == recipient_key {
        return error_response("Sender and recipient cannot be the same");
    }

    let transfer_instruction = system_instruction::transfer(&sender_key, &recipient_key, request.lamports);
    let account_addresses: Vec<String> = transfer_instruction.accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    success_response(json!({
        "program_id": transfer_instruction.program_id.to_string(),
        "accounts": account_addresses,
        "instruction_data": general_purpose::STANDARD.encode(&transfer_instruction.data)
    }))
}

#[handler]
async fn transfer_tokens(Json(request): Json<TokenTransferRequest>) -> Json<Value> {
    if request.amount == 0 {
        return error_response("Amount must be greater than 0");
    }

    let destination_key = match parse_public_key(&request.destination) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let mint_key = match parse_public_key(&request.mint) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let owner_key = match parse_public_key(&request.owner) {
        Ok(key) => key,
        Err(e) => return error_response(&e),
    };

    let source_token_account = get_associated_token_address(&owner_key, &mint_key);
    let destination_token_account = get_associated_token_address(&destination_key, &mint_key);

    let token_program = spl_token::id();
    let transfer_instruction = transfer(
        &token_program,
        &source_token_account,
        &destination_token_account,
        &owner_key,
        &[],
        request.amount,
    ).unwrap();

    let account_info: Vec<Value> = transfer_instruction.accounts
        .iter()
        .map(|acc| json!({
            "pubkey": acc.pubkey.to_string(),
            "isSigner": acc.is_signer
        }))
        .collect();

    success_response(json!({
        "program_id": transfer_instruction.program_id.to_string(),
        "accounts": account_info,
        "instruction_data": general_purpose::STANDARD.encode(&transfer_instruction.data)
    }))
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let server_routes = Route::new()
        .at("/keypair", poem::post(create_new_keypair))
        .at("/token/create", poem::post(handle_token_creation))
        .at("/token/mint", poem::post(handle_token_minting))
        .at("/message/sign", poem::post(sign_user_message))
        .at("/message/verify", poem::post(verify_user_message))
        .at("/send/sol", poem::post(transfer_sol))
        .at("/send/token", poem::post(transfer_tokens))
        .with(Cors::new());

    println!("🚀 Starting Solana API server on http://0.0.0.0:3000");
    println!("Ready to handle requests:");
    println!("  POST /keypair           - Generate new keypair");
    println!("  POST /token/create      - Create new token");
    println!("  POST /token/mint        - Mint tokens");
    println!("  POST /message/sign      - Sign messages");
    println!("  POST /message/verify    - Verify signatures");
    println!("  POST /send/sol          - Transfer SOL");
    println!("  POST /send/token        - Transfer tokens");

    Server::new(poem::listener::TcpListener::bind("0.0.0.0:3000"))
        .run(server_routes)
        .await
}
