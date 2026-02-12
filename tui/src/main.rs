use age::secrecy::{ExposeSecretMut, SecretString};
use anyhow::anyhow;
use cursive::theme::Theme;
use cursive::traits::*;
use cursive::views::{Dialog, EditView, LinearLayout, SelectView, TextView};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPair {
    id: String,
    pk: String,
    sk: String,
    #[serde(rename = "type")]
    key_type: String,
}

fn get_vault_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")?;
    let mut path = PathBuf::from(home);
    path.push(".dmail");
    path.push("vault.json");
    Ok(path)
}

fn encrypt_vault(keys: &[KeyPair], pass: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(keys)?;
    let passphrase = SecretString::from(pass.to_owned());
    let recipient = age::scrypt::Recipient::new(passphrase);
    let encrypted = age::encrypt(&recipient, &bytes)?;
    Ok(encrypted)
}

fn decrypt_vault(encrypted: &[u8], pass: &str) -> anyhow::Result<Vec<KeyPair>> {
    let passphrase = SecretString::from(pass.to_owned());
    let identity = age::scrypt::Identity::new(passphrase);
    let decrypted = age::decrypt(&identity, &encrypted)?;
    let keys = serde_json::from_slice(&decrypted)?;
    Ok(keys)
}

fn save_vault(keys: &[KeyPair], passphrase: &str) -> anyhow::Result<bool> {
    let path = get_vault_path()?;
    let encrypted = encrypt_vault(keys, passphrase)?;
    fs::write(&path, encrypted)?;
    Ok(true)
}

fn ed25519_gen(id: String) -> KeyPair {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    KeyPair {
        id,
        sk: bs58::encode(signing_key.to_bytes()).into_string(),
        pk: bs58::encode(verifying_key.to_bytes()).into_string(),
        key_type: "Ed25519VerificationKey2020".to_string(),
    }
}

fn x25519_gen(id: String) -> KeyPair {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    KeyPair {
        id,
        sk: bs58::encode(secret.to_bytes()).into_string(),
        pk: bs58::encode(public.to_bytes()).into_string(),
        key_type: "X25519KeyAgreementKey2019".to_string(),
    }
}

fn open(pass: String) -> anyhow::Result<Vec<KeyPair>> {
    let path = get_vault_path()?;
    let bytes = fs::read(path)?;
    let keys = decrypt_vault(&bytes, &pass)?;
    Ok(keys)
}

fn init(pass: String) -> anyhow::Result<bool> {
    let path = get_vault_path()?;
    if path.exists() {
        return Err(anyhow!("Vault already initialized."));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let empty: Vec<KeyPair> = vec![];
    let encrypted = encrypt_vault(&empty, &pass)?;
    fs::write(path, encrypted)?;
    Ok(true)
}

fn unlock_or_init(s: &mut cursive::Cursive) {
    match get_vault_path() {
        Ok(path) if path.exists() => unlock_dialog(s),
        Ok(_) => init_dialog(s),
        Err(e) => {
            s.add_layer(
                Dialog::text(format!("Failed to determine vault path:\n{}", e))
                    .title("Error")
                    .button("Quit", |s| s.quit()),
            );
        }
    }
}

fn unlock_dialog(s: &mut cursive::Cursive) {
    s.add_layer(
        Dialog::new()
            .title("Unlock Vault")
            .content(
                LinearLayout::vertical()
                    .child(TextView::new("Enter password:"))
                    .child(
                        EditView::new()
                            .secret()
                            .with_name("password")
                            .fixed_width(30),
                    ),
            )
            .button("Unlock", |s| {
                let pass =
                    s.call_on_name("password", |v: &mut EditView| v.get_content().to_string());

                if let Some(pass) = pass {
                    match open(pass.clone()) {
                        Ok(keys) => {
                            s.pop_layer();
                            show_main_menu(s, pass, keys);
                        }
                        Err(e) => {
                            s.add_layer(
                                Dialog::text(format!("Failed to decrypt vault:\n{}", e))
                                    .title("Error")
                                    .button("OK", |s| {
                                        s.pop_layer();
                                    }),
                            );
                        }
                    }
                }
            })
            .button("Quit", |s| s.quit()),
    );
}

fn init_dialog(s: &mut cursive::Cursive) {
    s.add_layer(
        Dialog::new()
            .title("Initialize Vault")
            .content(
                LinearLayout::vertical()
                    .child(TextView::new("Create new password:"))
                    .child(
                        EditView::new()
                            .secret()
                            .with_name("password")
                            .fixed_width(30),
                    ),
            )
            .button("Initialize", |s| {
                let pass =
                    s.call_on_name("password", |v: &mut EditView| v.get_content().to_string());

                if let Some(pass) = pass {
                    match init(pass.clone()) {
                        Ok(_) => {
                            s.pop_layer();
                            show_main_menu(s, pass, Vec::new());
                        }
                        Err(e) => {
                            s.add_layer(
                                Dialog::text(format!("Failed to initialize vault:\n{}", e))
                                    .title("Error")
                                    .button("OK", |s| {
                                        s.pop_layer();
                                    }),
                            );
                        }
                    }
                }
            })
            .button("Quit", |s| s.quit()),
    );
}

fn show_main_menu(s: &mut cursive::Cursive, passphrase: String, keys: Vec<KeyPair>) {
    s.set_user_data((SecretString::new(passphrase.into()), keys));

    s.add_layer(
        Dialog::text("Select an action")
            .title("Vault Menu")
            .button("List Keys", |s| key_list(s))
            .button("Add Key", |s| add_dialog(s))
            .button("Edit Key", |s| edit_dialog(s))
            .button("Delete Key", |s| delete_dialog(s))
            .button("Generate DID Document", |s| did_gen_dialog(s))
            .button("Quit", |s| s.quit()),
    );
}

fn key_list(s: &mut cursive::Cursive) {
    if let Some((_, keys)) = s.user_data::<(SecretString, Vec<KeyPair>)>() {
        let mut select = SelectView::new();
        for k in keys.iter() {
            select.add_item(format!("{} [{}]", k.id, k.key_type), ());
        }

        s.add_layer(
            Dialog::around(select.scrollable().fixed_size((60, 20)))
                .title("Key List")
                .button("Back", |s| {
                    s.pop_layer();
                }),
        );
    }
}

fn add_dialog(s: &mut cursive::Cursive) {
    s.add_layer(
        Dialog::new()
            .title("Add Key")
            .content(
                LinearLayout::vertical()
                    .child(TextView::new("Key ID:"))
                    .child(EditView::new().with_name("key_id").fixed_width(30))
                    .child(TextView::new("Type:"))
                    .child(
                        SelectView::<&'static str>::new()
                            .item("Ed25519", "ed25519")
                            .item("X25519", "x25519")
                            .with_name("key_type")
                            .fixed_width(30),
                    ),
            )
            .button("Add", |s| {
                let id = s.call_on_name("key_id", |v: &mut EditView| v.get_content().to_string());

                let kind = s.call_on_name("key_type", |v: &mut SelectView<&'static str>| {
                    v.selection().map(|arc| *arc)
                });

                if let (Some(id), Some(Some(kind))) = (id, kind) {
                    if let Some((pass, keys)) = s.user_data::<(SecretString, Vec<KeyPair>)>() {
                        let new_key = match kind {
                            "ed25519" => ed25519_gen(id),
                            _ => x25519_gen(id),
                        };

                        keys.push(new_key);
                        let _ = save_vault(keys, pass.expose_secret_mut());
                    }
                }

                s.pop_layer();
            })
            .button("Cancel", |s| {
                s.pop_layer();
            }),
    );
}

fn edit_dialog(s: &mut cursive::Cursive) {
    if let Some((_, keys)) = s.user_data::<(SecretString, Vec<KeyPair>)>() {
        let mut select = SelectView::new();

        for (i, k) in keys.iter().enumerate() {
            select.add_item(format!("{} [{}]", k.id, k.key_type), i);
        }

        s.add_layer(
            Dialog::around(
                select
                    .on_submit(|s, index| {
                        let idx = *index;

                        let current_id = if let Some((_, keys)) =
                            s.user_data::<(SecretString, Vec<KeyPair>)>()
                        {
                            keys.get(idx).map(|k| k.id.clone())
                        } else {
                            None
                        };

                        if let Some(current_id) = current_id {
                            s.add_layer(
                                Dialog::new()
                                    .title("Edit Key ID")
                                    .content(
                                        LinearLayout::vertical()
                                            .child(TextView::new("New Key ID:"))
                                            .child(
                                                EditView::new()
                                                    .content(current_id)
                                                    .with_name("edit_key_id")
                                                    .fixed_width(30),
                                            ),
                                    )
                                    .button("Save", move |s| {
                                        let new_id = s
                                            .call_on_name("edit_key_id", |v: &mut EditView| {
                                                v.get_content().to_string()
                                            });

                                        if let Some(new_id) = new_id {
                                            if let Some((pass, keys)) =
                                                s.user_data::<(String, Vec<KeyPair>)>()
                                            {
                                                if idx < keys.len() {
                                                    keys[idx].id = new_id;
                                                    let _ = save_vault(keys, pass);
                                                }
                                            }
                                        }

                                        s.pop_layer();
                                        s.pop_layer();
                                    })
                                    .button("Cancel", |s| {
                                        s.pop_layer();
                                    }),
                            );
                        }
                    })
                    .scrollable()
                    .fixed_size((60, 20)),
            )
            .title("Edit Key")
            .button("Back", |s| {
                s.pop_layer();
            }),
        );
    }
}

fn delete_dialog(s: &mut cursive::Cursive) {
    if let Some((_, keys)) = s.user_data::<(SecretString, Vec<KeyPair>)>() {
        let mut select = SelectView::new();

        for (i, k) in keys.iter().enumerate() {
            select.add_item(format!("{} [{}]", k.id, k.key_type), i);
        }

        s.add_layer(
            Dialog::around(
                select
                    .on_submit(|s, index| {
                        if let Some((pass, keys)) = s.user_data::<(SecretString, Vec<KeyPair>)>() {
                            if *index < keys.len() {
                                keys.remove(*index);
                                let _ = save_vault(keys, pass.expose_secret_mut());
                            }
                        }
                        s.pop_layer();
                    })
                    .scrollable()
                    .fixed_size((60, 20)),
            )
            .title("Delete Key")
            .button("Back", |s| {
                s.pop_layer();
            }),
        );
    }
}

fn did_gen_dialog(s: &mut cursive::Cursive) {
    s.add_layer(
        Dialog::new()
            .title("Register Verification Methods from DID Document")
            .content(
                LinearLayout::vertical()
                    .child(TextView::new("DID:"))
                    .child(EditView::new().with_name("did_input").fixed_width(50)),
            )
            .button("Generate JSON", |s| {
                let did =
                    s.call_on_name("did_input", |v: &mut EditView| v.get_content().to_string());

                if let Some(did) = did {
                    if let Some((_, keys)) = s.user_data::<(SecretString, Vec<KeyPair>)>() {
                        let verification_methods: Vec<serde_json::Value> = keys
                            .iter()
                            .map(|k| {
                                serde_json::json!({
                                    "id": format!("{}#{}", did, k.id),
                                    "type": k.key_type,
                                    "controller": did,
                                    "publicKeyBase58": k.pk,
                                })
                            })
                            .collect();

                        let doc = serde_json::json!({
                            "verificationMethod": verification_methods
                        });

                        let pretty =
                            serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string());

                        s.add_layer(
                            Dialog::around(TextView::new(pretty).scrollable().fixed_size((80, 20)))
                                .title("Generated DID Document")
                                .button("Close", |s| {
                                    s.pop_layer();
                                }),
                        );
                    }
                }
            })
            .button("Cancel", |s| {
                s.pop_layer();
            }),
    );
}

fn main() {
    let mut siv = cursive::default();
    siv.set_theme(Theme::retro());
    unlock_or_init(&mut siv);
    siv.run();
}
