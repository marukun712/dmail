use age::secrecy::SecretString;
use color_eyre::Result;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ratatui::{
    DefaultTerminal,
    buffer::Buffer,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize, palette::tailwind},
    symbols,
    text::Line,
    widgets::{Block, Padding, Paragraph, Tabs, Widget},
};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use strum::{Display, EnumIter, FromRepr, IntoEnumIterator};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::default().run(terminal);
    ratatui::restore();
    app_result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPair {
    id: String,
    pk: String,
    sk: String,
    #[serde(rename = "type")]
    key_type: String,
}

#[derive(Default, Clone, PartialEq)]
enum VaultState {
    #[default]
    Locked,
    Unlocking,
    Unlocked,
    UnlockError(String),
}

#[derive(Default, Clone, PartialEq)]
enum KeyManagementMode {
    #[default]
    ViewList,
    AddingKey,
    SelectingKeyType,
}

#[derive(Default)]
enum InputMode {
    #[default]
    Normal,
    Editing,
}

#[derive(Default)]
struct App {
    state: AppState,
    selected_tab: SelectedTab,
    km_mode: KeyManagementMode,
    vault_state: VaultState,
    vault_keys: Vec<KeyPair>,
    input: String,
    password: String,
    character_index: usize,
    input_mode: InputMode,
    status_message: String,
    selected_key_index: usize,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum AppState {
    #[default]
    Running,
    Quitting,
}

#[derive(Default, Clone, Copy, Display, FromRepr, EnumIter, PartialEq)]
enum SelectedTab {
    #[default]
    #[strum(to_string = "Tab 1")]
    Tab1,
    #[strum(to_string = "Tab 2")]
    Tab2,
    #[strum(to_string = "Tab 3")]
    Tab3,
    #[strum(to_string = "Tab 4")]
    Tab4,
}

fn get_vault_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME");
    let parsed_home = match home {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    let mut path = PathBuf::from(parsed_home);
    path.push(".dmail");
    path.push("vault.json");
    Ok(path)
}

fn encrypt_vault(keys: &[KeyPair], pass: &str) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(keys);
    let parsed_bytes = match bytes {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    let passphrase = SecretString::from(pass.to_owned());
    let recipient = age::scrypt::Recipient::new(passphrase);
    let encrypted = age::encrypt(&recipient, &parsed_bytes);
    let parsed_encrypted = match encrypted {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    Ok(parsed_encrypted)
}

fn decrypt_vault(encrypted: &[u8], pass: &str) -> Result<Vec<KeyPair>, String> {
    let passphrase = SecretString::from(pass.to_owned());
    let identity = age::scrypt::Identity::new(passphrase);
    let decrypted = age::decrypt(&identity, &encrypted);
    let parsed_decrypted = match decrypted {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    let keys = serde_json::from_slice(&parsed_decrypted);
    let parsed_keys = match keys {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    Ok(parsed_keys)
}

fn load_or_init_vault(passphrase: &str) -> Result<Vec<KeyPair>, String> {
    let path = match get_vault_path() {
        Ok(p) => p,
        Err(e) => return Err(e),
    };
    if let Some(parent) = path.parent() {
        match fs::create_dir_all(parent) {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    if !path.exists() {
        let empty_vault: Vec<KeyPair> = Vec::new();
        let encrypted = match encrypt_vault(&empty_vault, passphrase) {
            Ok(data) => data,
            Err(e) => return Err(e),
        };
        match fs::write(&path, encrypted) {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
        return Ok(empty_vault);
    }
    let encrypted = match fs::read(&path) {
        Ok(data) => data,
        Err(e) => return Err(e.to_string()),
    };
    match decrypt_vault(&encrypted, passphrase) {
        Ok(vault) => Ok(vault),
        Err(e) => Err(e),
    }
}

fn save_vault(keys: &[KeyPair], passphrase: &str) -> Result<bool, String> {
    let path = match get_vault_path() {
        Ok(p) => p,
        Err(e) => return Err(e),
    };
    let encrypted = match encrypt_vault(keys, passphrase) {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    match fs::write(&path, encrypted) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
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

impl App {
    fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while self.state == AppState::Running {
            terminal.draw(|frame| frame.render_widget(&self, frame.area()))?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.character_index.saturating_sub(1);
        self.character_index = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.character_index.saturating_add(1);
        self.character_index = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index();
        self.input.insert(index, new_char);
        self.move_cursor_right();
    }

    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or(self.input.len())
    }

    fn delete_char(&mut self) {
        let is_not_cursor_leftmost = self.character_index != 0;
        if is_not_cursor_leftmost {
            let current_index = self.character_index;
            let from_left_to_current_index = current_index - 1;

            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            let after_char_to_delete = self.input.chars().skip(current_index);

            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.chars().count())
    }

    fn reset_cursor(&mut self) {
        self.character_index = 0;
    }

    fn submit_message(&mut self) {
        match self.selected_tab {
            SelectedTab::Tab1 => {
                if self.vault_state == VaultState::Locked
                    || matches!(self.vault_state, VaultState::UnlockError(_))
                {
                    let passphrase = self.input.clone();
                    self.unlock_vault(&passphrase);
                    self.input.clear();
                    self.reset_cursor();
                }
            }
            _ => {
                self.password = self.input.clone();
                self.input.clear();
                self.reset_cursor();
            }
        }
    }

    fn unlock_vault(&mut self, passphrase: &str) {
        self.vault_state = VaultState::Unlocking;
        match load_or_init_vault(passphrase) {
            Ok(keys) => {
                self.vault_keys = keys;
                self.vault_state = VaultState::Unlocked;
                self.status_message = format!("Unlocked! ({} keys)", self.vault_keys.len());
            }
            Err(e) => {
                let error_msg = if e.to_string().contains("decryption failed")
                    || e.to_string().contains("invalid")
                {
                    "Invalid passphrase".to_string()
                } else {
                    format!("Error: {}", e)
                };
                self.vault_state = VaultState::UnlockError(error_msg.clone());
                self.status_message = error_msg;
            }
        }
    }

    fn handle_events(&mut self) -> std::io::Result<()> {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                if self.selected_tab == SelectedTab::Tab1
                    && self.vault_state == VaultState::Unlocked
                {
                    match &self.km_mode {
                        KeyManagementMode::ViewList => match key.code {
                            KeyCode::Char('n') => {
                                self.km_mode = KeyManagementMode::AddingKey;
                                self.input_mode = InputMode::Editing;
                                return Ok(());
                            }
                            KeyCode::Char('d') if !self.vault_keys.is_empty() => {
                                self.delete_selected_key();
                                return Ok(());
                            }
                            KeyCode::Up => {
                                if self.selected_key_index > 0 {
                                    self.selected_key_index -= 1;
                                }
                                return Ok(());
                            }
                            KeyCode::Down => {
                                if !self.vault_keys.is_empty()
                                    && self.selected_key_index < self.vault_keys.len() - 1
                                {
                                    self.selected_key_index += 1;
                                }
                                return Ok(());
                            }
                            _ => {}
                        },
                        KeyManagementMode::AddingKey => match key.code {
                            KeyCode::Enter if !self.input.is_empty() => {
                                self.km_mode = KeyManagementMode::SelectingKeyType;
                                self.input_mode = InputMode::Normal;
                                return Ok(());
                            }
                            KeyCode::Esc => {
                                self.km_mode = KeyManagementMode::ViewList;
                                self.input.clear();
                                self.reset_cursor();
                                self.input_mode = InputMode::Normal;
                                return Ok(());
                            }
                            KeyCode::Char(to_insert) => {
                                self.enter_char(to_insert);
                                return Ok(());
                            }
                            KeyCode::Backspace => {
                                self.delete_char();
                                return Ok(());
                            }
                            _ => return Ok(()),
                        },
                        KeyManagementMode::SelectingKeyType => match key.code {
                            KeyCode::Char('1') => {
                                self.add_ed25519_key();
                                return Ok(());
                            }
                            KeyCode::Char('2') => {
                                self.add_x25519_key();
                                return Ok(());
                            }
                            KeyCode::Esc => {
                                self.km_mode = KeyManagementMode::ViewList;
                                self.input.clear();
                                self.reset_cursor();
                                return Ok(());
                            }
                            _ => return Ok(()),
                        },
                    }
                }

                match self.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('l') | KeyCode::Right => self.next_tab(),
                        KeyCode::Char('h') | KeyCode::Left => self.previous_tab(),
                        KeyCode::Char('q') | KeyCode::Esc => self.quit(),
                        KeyCode::Char('e') => {
                            self.input_mode = InputMode::Editing;
                        }
                        _ => {}
                    },
                    InputMode::Editing => match key.code {
                        KeyCode::Enter => self.submit_message(),
                        KeyCode::Char(to_insert) => self.enter_char(to_insert),
                        KeyCode::Backspace => self.delete_char(),
                        KeyCode::Left => self.move_cursor_left(),
                        KeyCode::Right => self.move_cursor_right(),
                        KeyCode::Esc => self.input_mode = InputMode::Normal,
                        _ => {}
                    },
                }
            }
        }
        Ok(())
    }

    fn add_ed25519_key(&mut self) {
        let id = self.input.clone();
        let keypair = ed25519_gen(id);
        self.vault_keys.push(keypair);
        if let Err(e) = save_vault(&self.vault_keys, &self.password) {
            self.status_message = format!("Failed to save: {}", e);
        } else {
            self.status_message = "Key added successfully".to_string();
        }
        self.input.clear();
        self.reset_cursor();
        self.km_mode = KeyManagementMode::ViewList;
    }

    fn add_x25519_key(&mut self) {
        let id = self.input.clone();
        let keypair = x25519_gen(id);
        self.vault_keys.push(keypair);
        if let Err(e) = save_vault(&self.vault_keys, &self.password) {
            self.status_message = format!("Failed to save: {}", e);
        } else {
            self.status_message = "Key added successfully".to_string();
        }
        self.input.clear();
        self.reset_cursor();
        self.km_mode = KeyManagementMode::ViewList;
    }

    fn delete_selected_key(&mut self) {
        if self.selected_key_index < self.vault_keys.len() {
            self.vault_keys.remove(self.selected_key_index);
            if let Err(e) = save_vault(&self.vault_keys, &self.password) {
                self.status_message = format!("Failed to save: {}", e);
            } else {
                self.status_message = "Key deleted successfully".to_string();
            }
            if !self.vault_keys.is_empty() && self.selected_key_index >= self.vault_keys.len() {
                self.selected_key_index = self.vault_keys.len() - 1;
            } else if self.vault_keys.is_empty() {
                self.selected_key_index = 0;
            }
        }
    }

    fn next_tab(&mut self) {
        let current_index = self.selected_tab as usize;
        let next_index = current_index.saturating_add(1);
        self.selected_tab = SelectedTab::from_repr(next_index).unwrap_or(self.selected_tab);
    }

    fn previous_tab(&mut self) {
        let current_index = self.selected_tab as usize;
        let previous_index = current_index.saturating_sub(1);
        self.selected_tab = SelectedTab::from_repr(previous_index).unwrap_or(self.selected_tab);
    }

    fn quit(&mut self) {
        self.state = AppState::Quitting;
    }

    fn render_tabs(&self, area: Rect, buf: &mut Buffer) {
        let titles = SelectedTab::iter().map(|tab| self.tab_title(tab));
        let highlight_style = (Color::default(), self.palette(self.selected_tab).c700);
        let selected_tab_index = self.selected_tab as usize;

        Tabs::new(titles)
            .highlight_style(highlight_style)
            .select(selected_tab_index)
            .padding("", "")
            .divider(" ")
            .render(area, buf);
    }

    fn render_selected_tab(&self, area: Rect, buf: &mut Buffer) {
        match self.selected_tab {
            SelectedTab::Tab1 => self.render_km(area, buf),
            SelectedTab::Tab2 => {
                Paragraph::new("Welcome to the Ratatui tabs example!")
                    .block(self.tab_block(self.selected_tab))
                    .render(area, buf);
            }
            SelectedTab::Tab3 => {
                Paragraph::new("Look! I'm different than others!")
                    .block(self.tab_block(self.selected_tab))
                    .render(area, buf);
            }
            SelectedTab::Tab4 => {
                Paragraph::new(
                    "I know, these are some basic changes. But I think you got the main idea.",
                )
                .block(self.tab_block(self.selected_tab))
                .render(area, buf);
            }
        }
    }

    fn render_km(&self, area: Rect, buf: &mut Buffer) {
        match &self.vault_state {
            VaultState::Locked => {
                let title = "🔒 Vault Locked";
                let input_display = if matches!(self.input_mode, InputMode::Editing) {
                    "*".repeat(self.input.len())
                } else {
                    String::new()
                };
                Paragraph::new(format!(
                    "Enter passphrase to unlock vault\n\n{}",
                    input_display
                ))
                .style(match self.input_mode {
                    InputMode::Normal => Style::default(),
                    InputMode::Editing => Style::default().fg(Color::Yellow),
                })
                .block(
                    Block::bordered()
                        .title(title)
                        .border_set(symbols::border::ROUNDED)
                        .padding(Padding::horizontal(1))
                        .border_style(self.palette(self.selected_tab).c700),
                )
                .render(area, buf);
            }
            VaultState::Unlocking => {
                Paragraph::new("⏳ Unlocking vault...")
                    .centered()
                    .style(Style::default().fg(Color::Cyan))
                    .block(
                        Block::bordered()
                            .title("Key Management")
                            .border_set(symbols::border::ROUNDED)
                            .border_style(self.palette(self.selected_tab).c700),
                    )
                    .render(area, buf);
            }
            VaultState::Unlocked => match &self.km_mode {
                KeyManagementMode::ViewList => self.render_key_list(area, buf),
                KeyManagementMode::AddingKey => self.render_add_key_form(area, buf),
                KeyManagementMode::SelectingKeyType => self.render_key_type_selector(area, buf),
            },
            VaultState::UnlockError(err) => {
                let text = format!("❌ {}\n\nPress 'e' to try again", err);
                Paragraph::new(text)
                    .centered()
                    .style(Style::default().fg(Color::Red))
                    .block(
                        Block::bordered()
                            .title("Error")
                            .border_set(symbols::border::ROUNDED)
                            .border_style(Color::Red),
                    )
                    .render(area, buf);
            }
        }
    }

    fn render_key_list(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::bordered()
            .title("🔑 Key Management")
            .title_bottom("'n' New | '↑↓' Select | 'd' Delete | 'q' Quit")
            .border_style(self.palette(self.selected_tab).c700)
            .border_set(symbols::border::ROUNDED)
            .padding(Padding::horizontal(1));

        let inner_area = block.inner(area);
        block.render(area, buf);

        if self.vault_keys.is_empty() {
            Paragraph::new("No keys yet. Press 'n' to add a new key.")
                .centered()
                .style(Style::default().fg(Color::Gray))
                .render(inner_area, buf);
        } else {
            for (idx, key) in self.vault_keys.iter().enumerate() {
                if idx >= inner_area.height as usize {
                    break;
                }

                let is_selected = idx == self.selected_key_index;
                let style = if is_selected {
                    Style::default()
                        .bg(self.palette(self.selected_tab).c700)
                        .fg(Color::White)
                } else {
                    Style::default()
                };

                let icon = match key.key_type.as_str() {
                    "Ed25519VerificationKey2020" => "✍️ ",
                    "X25519KeyAgreementKey2019" => "🔐",
                    _ => "🔑",
                };

                let pk_len = key.pk.len();
                let pk_display = if pk_len > 16 {
                    format!("{}...{}", &key.pk[..8], &key.pk[pk_len - 8..])
                } else {
                    key.pk.clone()
                };

                let line = format!(
                    "{} {} | {} | pk: {}",
                    icon, key.id, &key.key_type, pk_display
                );

                let line_area = Rect {
                    x: inner_area.x,
                    y: inner_area.y + idx as u16,
                    width: inner_area.width,
                    height: 1,
                };

                Paragraph::new(line).style(style).render(line_area, buf);
            }
        }
    }

    fn render_add_key_form(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::bordered()
            .title("🆕 Add New Key")
            .title_bottom("Enter ID, then press Enter | ESC to cancel")
            .border_style(Color::Green)
            .border_set(symbols::border::ROUNDED)
            .padding(Padding::horizontal(1));

        let inner_area = block.inner(area);
        block.render(area, buf);

        let input_display = if matches!(self.input_mode, InputMode::Editing) {
            &self.input
        } else {
            ""
        };

        Paragraph::new(format!("Key ID: {}", input_display))
            .style(Style::default().fg(Color::Yellow))
            .render(inner_area, buf);
    }

    fn render_key_type_selector(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::bordered()
            .title("🔐 Select Key Type")
            .title_bottom("Press 1 or 2 | ESC to cancel")
            .border_style(Color::Cyan)
            .border_set(symbols::border::ROUNDED)
            .padding(Padding::horizontal(1));

        let inner_area = block.inner(area);
        block.render(area, buf);

        let text = "1:Ed25519 (Signature)\n2:X25519 (Encryption)";
        Paragraph::new(text)
            .centered()
            .style(Style::default())
            .render(inner_area, buf);
    }

    fn tab_title(&self, tab: SelectedTab) -> Line<'static> {
        let (icon, name) = match tab {
            SelectedTab::Tab1 => ("🔑", "Keys"),
            SelectedTab::Tab2 => ("📧", "Mail"),
            SelectedTab::Tab3 => ("⚙️ ", "Settings"),
            SelectedTab::Tab4 => ("ℹ️ ", "Info"),
        };

        format!(" {} {} ", icon, name)
            .fg(tailwind::SLATE.c200)
            .bg(self.palette(tab).c900)
            .into()
    }

    fn tab_block(&self, tab: SelectedTab) -> Block<'static> {
        Block::bordered()
            .border_set(symbols::border::ROUNDED)
            .padding(Padding::horizontal(1))
            .border_style(self.palette(tab).c700)
    }

    const fn palette(&self, tab: SelectedTab) -> tailwind::Palette {
        match tab {
            SelectedTab::Tab1 => tailwind::BLUE,
            SelectedTab::Tab2 => tailwind::EMERALD,
            SelectedTab::Tab3 => tailwind::INDIGO,
            SelectedTab::Tab4 => tailwind::RED,
        }
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        use Constraint::{Length, Min};

        let vertical = Layout::vertical([Length(1), Min(0), Length(1)]);
        let [header_area, inner_area, footer_area] = vertical.areas(area);

        let horizontal = Layout::horizontal([Min(0), Length(20)]);
        let [tabs_area, title_area] = horizontal.areas(header_area);

        "🔑 dmail".bold().render(title_area, buf);
        self.render_tabs(tabs_area, buf);
        self.render_selected_tab(inner_area, buf);
        Line::raw("◄► Tabs | e Edit | q Quit")
            .centered()
            .style(Style::default().fg(tailwind::SLATE.c400))
            .render(footer_area, buf);
    }
}
