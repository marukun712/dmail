use age::secrecy::SecretString;
use color_eyre::Result;
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
use std::{
    fs,
    path::{Path, PathBuf},
};
use strum::{Display, EnumIter, FromRepr, IntoEnumIterator};

fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::default().run(terminal);
    ratatui::restore();
    app_result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPair {
    pk: String,
    sk: String,
}

#[derive(Default, Clone, PartialEq)]
enum VaultState {
    #[default]
    Locked,
    Unlocking,
    Unlocked,
    UnlockError(String),
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
    password: String,
    input: String,
    character_index: usize,
    input_mode: InputMode,
    vault_state: VaultState,
    vault_keys: Vec<KeyPair>,
    status_message: String,
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

fn load_vault(passphrase: &str) -> Result<Vec<KeyPair>, String> {
    let path = get_vault_path();
    let parsed_path = match path {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    let parsed_str = match parsed_path.to_str() {
        Some(v) => v,
        None => return Err("Invalid Path".to_string()),
    };
    if !Path::new(parsed_str).exists() {
        return Err("Vault file does not exist".to_string());
    }
    let encrypted = fs::read(&parsed_str);
    let parsed_encrypted = match encrypted {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    decrypt_vault(&parsed_encrypted, passphrase)
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
        match load_vault(passphrase) {
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
                let title = "Enter passphrase to unlock vault";
                let input_display = if matches!(self.input_mode, InputMode::Editing) {
                    "*".repeat(self.input.len())
                } else {
                    String::new()
                };
                Paragraph::new(format!("{}\n\n{}", title, input_display))
                    .style(match self.input_mode {
                        InputMode::Normal => Style::default(),
                        InputMode::Editing => Style::default().fg(Color::Yellow),
                    })
                    .block(
                        Block::bordered()
                            .title("Key Management")
                            .border_set(symbols::border::PROPORTIONAL_TALL)
                            .padding(Padding::horizontal(1))
                            .border_style(self.palette(self.selected_tab).c700),
                    )
                    .render(area, buf);
            }
            VaultState::Unlocking => {
                Paragraph::new("Unlocking vault...")
                    .block(self.tab_block(self.selected_tab).title("Key Management"))
                    .render(area, buf);
            }
            VaultState::Unlocked => {
                Paragraph::new(&*self.status_message)
                    .style(Style::default().fg(Color::Green))
                    .block(self.tab_block(self.selected_tab).title("Key Management"))
                    .render(area, buf);
            }
            VaultState::UnlockError(err) => {
                let text = format!("{}\n\nPress 'e' to try again", err);
                Paragraph::new(text)
                    .style(Style::default().fg(Color::Red))
                    .block(self.tab_block(self.selected_tab).title("Key Management"))
                    .render(area, buf);
            }
        }
    }

    fn tab_title(&self, tab: SelectedTab) -> Line<'static> {
        format!("  {tab}  ")
            .fg(tailwind::SLATE.c200)
            .bg(self.palette(tab).c900)
            .into()
    }

    fn tab_block(&self, tab: SelectedTab) -> Block<'static> {
        Block::bordered()
            .border_set(symbols::border::PROPORTIONAL_TALL)
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

        "Ratatui Tabs Example".bold().render(title_area, buf);
        self.render_tabs(tabs_area, buf);
        self.render_selected_tab(inner_area, buf);
        Line::raw("◄ ► to change tab | Press q to quit")
            .centered()
            .render(footer_area, buf);
    }
}
