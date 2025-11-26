use std::io::{self, Write};

use console::Term;

/// Read password/code input with asterisk masking
///
/// Shows an asterisk (*) for each character typed, supports backspace,
/// and handles Ctrl+C/Escape for cancellation.
pub fn read_masked(prompt: &str) -> io::Result<String> {
    let term = Term::stderr();
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    loop {
        let key = term.read_key()?;
        match key {
            console::Key::Enter => {
                println!();
                break;
            }
            console::Key::Char(c) => {
                input.push(c);
                print!("*");
                io::stdout().flush()?;
            }
            console::Key::Backspace => {
                if input.pop().is_some() {
                    print!("\x08 \x08");
                    io::stdout().flush()?;
                }
            }
            console::Key::Escape | console::Key::CtrlC => {
                println!();
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            _ => {}
        }
    }
    Ok(input)
}
