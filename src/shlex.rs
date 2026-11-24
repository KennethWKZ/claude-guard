//! Python 3.9's `shlex`, posix mode with `whitespace_split = True`, ported state for state from `shlex.read_token`.
//! Two settings are used: guard-bash's `shlex.shlex(command, posix=True, punctuation_chars=";&|()!<>")`
//! (`split`) and husky's `shlex.split(command)` (`split_plain`: no punctuation characters, no comments). guard-bash's verdicts depend on how this splits a command,
//! so it keeps Python's quirks: `#` starts a comment even inside a word, a run of punctuation characters is one
//! token (`;;`, `>&`, `|&`), and an empty quoted string is a token.

#[derive(Debug, PartialEq, Eq)]
pub enum LexError {
    NoClosingQuotation,
    NoEscapedCharacter,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Space,       // ' '
    Word,        // 'a'
    Punct,       // 'c'
    Quote(char), // '\'' or '"'
    Escape,      // '\\'
    End,         // None
}

const PUNCT: &str = ";&|()!<>";

#[derive(Clone, Copy)]
struct Config {
    punct: &'static str,
    comments: bool,
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

struct Lexer {
    cfg: Config,
    chars: Vec<char>,
    pos: usize,
    state: State,
    pushback: Vec<char>,
    token: String,
}

impl Lexer {
    fn is_punct(&self, c: char) -> bool {
        self.cfg.punct.contains(c)
    }

    fn read(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /// `instream.readline()`: the rest of the line, newline included.
    fn skip_line(&mut self) {
        while let Some(c) = self.read() {
            if c == '\n' {
                break;
            }
        }
    }

    fn read_token(&mut self) -> Result<Option<String>, LexError> {
        let mut quoted = false;
        let mut escaped_state = State::Space;
        loop {
            let next = match self.pushback.pop() {
                Some(c) => Some(c),
                None => self.read(),
            };
            match self.state {
                State::End => {
                    self.token.clear();
                    break;
                }
                State::Space => match next {
                    None => {
                        self.state = State::End;
                        break;
                    }
                    Some(c) if is_ws(c) => {
                        if !self.token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some('#') if self.cfg.comments => self.skip_line(),
                    Some('\\') => {
                        escaped_state = State::Word;
                        self.state = State::Escape;
                    }
                    Some(c) if self.is_punct(c) => {
                        self.token = c.to_string();
                        self.state = State::Punct;
                    }
                    Some(c) if c == '\'' || c == '"' => self.state = State::Quote(c),
                    Some(c) => {
                        self.token = c.to_string();
                        self.state = State::Word;
                    }
                },
                State::Quote(q) => {
                    quoted = true;
                    match next {
                        None => return Err(LexError::NoClosingQuotation),
                        Some(c) if c == q => self.state = State::Word,
                        Some('\\') if q == '"' => {
                            escaped_state = State::Quote(q);
                            self.state = State::Escape;
                        }
                        Some(c) => self.token.push(c),
                    }
                }
                State::Escape => match next {
                    None => return Err(LexError::NoEscapedCharacter),
                    Some(c) => {
                        // In posix shells, only the quote itself or the escape character may be escaped in quotes.
                        if let State::Quote(q) = escaped_state {
                            if c != '\\' && c != q {
                                self.token.push('\\');
                            }
                        }
                        self.token.push(c);
                        self.state = escaped_state;
                    }
                },
                State::Word | State::Punct => match next {
                    None => {
                        self.state = State::End;
                        break;
                    }
                    Some(c) if is_ws(c) => {
                        self.state = State::Space;
                        if !self.token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some('#') if self.cfg.comments => {
                        self.skip_line();
                        self.state = State::Space;
                        if !self.token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if self.state == State::Punct => {
                        if self.is_punct(c) {
                            self.token.push(c);
                        } else {
                            self.pushback.push(c);
                            self.state = State::Space;
                            break;
                        }
                    }
                    Some(c) if c == '\'' || c == '"' => self.state = State::Quote(c),
                    Some('\\') => {
                        escaped_state = State::Word;
                        self.state = State::Escape;
                    }
                    Some(c) if !self.is_punct(c) => self.token.push(c),
                    Some(c) => {
                        self.pushback.push(c);
                        self.state = State::Space;
                        if !self.token.is_empty() || quoted {
                            break;
                        }
                    }
                },
            }
        }
        let result = std::mem::take(&mut self.token);
        if !quoted && result.is_empty() {
            return Ok(None);
        }
        Ok(Some(result))
    }
}

/// `list(lex)`: every token, or the ValueError Python would raise.
pub fn split(command: &str) -> Result<Vec<String>, LexError> {
    run(
        command,
        Config {
            punct: PUNCT,
            comments: true,
        },
    )
}

/// `shlex.split(command)` (posix): no punctuation characters, `#` is an ordinary character.
pub fn split_plain(command: &str) -> Result<Vec<String>, LexError> {
    run(
        command,
        Config {
            punct: "",
            comments: false,
        },
    )
}

fn run(command: &str, cfg: Config) -> Result<Vec<String>, LexError> {
    let mut lx = Lexer {
        cfg,
        chars: command.chars().collect(),
        pos: 0,
        state: State::Space,
        pushback: Vec::new(),
        token: String::new(),
    };
    let mut out = Vec::new();
    while let Some(t) = lx.read_token()? {
        out.push(t);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(c: &str) -> Vec<String> {
        split(c).unwrap()
    }

    #[test]
    fn python_examples() {
        assert_eq!(s("a && b; c|d"), ["a", "&&", "b", ";", "c", "|", "d"]);
        assert_eq!(s("cat .env 2>&1"), ["cat", ".env", "2", ">&", "1"]);
        assert_eq!(s("echo 'a b' \"c\\\"d\""), ["echo", "a b", "c\"d"]);
        assert_eq!(s("echo \"a\\nb\""), ["echo", "a\\nb"]);
        assert_eq!(s("a#b c"), ["a"]);
        assert_eq!(s("x ''"), ["x", ""]);
        assert_eq!(s("(cd x);;y"), ["(", "cd", "x", ");;", "y"]);
        assert_eq!(
            split("cat \"unterminated"),
            Err(LexError::NoClosingQuotation)
        );
        assert_eq!(split("a\\"), Err(LexError::NoEscapedCharacter));
        assert_eq!(split_plain("cd x;y #z").unwrap(), ["cd", "x;y", "#z"]);
        assert_eq!(
            split_plain("git -C 'a b' worktree add ../wt").unwrap(),
            ["git", "-C", "a b", "worktree", "add", "../wt"]
        );
    }
}
