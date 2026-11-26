//! Python 3.9's `shlex`, posix mode with `whitespace_split = True`, ported state for state from `shlex.read_token`.
//! Two settings are used: guard-bash's `shlex.shlex(command, posix=True, punctuation_chars=";&|()!<>")`
//! (`split_python`) and husky's `shlex.split(command)` (`split_plain`: no punctuation characters, no comments). guard-bash's verdicts depend on how this splits a command,
//! so it keeps Python's quirks: `#` starts a comment even inside a word, a run of punctuation characters is one
//! token (`;;`, `>&`, `|&`), and an empty quoted string is a token.
//!
//! `split_lines` is guard-bash's setting plus what Python's shlex never did: an unquoted newline is a `"\n"` token
//! (a command separator, as in a shell), a comment ends at its newline without swallowing it, and a backslash before
//! a newline is a line continuation (both go, as in a shell, also inside double quotes).

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
struct Config<'a> {
    punct: &'a str,
    /// `lex.whitespace` (Python's default is " \t\r\n").
    whitespace: &'a str,
    comments: bool,
    /// `split_lines`: newlines outside quotes are `"\n"` tokens; backslash-newline is removed.
    newline_tokens: bool,
}

const WHITESPACE: &str = " \t\r\n";

struct Lexer<'a> {
    cfg: Config<'a>,
    chars: Vec<char>,
    pos: usize,
    state: State,
    pushback: Vec<char>,
    token: String,
}

impl Lexer<'_> {
    fn is_punct(&self, c: char) -> bool {
        self.cfg.punct.contains(c)
    }

    fn is_ws(&self, c: char) -> bool {
        self.cfg.whitespace.contains(c)
    }

    fn read(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /// `instream.readline()`: the rest of the line, newline included. With `newline_tokens` the newline is put back,
    /// so it still separates commands.
    fn skip_line(&mut self) {
        while let Some(c) = self.read() {
            if c == '\n' {
                if self.cfg.newline_tokens {
                    self.pushback.push('\n');
                }
                break;
            }
        }
    }

    fn is_newline_token(&self, c: char) -> bool {
        self.cfg.newline_tokens && c == '\n'
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
                    Some(c) if self.is_newline_token(c) => {
                        if !self.token.is_empty() || quoted {
                            self.pushback.push(c);
                            break;
                        }
                        self.token = "\n".to_string();
                        break;
                    }
                    Some(c) if self.is_ws(c) => {
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
                    Some('\n') if self.cfg.newline_tokens => self.state = escaped_state,
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
                    Some(c) if self.is_newline_token(c) => {
                        self.pushback.push(c);
                        self.state = State::Space;
                        if !self.token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if self.is_ws(c) => {
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

/// `list(lex)`: every token, or the ValueError Python would raise: guard-bash's own reading, where a newline is a
/// space. The guard's first pass uses it so its verdicts match the Python guard's; `split_lines` is the second.
pub fn split_python(command: &str) -> Result<Vec<String>, LexError> {
    run(
        command,
        Config {
            punct: PUNCT,
            whitespace: WHITESPACE,
            comments: true,
            newline_tokens: false,
        },
    )
}

/// `split`, with unquoted newlines as `"\n"` tokens and backslash-newline removed (see the module comment).
pub fn split_lines(command: &str) -> Result<Vec<String>, LexError> {
    run(
        command,
        Config {
            punct: PUNCT,
            whitespace: " \t\r",
            comments: true,
            newline_tokens: true,
        },
    )
}

/// `shlex.split(command)` (posix): no punctuation characters, `#` is an ordinary character.
pub fn split_plain(command: &str) -> Result<Vec<String>, LexError> {
    run(
        command,
        Config {
            punct: "",
            whitespace: WHITESPACE,
            comments: false,
            newline_tokens: false,
        },
    )
}

/// `shlex.shlex(command, posix=True, punctuation_chars=punct)` with `whitespace_split = True`, `commenters = ""`
/// and `lex.whitespace = whitespace`: the settings the repo guards use (`punct` "();<>|&" is Python's
/// `punctuation_chars=True`).
pub fn split_with(command: &str, punct: &str, whitespace: &str) -> Result<Vec<String>, LexError> {
    run(
        command,
        Config {
            punct,
            whitespace,
            comments: false,
            newline_tokens: false,
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
        split_python(c).unwrap()
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
            split_python("cat \"unterminated"),
            Err(LexError::NoClosingQuotation)
        );
        assert_eq!(split_python("a\\"), Err(LexError::NoEscapedCharacter));
        assert_eq!(split_plain("cd x;y #z").unwrap(), ["cd", "x;y", "#z"]);
        assert_eq!(
            split_plain("git -C 'a b' worktree add ../wt").unwrap(),
            ["git", "-C", "a b", "worktree", "add", "../wt"]
        );
    }

    #[test]
    fn split_lines_newlines() {
        let l = |c: &str| split_lines(c).unwrap();
        assert_eq!(l("cd x\nsudo ls"), ["cd", "x", "\n", "sudo", "ls"]);
        assert_eq!(l("a\n\nb"), ["a", "\n", "\n", "b"]);
        assert_eq!(l("a;\nb"), ["a", ";", "\n", "b"]);
        assert_eq!(l("a |\n b"), ["a", "|", "\n", "b"]);
        assert_eq!(l("a # note\nb"), ["a", "\n", "b"]);
        assert_eq!(l("a#note\nb"), ["a", "\n", "b"]);
        assert_eq!(l("echo 'a\nb'"), ["echo", "a\nb"]);
        assert_eq!(l("echo \"a\nb\""), ["echo", "a\nb"]);
        assert_eq!(l("cd x \\\n && ls"), ["cd", "x", "&&", "ls"]);
        assert_eq!(l("ec\\\nho hi"), ["echo", "hi"]);
        assert_eq!(l("echo \"a\\\nb\""), ["echo", "ab"]);
        assert_eq!(l("echo 'a\\\nb'"), ["echo", "a\\\nb"]);
        assert_eq!(l("\n"), ["\n"]);
        // Python's split keeps reading a newline as a space.
        assert_eq!(s("cd x\nsudo ls"), ["cd", "x", "sudo", "ls"]);
    }
}
