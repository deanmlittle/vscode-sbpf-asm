//! Zed extension for sBPF assembly.
//!
//! Highlighting, brackets and the outline come from the Tree-sitter grammar and
//! the queries in `languages/sbpf-asm/`. This file only tells Zed how to start
//! the language server: the one shipped with the VS Code extension
//! (`vscode-sbpf-asm/out/server.js`), which speaks standard LSP over stdio and
//! provides completion, hover docs, go-to-definition, references and
//! `sbpf build` diagnostics.

use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result};

/// Must match the key under `[language_servers]` in `extension.toml`, and the
/// key users put under `"lsp"` in their Zed settings.
const SERVER_ID: &str = "sbpf-asm-lsp";

/// Optional executable on PATH that starts the server over stdio, for people
/// who prefer a wrapper script to editing settings.
const WRAPPER_BINARY: &str = "sbpf-asm-language-server";

struct SbpfAsmExtension;

impl zed::Extension for SbpfAsmExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        if language_server_id.as_ref() != SERVER_ID {
            return Err(format!("unknown language server: {language_server_id}"));
        }

        // 1. Explicit settings:
        //    "lsp": { "sbpf-asm-lsp": { "binary": {
        //        "path": "node",                                   (optional)
        //        "arguments": ["/abs/path/out/server.js", "--stdio"] } } }
        //    If `path` is omitted, Zed's bundled Node.js is used, so the user
        //    does not need Node installed separately.
        let binary = LspSettings::for_worktree(SERVER_ID, worktree)?.binary;
        if let Some(binary) = binary {
            let arguments = binary.arguments.unwrap_or_default();
            if binary.path.is_some() || !arguments.is_empty() {
                let command = match binary.path {
                    Some(path) => path,
                    None => zed::node_binary_path()?,
                };
                let mut env = worktree.shell_env();
                env.extend(binary.env.unwrap_or_default());
                return Ok(zed::Command {
                    command,
                    args: arguments,
                    env,
                });
            }
        }

        // 2. A wrapper executable on PATH.
        if let Some(path) = worktree.which(WRAPPER_BINARY) {
            return Ok(zed::Command {
                command: path,
                args: vec!["--stdio".into()],
                env: worktree.shell_env(),
            });
        }

        Err(format!(
            "sBPF language server not configured. Build vscode-sbpf-asm \
             (npm ci && npm run compile), then add to your Zed settings:\n\
             \"lsp\": {{ \"{SERVER_ID}\": {{ \"binary\": {{ \"arguments\": \
             [\"/absolute/path/to/vscode-sbpf-asm/out/server.js\", \"--stdio\"] }} }} }}\n\
             or put an executable named `{WRAPPER_BINARY}` on your PATH."
        ))
    }
}

zed::register_extension!(SbpfAsmExtension);
