# sBPF Assembly for Zed

Zed support for sBPF (Solana BPF) assembly `.s` / `.sbpf` files. It lives in the same repository as the VS Code extension and reuses its language server.

| Feature | Source |
|---|---|
| Syntax highlighting | Tree-sitter grammar in `../tree-sitter-sbpf` + `languages/sbpf-asm/highlights.scm` |
| Outline panel / symbol search (labels, `.equ`, `.macro`) | `languages/sbpf-asm/outline.scm` |
| Bracket matching, comment toggling (`cmd-/`) | `languages/sbpf-asm/config.toml`, `brackets.scm` |
| Completion, hover docs for every opcode and syscall, go-to-definition, references, `sbpf build` diagnostics | The VS Code extension's language server (`../src/server.ts` → `../out/server.js`), started by `src/lib.rs` |

The VS Code step debugger and end-of-line hints are VS Code-only and are not included.

## Install (from a clone of this repository)

1. **Prerequisites**
   - Rust installed via **rustup** (Zed compiles the extension with it).
   - The language server built once, from the repository root:
     ```sh
     npm ci && npm run compile        # produces out/server.js
     ```
   - `sbpf` on your PATH, for build diagnostics (`cargo install sbpf`).

2. **Install the dev extension.** In Zed, open the command palette (`cmd-shift-p`), run **`zed: install dev extension`**, and select this `zed/` folder.

3. **Point Zed at the language server** (settings, `cmd-,`):
   ```json
   {
     "lsp": {
       "sbpf-asm-lsp": {
         "binary": {
           "arguments": ["/absolute/path/to/vscode-sbpf-asm/out/server.js", "--stdio"]
         }
       }
     }
   }
   ```
   Leaving out `"path"` makes Zed run the script with its own bundled Node.js. Add `"path": "/path/to/node"` to use a different Node.

4. **Check it works.** Open any `.s` file. The language selector in the status bar should say **sBPF Assembly**. Hover an opcode to see its documentation, `cmd-click` a label to jump to it, and press `cmd-shift-o` to list the labels.

If hovers don't appear, run **`dev: open language server logs`** and check the `sbpf-asm-lsp` entry.

## Testing grammar changes before they are pushed

`extension.toml` loads the grammar from GitHub at `rev`, so Zed can only see grammar commits that have been pushed. To test a local, unpushed grammar commit, temporarily change the grammar's `repository` to the local clone. **Don't commit this change.**

```toml
[grammars.sbpf]
repository = "file:///absolute/path/to/vscode-sbpf-asm"
rev = "<local commit hash>"
path = "tree-sitter-sbpf"
```

## Changing things

- **`src/lib.rs` or the query files:** command palette → `zed: rebuild dev extension`.
- **`../tree-sitter-sbpf/grammar.js`:**
  1. In `tree-sitter-sbpf/`, run `tree-sitter generate`.
  2. Check it with `tree-sitter parse <file.s>`.
  3. Commit (including the regenerated `src/`).
  4. Set `rev` above to the new commit hash and rebuild the dev extension.

  Test the highlight queries with `tree-sitter query ../zed/languages/sbpf-asm/highlights.scm <file.s>`.

## Notes

- `.s` is a generic assembly extension. If another assembly extension is also installed, choose the language from the status bar per file, or pin it with `"file_types": { "sBPF Assembly": ["*.s"] }`.
- Publishing to the Zed extension registry is a separate PR to [zed-industries/extensions](https://github.com/zed-industries/extensions). The registry supports extensions in a subdirectory, so this one would be registered with `path = "zed"`.
