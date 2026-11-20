/**
 * Tree-sitter grammar for sBPF assembly (the dialect accepted by the `sbpf`
 * assembler, see sbpf/crates/assembler/src/sbpf.pest).
 *
 * The grammar is deliberately lenient: each line is an optional label followed
 * by an optional directive or instruction, and operands are a flat list of
 * tokens. That keeps it robust for the default dialect, the LLVM dialect
 * (`r1 += 5`, `if r1 == 0 goto L`), and preprocessor macros (`\arg`, `\@`).
 * Precise meaning (registers, opcodes, syscalls) is assigned in the highlight
 * queries, not here.
 */
module.exports = grammar({
  name: 'sbpf',

  // Newlines are significant (they end statements), so they are not extras.
  extras: ($) => [/[ \t\r\f]/, $.comment],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) =>
      seq(repeat(seq(optional($._statement), $._newline)), optional($._statement)),

    _newline: (_) => /\n/,

    _statement: ($) =>
      choice(
        seq($.label, optional(choice($.directive, $.instruction))),
        $.directive,
        $.instruction,
      ),

    // `entrypoint:`, `1:`, `\name\()_end:`. Lexed as ONE token (name + colon)
    // so the longest match always wins over an identifier and there is no
    // ambiguity with an instruction that starts with the same word.
    label: (_) =>
      token(
        seq(
          choice(
            /[0-9]+/,
            /([A-Za-z_][A-Za-z0-9_]*|\\[A-Za-z_][A-Za-z0-9_]*|\\@|\\\(\))+/,
          ),
          ':',
        ),
      ),

    // `.equ NAME, 0x10`, `.globl entrypoint`, `.ascii "hi"`, `.macro M a, b=0`
    directive: ($) => seq(field('name', $.directive_name), repeat($._operand)),
    directive_name: (_) => /\.[A-Za-z_][A-Za-z0-9_]*/,

    // `ldxdw r2, [r6 + 8]`, `call sol_log_`, `r1 += 5`, `if r1 == 0 goto L`,
    // and macro invocations such as `CHECK_SIGNER 0x9`.
    instruction: ($) =>
      choice(
        seq(field('mnemonic', alias($.identifier, $.mnemonic)), repeat($._operand)),
        seq(field('mnemonic', alias($.macro_argument, $.mnemonic)), repeat($._operand)),
        // LLVM dialect store: `*(u64 *)(r1 + 8) = r2`
        seq('*', repeat($._operand)),
      ),

    _operand: ($) =>
      choice(
        $.identifier,
        $.number,
        $.numeric_label_reference,
        $.string,
        $.macro_argument,
        $.memory_operand,
        $.parenthesized,
        $.operator,
        ',',
      ),

    memory_operand: ($) => seq('[', repeat($._operand), ']'),
    parenthesized: ($) => seq('(', repeat($._operand), ')'),

    operator: (_) => /[+\-*\/%&|^<>=!~]+/,

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,

    // Hex (0x1f, 0xff_ff) or decimal (42, 1_000), optionally negative.
    number: (_) =>
      token(choice(/-?0[xX][0-9a-fA-F][0-9a-fA-F_]*/, /-?[0-9][0-9_]*/)),

    // `1f` / `1b`: references to numeric labels forward/backward.
    numeric_label_reference: (_) => token(prec(1, /[0-9]+[fb]/)),

    string: (_) => token(seq('"', repeat(choice(/[^"\\\n]/, /\\./)), '"')),

    // Macro parameters: `\dst`, `\@` (unique id), `\()` (separator).
    macro_argument: (_) => token(choice(/\\[A-Za-z_][A-Za-z0-9_]*/, '\\@', '\\()')),

    comment: (_) => token(choice(/#[^\n]*/, /;[^\n]*/, /\/\/[^\n]*/)),
  },
});
