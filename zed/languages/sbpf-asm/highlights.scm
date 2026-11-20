; sBPF assembly highlights.
;
; Every pattern below is written to be mutually exclusive with the others
; (via #match? / #not-match?), so the result is the same whether an editor
; resolves overlapping captures first-wins or last-wins.

(comment) @comment
(string) @string
(number) @number

; ---------------------------------------------------------------- labels

(label) @label
(numeric_label_reference) @label

; ------------------------------------------------------------ directives

; .globl .equ .rodata .ascii .macro .include ...
(directive_name) @preproc

; ---------------------------------------------------------- instructions

; Real sBPF opcodes (both dialects; v0/v2/v3), plus LLVM-dialect keywords.
((mnemonic) @keyword
  (#match? @keyword "^(?i)(lddw|ldx(b|h|w|dw)|st(b|h|w|dw)|stx(b|h|w|dw)|(add|sub|mul|div|mod|or|and|xor|mov|lsh|rsh|arsh|lmul|udiv|urem|sdiv|srem)(32|64)|neg(32|64)|(hor|uhmul|shmul)64|(be|le)(16|32|64)|ja|j(eq|ne|gt|ge|lt|le|set|sgt|sge|slt|sle)(32)?|call|callx|exit|if|goto)$"))

; LLVM dialect: the statement starts with a register (`r1 += 5`, `w2 = w3`).
((mnemonic) @variable.special
  (#match? @variable.special "^[rw]([0-9]|10)$"))

; Anything else in mnemonic position is a macro invocation (`CHECK_SIGNER 0x9`).
((mnemonic) @function
  (#not-match? @function "^(?i)(lddw|ldx(b|h|w|dw)|st(b|h|w|dw)|stx(b|h|w|dw)|(add|sub|mul|div|mod|or|and|xor|mov|lsh|rsh|arsh|lmul|udiv|urem|sdiv|srem)(32|64)|neg(32|64)|(hor|uhmul|shmul)64|(be|le)(16|32|64)|ja|j(eq|ne|gt|ge|lt|le|set|sgt|sge|slt|sle)(32)?|call|callx|exit|if|goto)$")
  (#not-match? @function "^[rw]([0-9]|10)$"))

; -------------------------------------------------------------- operands

; Registers r0-r10 (and w0-w10, the 32-bit view in the LLVM dialect).
((identifier) @variable.special
  (#match? @variable.special "^[rw]([0-9]|10)$"))

; Syscalls: `call sol_log_`, `call abort`.
((identifier) @function.builtin
  (#match? @function.builtin "^(sol_[A-Za-z0-9_]+|abort)$"))

; LLVM dialect words: `goto L`, `r1 = 5 ll`, `*(u64 *)`, `if r1 s> r2`.
((identifier) @keyword
  (#match? @keyword "^(goto|ll|u8|u16|u32|u64|s)$"))

; UPPER_CASE names are conventionally .equ constants.
((identifier) @constant
  (#match? @constant "^[A-Z_][A-Z0-9_]*$")
  (#not-match? @constant "^[rw]([0-9]|10)$"))

; Every other identifier refers to a label (jump/call target, rodata name).
((identifier) @label
  (#not-match? @label "^[A-Z_][A-Z0-9_]*$")
  (#not-match? @label "^[rw]([0-9]|10)$")
  (#not-match? @label "^(sol_[A-Za-z0-9_]+|abort)$")
  (#not-match? @label "^(goto|ll|u8|u16|u32|u64|s)$"))

; Macro parameters: \arg, \@, \()
(macro_argument) @variable.parameter

; ------------------------------------------------------------ punctuation

(operator) @operator
"*" @operator
["[" "]" "(" ")"] @punctuation.bracket
"," @punctuation.delimiter
