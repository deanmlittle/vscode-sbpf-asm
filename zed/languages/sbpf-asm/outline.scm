; Outline panel / symbol search: named labels, .equ constants and .macro
; definitions. Numeric labels (`1:`) and labels inside macro bodies
; (`\name:`, `loop_\@:`) are skipped: they are not real symbols.
((label) @name @item
  (#not-match? @name "^[0-9]|\\\\"))

(directive
  name: (directive_name) @context
  .
  (identifier) @name
  (#any-of? @context ".equ" ".macro")) @item
