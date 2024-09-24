import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  CompletionItem,
  CompletionItemKind,
  TextDocumentPositionParams,
  Hover,
  InitializeParams,
  TextDocumentSyncKind,
  CodeActionParams,
  CodeActionKind,
  TextEdit,
  Range,
  Position,
  CodeAction,
  Diagnostic,
  DiagnosticSeverity
} from 'vscode-languageserver/node';


import { TextDocument } from 'vscode-languageserver-textdocument';

const connection: ProposedFeatures.Connection = createConnection(ProposedFeatures.all);

const documents: TextDocuments<TextDocument> = new TextDocuments(TextDocument);

console.log('sBPF Aseembly Language Server is starting...');

let opcodes = [
  { code: 'lddw', label: 'lddw_imm', description: 'lddw dst, imm - dst = imm' },
  { code: 'ldxb', label: 'ldxb_reg', description: 'ldxb dst, [src + off] - dst = (src + off) as u8' },
  { code: 'ldxh', label: 'ldxh_reg', description: 'ldxh dst, [src + off] - dst = (src + off) as u16' },
  { code: 'ldxw', label: 'ldxw_reg', description: 'ldxw dst, [src + off] - dst = (src + off) as u32' },
  { code: 'ldxdw', label: 'ldxdw_reg', description: 'ldxdw dst, [src + off] - dst = (src + off) as u64' },
  { code: 'stb', label: 'stb_imm', description: 'stb [dst + off], imm - (dst + offset) as u8 = imm' },
  { code: 'sth', label: 'sth_imm', description: 'sth [dst + off], imm - (dst + offset) as u16 = imm' },
  { code: 'stw', label: 'stw_imm', description: 'stw [dst + off], imm - (dst + offset) as u32 = imm' },
  { code: 'stdw', label: 'stdw_imm', description: 'stdw [dst + off], imm - (dst + offset) as u64 = imm' },
  { code: 'stxb', label: 'stxb_reg', description: 'stxb [dst + off], src - (dst + offset) as u8 = src' },
  { code: 'stxh', label: 'stxh_reg', description: 'stxh [dst + off], src - (dst + offset) as u16 = src' },
  { code: 'stxw', label: 'stxw_reg', description: 'stxw [dst + off], src - (dst + offset) as u32 = src' },
  { code: 'stxdw', label: 'stxdw_reg', description: 'stxdw [dst + off], src - (dst + offset) as u64 = src' },
  { code: 'add32', label: 'add32_imm', description: 'add32 dst, imm - dst += imm' },
  { code: 'add32', label: 'add32_reg', description: 'add32 dst, src - dst += src' },
  { code: 'sub32', label: 'sub32_imm', description: 'sub32 dst, imm - dst = imm - dst' },
  { code: 'sub32', label: 'sub32_reg', description: 'sub32 dst, src - dst -= src' },
  { code: 'mul32', label: 'mul32_imm', description: 'mul32 dst, imm - dst *= imm' },
  { code: 'mul32', label: 'mul32_reg', description: 'mul32 dst, src - dst *= src' },
  { code: 'div32', label: 'div32_imm', description: 'div32 dst, imm - dst /= imm' },
  { code: 'div32', label: 'div32_reg', description: 'div32 dst, src - dst /= src' },
  { code: 'or32', label: 'or32_imm', description: 'or32 dst, imm - dst |= imm' },
  { code: 'or32', label: 'or32_reg', description: 'or32 dst, src - dst |= src' },
  { code: 'and32', label: 'and32_imm', description: 'and32 dst, imm - dst &= imm' },
  { code: 'and32', label: 'and32_reg', description: 'and32 dst, src - dst &= src' },
  { code: 'lsh32', label: 'lsh32_imm', description: 'lsh32 dst, imm - dst <<= imm' },
  { code: 'lsh32', label: 'lsh32_reg', description: 'lsh32 dst, src - dst <<= src' },
  { code: 'rsh32', label: 'rsh32_imm', description: 'rsh32 dst, imm - dst >>= imm' },
  { code: 'rsh32', label: 'rsh32_reg', description: 'rsh32 dst, src - dst >>= src' },
  { code: 'neg32', label: 'neg32_reg', description: 'neg32 dst - dst = -dst' },
  { code: 'mod32', label: 'mod32_imm', description: 'mod32 dst, imm - dst %= imm' },
  { code: 'mod32', label: 'mod32_reg', description: 'mod32 dst, src - dst %= src' },
  { code: 'xor32', label: 'xor32_imm', description: 'xor32 dst, imm - dst ^= imm' },
  { code: 'xor32', label: 'xor32_reg', description: 'xor32 dst, src - dst ^= src' },
  { code: 'mov32', label: 'mov32_imm', description: 'mov32 dst, imm - dst = imm' },
  { code: 'mov32', label: 'mov32_reg', description: 'mov32 dst, src - dst = src' },
  { code: 'arsh32', label: 'arsh32_imm', description: 'arsh32 dst, imm - dst >>= imm (arithmetic)' },
  { code: 'arsh32', label: 'arsh32_reg', description: 'arsh32 dst, src - dst >>= src (arithmetic)' },
  { code: 'lmul32', label: 'lmul32_imm', description: 'lmul32 dst, imm - dst *= (dst * imm) as u32' },
  { code: 'lmul32', label: 'lmul32_reg', description: 'lmul32 dst, src - dst *= (dst * src) as u32' },
  { code: 'uhmul32', label: 'uhmul32_imm', description: 'uhmul32 dst, imm - dst = (dst * imm) as u64' },
  { code: 'udiv32', label: 'udiv32_reg', description: 'udiv32 dst, src - dst /= src' },
  { code: 'urem32', label: 'urem32_imm', description: 'urem32 dst, imm - dst %= imm' },
  { code: 'urem32', label: 'urem32_reg', description: 'urem32 dst, src - dst %= src' },
  { code: 'shmul32', label: 'shmul32_imm', description: 'shmul32 dst, imm - dst = (dst * imm) as i64' },
  { code: 'sdiv32', label: 'sdiv32_reg', description: 'sdiv32 dst, src - dst /= src' },
  { code: 'srem32', label: 'srem32_imm', description: 'srem32 dst, imm - dst %= imm' },
  { code: 'srem32', label: 'srem32_reg', description: 'srem32 dst, src - dst %= src' },
  { code: 'le', label: 'le', description: 'le dst - dst = htole<imm>(dst), with imm in {16, 32, 64}' },
  { code: 'be', label: 'be', description: 'be dst - dst = htobe<imm>(dst), with imm in {16, 32, 64}' },
  { code: 'add64', label: 'add64_imm', description: 'add64 dst, imm - dst += imm' },
  { code: 'add64', label: 'add64_reg', description: 'add64 dst, src - dst += src' },
  { code: 'sub64', label: 'sub64_imm', description: 'sub64 dst, imm - dst -= imm' },
  { code: 'sub64', label: 'sub64_reg', description: 'sub64 dst, src - dst -= src' },
  { code: 'mul64', label: 'mul64_imm', description: 'mul64 dst, imm - dst *= imm' },
  { code: 'mul64', label: 'mul64_reg', description: 'mul64 dst, src - dst *= src' },
  { code: 'div64', label: 'div64_imm', description: 'div64 dst, imm - dst /= imm' },
  { code: 'div64', label: 'div64_reg', description: 'div64 dst, src - dst /= src' },
  { code: 'or64', label: 'or64_imm', description: 'or64 dst, imm - dst |= imm' },
  { code: 'or64', label: 'or64_reg', description: 'or64 dst, src - dst |= src' },
  { code: 'and64', label: 'and64_imm', description: 'and64 dst, imm - dst &= imm' },
  { code: 'and64', label: 'and64_reg', description: 'and64 dst, src - dst &= src' },
  { code: 'lsh64', label: 'lsh64_imm', description: 'lsh64 dst, imm - dst <<= imm' },
  { code: 'lsh64', label: 'lsh64_reg', description: 'lsh64 dst, src - dst <<= src' },
  { code: 'rsh64', label: 'rsh64_imm', description: 'rsh64 dst, imm - dst >>= imm' },
  { code: 'rsh64', label: 'rsh64_reg', description: 'rsh64 dst, src - dst >>= src' },
  { code: 'neg64', label: 'neg64_reg', description: 'neg64 dst - dst = -dst' },
  { code: 'mod64', label: 'mod64_imm', description: 'mod64 dst, imm - dst %= imm' },
  { code: 'mod64', label: 'mod64_reg', description: 'mod64 dst, src - dst %= src' },
  { code: 'xor64', label: 'xor64_imm', description: 'xor64 dst, imm - dst ^= imm' },
  { code: 'xor64', label: 'xor64_reg', description: 'xor64 dst, src - dst ^= src' },
  { code: 'mov64', label: 'mov64_imm', description: 'mov64 dst, imm - dst = imm' },
  { code: 'mov64', label: 'mov64_reg', description: 'mov64 dst, src - dst = src' },
  { code: 'arsh64', label: 'arsh64_imm', description: 'arsh64 dst, imm - dst >>= imm (arithmetic)' },
  { code: 'arsh64', label: 'arsh64_reg', description: 'arsh64 dst, src - dst >>= src (arithmetic)' },
  { code: 'hor64', label: 'hor64_imm', description: 'hor64 dst, imm - dst |= imm << 32' },
  { code: 'lmul64', label: 'lmul64_imm', description: 'lmul64 dst, imm - dst = (dst * imm) as u64' },
  { code: 'lmul64', label: 'lmul64_reg', description: 'lmul64 dst, src - dst = (dst * src) as u64' },
  { code: 'uhmul64', label: 'uhmul64_imm', description: 'uhmul64 dst, imm - dst = (dst * imm) >> 64' },
  { code: 'uhmul64', label: 'uhmul64_reg', description: 'uhmul64 dst, src - dst = (dst * src) >> 64' },
  { code: 'udiv64', label: 'udiv64_imm', description: 'udiv64 dst, imm - dst /= imm' },
  { code: 'udiv64', label: 'udiv64_reg', description: 'udiv64 dst, src - dst /= src' },
  { code: 'urem64', label: 'urem64_imm', description: 'urem64 dst, imm - dst %= imm' },
  { code: 'urem64', label: 'urem64_reg', description: 'urem64 dst, src - dst %= src' },
  { code: 'shmul64', label: 'shmul64_imm', description: 'shmul64 dst, imm - dst = (dst * imm) >> 64' },
  { code: 'shmul64', label: 'shmul64_reg', description: 'shmul64 dst, src - dst = (dst * src) >> 64' },
  { code: 'sdiv64', label: 'sdiv64_imm', description: 'sdiv64 dst, imm - dst /= imm' },
  { code: 'sdiv64', label: 'sdiv64_reg', description: 'sdiv64 dst, src - dst /= src' },
  { code: 'srem64', label: 'srem64_imm', description: 'srem64 dst, imm - dst %= imm' },
  { code: 'srem64', label: 'srem64_reg', description: 'srem64 dst, src - dst %= src' },
  { code: 'ja', label: 'ja_reg', description: 'ja +off - PC += off' },
  { code: 'jeq', label: 'jeq_imm', description: 'jeq dst, imm, +off - PC += off if dst == imm' },
  { code: 'jeq', label: 'jeq_reg', description: 'jeq dst, src, +off - PC += off if dst == src' },
  { code: 'jgt', label: 'jgt_imm', description: 'jgt dst, imm, +off - PC += off if dst > imm' },
  { code: 'jgt', label: 'jgt_reg', description: 'jgt dst, src, +off - PC += off if dst > src' },
  { code: 'jge', label: 'jge_imm', description: 'jge dst, imm, +off - PC += off if dst >= imm' },
  { code: 'jge', label: 'jge_reg', description: 'jge dst, src, +off - PC += off if dst >= src' },
  { code: 'jlt', label: 'jlt_imm', description: 'jlt dst, imm, +off - PC += off if dst < imm' },
  { code: 'jlt', label: 'jlt_reg', description: 'jlt dst, src, +off - PC += off if dst < src' },
  { code: 'jle', label: 'jle_imm', description: 'jle dst, imm, +off - PC += off if dst <= imm' },
  { code: 'jle', label: 'jle_reg', description: 'jle dst, src, +off - PC += off if dst <= src' },
  { code: 'jset', label: 'jset_imm', description: 'jset dst, imm, +off - PC += off if dst & imm' },
  { code: 'jset', label: 'jset_reg', description: 'jset dst, src, +off - PC += off if dst & src' },
  { code: 'jne', label: 'jne_imm', description: 'jne dst, imm, +off - PC += off if dst != imm' },
  { code: 'jne', label: 'jne_reg', description: 'jne dst, src, +off - PC += off if dst != src' },
  { code: 'jsgt', label: 'jsgt_imm', description: 'jsgt dst, imm, +off - PC += off if dst > imm (signed)' },
  { code: 'jsgt', label: 'jsgt_reg', description: 'jsgt dst, src, +off - PC += off if dst > src (signed)' },
  { code: 'jsge', label: 'jsge_imm', description: 'jsge dst, imm, +off - PC += off if dst >= imm (signed)' },
  { code: 'jsge', label: 'jsge_reg', description: 'jsge dst, src, +off - PC += off if dst >= src (signed)' },
  { code: 'jslt', label: 'jslt_imm', description: 'jslt dst, imm, +off - PC += off if dst < imm (signed)' },
  { code: 'jslt', label: 'jslt_reg', description: 'jslt dst, src, +off - PC += off if dst < src (signed)' },
  { code: 'jsle', label: 'jsle_imm', description: 'jsle dst, imm, +off - PC += off if dst <= imm (signed)' },
  { code: 'jsle', label: 'jsle_reg', description: 'jsle dst, src, +off - PC += off if dst <= src (signed)' },
  { code: 'call', label: 'call_imm', description: 'call imm - syscall function call to syscall with key imm' },
  { code: 'exit', label: 'exit_reg', description: 'exit - return r0' },
];

// Taken from: https://github.com/solana-labs/solana/blob/27eff8408b7223bb3c4ab70523f8a8dca3ca6645/sdk/program/src/syscalls/definitions.rs#L39
// TODO: Check for updates from https://github.com/anza-xyz/agave/blob/master/sdk/program/src/syscalls/definitions.rs
let syscalls = [
  { label: 'abort', description: 'panic!()' },
  { label: 'sol_log_', description: 'fn sol_log_(message: *const u8, len: u64)' },
  { label: 'sol_log_64_', description: 'fn sol_log_64_(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64)' },
  { label: 'sol_log_compute_units_', description: 'fn sol_log_compute_units_()' },
  { label: 'sol_log_pubkey', description: 'fn sol_log_pubkey(pubkey_addr: *const u8)' },
  { label: 'sol_create_program_address', description: 'fn sol_create_program_address(seeds_addr: *const u8, seeds_len: u64, program_id_addr: *const u8, address_bytes_addr: *const u8) -> u64)' },
  { label: 'sol_try_find_program_address', description: 'fn sol_try_find_program_address(seeds_addr: *const u8, seeds_len: u64, program_id_addr: *const u8, address_bytes_addr: *const u8, bump_seed_addr: *const u8) -> u64)' },
  { label: 'sol_sha256', description: 'fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)' },
  { label: 'sol_keccak256', description: 'fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)' },
  { label: 'sol_secp256k1_recover', description: 'fn sol_secp256k1_recover(hash: *const u8, recovery_id: u64, signature: *const u8, result: *mut u8) -> u64)' },
  { label: 'sol_blake3', description: 'fn sol_blake3(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)' },
  { label: 'sol_get_clock_sysvar', description: 'fn sol_get_clock_sysvar(addr: *mut u8) -> u64)' },
  { label: 'sol_get_epoch_schedule_sysvar', description: 'fn sol_get_epoch_schedule_sysvar(addr: *mut u8) -> u64)' },
  { label: 'sol_get_fees_sysvar', description: 'fn sol_get_fees_sysvar(addr: *mut u8) -> u64)' },
  { label: 'sol_get_rent_sysvar', description: 'fn sol_get_rent_sysvar(addr: *mut u8) -> u64)' },
  { label: 'sol_get_last_restart_slot', description: 'fn sol_get_last_restart_slot(addr: *mut u8) -> u64)' },
  { label: 'sol_memcpy_', description: 'fn sol_memcpy_(dst: *mut u8, src: *const u8, n: u64)' },
  { label: 'sol_memmove_', description: 'fn sol_memmove_(dst: *mut u8, src: *const u8, n: u64)' },
  { label: 'sol_memcmp_', description: 'fn sol_memcmp_(s1: *const u8, s2: *const u8, n: u64, result: *mut i32)' },
  { label: 'sol_memset_', description: 'fn sol_memset_(s: *mut u8, c: u8, n: u64)' },
  { label: 'sol_invoke_signed_c', description: 'fn sol_invoke_signed_c(instruction_addr: *const u8, account_infos_addr: *const u8, account_infos_len: u64, signers_seeds_addr: *const u8, signers_seeds_len: u64) -> u64)' },
  { label: 'sol_invoke_signed_rust', description: 'fn sol_invoke_signed_rust(instruction_addr: *const u8, account_infos_addr: *const u8, account_infos_len: u64, signers_seeds_addr: *const u8, signers_seeds_len: u64) -> u64)' },
  { label: 'sol_set_return_data', description: 'fn sol_set_return_data(data: *const u8, length: u64)' },
  { label: 'sol_get_return_data', description: 'fn sol_get_return_data(data: *mut u8, length: u64, program_id: *mut Pubkey) -> u64)' },
  { label: 'sol_log_data', description: 'fn sol_log_data(data: *const u8, data_len: u64)' },
  { label: 'sol_get_processed_sibling_instruction', description: 'fn sol_get_processed_sibling_instruction(index: u64, meta: *mut ProcessedSiblingInstruction, program_id: *mut Pubkey, data: *mut u8, accounts: *mut AccountMeta) -> u64)' },
  { label: 'sol_get_stack_height', description: 'fn sol_get_stack_height() -> u64)' },
  { label: 'sol_curve_validate_point', description: 'fn sol_curve_validate_point(curve_id: u64, point_addr: *const u8, result: *mut u8) -> u64)' },
  { label: 'sol_curve_group_op', description: 'fn sol_curve_group_op(curve_id: u64, group_op: u64, left_input_addr: *const u8, right_input_addr: *const u8, result_point_addr: *mut u8) -> u64)' },
  { label: 'sol_curve_multiscalar_mul', description: 'fn sol_curve_multiscalar_mul(curve_id: u64, scalars_addr: *const u8, points_addr: *const u8, points_len: u64, result_point_addr: *mut u8) -> u64)' },
  { label: 'sol_curve_pairing_map', description: 'fn sol_curve_pairing_map(curve_id: u64, point: *const u8, result: *mut u8) -> u64)' },
  { label: 'sol_alt_bn128_group_op', description: 'fn sol_alt_bn128_group_op(group_op: u64, input: *const u8, input_size: u64, result: *mut u8) -> u64)' },
  { label: 'sol_big_mod_exp', description: 'fn sol_big_mod_exp(params: *const u8, result: *mut u8) -> u64)' },
  { label: 'sol_get_epoch_rewards_sysvar', description: 'fn sol_get_epoch_rewards_sysvar(addr: *mut u8) -> u64)' },
  { label: 'sol_poseidon', description: 'fn sol_poseidon(parameters: u64, endianness: u64, vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)' },
  { label: 'sol_remaining_compute_units', description: 'fn sol_remaining_compute_units() -> u64)' },
  { label: 'sol_alt_bn128_compression', description: 'fn sol_alt_bn128_compression(op: u64, input: *const u8, input_size: u64, result: *mut u8) -> u64)' },
];

connection.onInitialize((params: InitializeParams) => {
  console.log('sBPF Language server initialized.');
  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      completionProvider: {
        resolveProvider: true
      },
      hoverProvider: true,
      codeActionProvider: true
    }
  };
});

documents.onDidOpen((e) => {
  console.log(`Document opened: ${e.document.uri}`);
});

connection.onCompletion(
  (textDocumentPosition: TextDocumentPositionParams): CompletionItem[] => {
    const completions: CompletionItem[] = [];

    opcodes.forEach((opcode) => {
      completions.push({
        label: opcode.label,
        insertText: opcode.code,
        kind: CompletionItemKind.Function,
        data: opcode.label
      });
    });

    syscalls.forEach((syscall) => {
      completions.push({
        label: syscall.label,
        kind: CompletionItemKind.Function,
        data: syscall.label
      });
    });

    return completions;
  }
);

connection.onCompletionResolve((item: CompletionItem): CompletionItem => {
  let opcode = opcodes.find((o) => o.label === item.label);
  if (opcode) {
    item.detail = opcode.label;
    item.documentation = opcode.description;
    return item;
  }

  let syscall = syscalls.find((s) => s.label === item.label);
  if (syscall) {
    item.detail = syscall.label;
    item.documentation = syscall.description;
    return item;
  }

  return item;
});

connection.onHover((params) => {
  const document = documents.get(params.textDocument.uri);
  if (!document) { return null; }
  const position = params.position;
  const wordRange = getWordRangeAtPosition(document, position);
  const word = document.getText(wordRange);

  const opcode = opcodes.find((o) => o.code === word);
  if (opcode) {
    return {
      contents: {
        kind: 'markdown',
        value: `**${opcode.label}**\n\n${opcode.description}`
      }
    };
  }

  const syscall = syscalls.find((s) => s.label === word);
  if (syscall) {
    return {
      contents: {
        kind: 'markdown',
        value: `**${syscall.label}**\n\n${syscall.description}`
      }
    };
  }

  return null;
});

function getWordRangeAtPosition(
  document: TextDocument,
  position: Position
): Range {
  const text = document.getText();
  const offset = document.offsetAt(position);

  let start = offset;
  let end = offset;

  while (start > 0 && /\w/.test(text.charAt(start - 1))) {
    start--;
  }
  while (end < text.length && /\w/.test(text.charAt(end))) {
    end++;
  }

  return {
    start: document.positionAt(start),
    end: document.positionAt(end)
  };
}

// Listen for document changes
documents.onDidChangeContent((change) => {
  validateTextDocument(change.document);
});

async function validateTextDocument(textDocument: TextDocument): Promise<void> {
  const text = textDocument.getText();

  const diagnostics: Diagnostic[] = [];

  // Check for .globl directive
  const globlRegex = /\.globl\s+(\w+)/;
  const globlMatch = globlRegex.exec(text);

  if (!globlMatch) {
    const diagnostic: Diagnostic = {
      severity: DiagnosticSeverity.Error,
      range: {
        start: Position.create(0, 0),
        end: Position.create(0, 0),
      },
      message: "Global entrypoint not defined. Try adding '.globl entrypoint'",
      source: 'solana-ebpf',
      code: 'missing-globl',
    };
    diagnostics.push(diagnostic);
  } else {
    const globlName = globlMatch[1];

    // Check for label matching the globl name
    const labelRegex = new RegExp(`^${globlName}:`, 'm');
    if (!labelRegex.test(text)) {
      const diagnostic: Diagnostic = {
        severity: DiagnosticSeverity.Error,
        range: {
          start: Position.create(0, 0),
          end: Position.create(0, 0),
        },
        message: `Global entrypoint label '${globlName}:' not found.`,
        source: 'solana-ebpf',
        code: 'missing-entrypoint',
      };
      diagnostics.push(diagnostic);
    }
  }

  connection.sendDiagnostics({ uri: textDocument.uri, diagnostics });
}

connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const document = documents.get(params.textDocument.uri);
  if (!document) { return []; }

  const codeActions: CodeAction[] = [];

  for (const diagnostic of params.context.diagnostics) {
    if (diagnostic.source !== 'solana-ebpf' || !diagnostic.code) {
      continue;
    }

    if (diagnostic.code === 'missing-globl') {
      // Quick fix for missing .globl
      const edit: TextEdit = TextEdit.insert(
        Position.create(0, 0),
        '.globl entrypoint\n'
      );

      const action: CodeAction = {
        title: "Add '.globl entrypoint'",
        kind: CodeActionKind.QuickFix,
        diagnostics: [diagnostic],
        edit: {
          changes: {
            [document.uri]: [edit],
          },
        },
      };
      codeActions.push(action);
    } else if (diagnostic.code === 'missing-entrypoint') {
      // Quick fix for missing entrypoint label
      const lines = document.getText().split('\n');
      let insertLine = lines.length;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim() === '.globl entrypoint') {
          insertLine = i + 1;
          break;
        }
      }

      const edit: TextEdit = TextEdit.insert(
        Position.create(insertLine, 0),
        'entrypoint:\n'
      );

      const action: CodeAction = {
        title: "Add 'entrypoint:' label",
        kind: CodeActionKind.QuickFix,
        diagnostics: [diagnostic],
        edit: {
          changes: {
            [document.uri]: [edit],
          },
        },
      };
      codeActions.push(action);
    }
  }

  return codeActions;
});

documents.listen(connection);
connection.listen();