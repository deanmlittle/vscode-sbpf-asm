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
  DiagnosticSeverity,
  InsertTextFormat
} from 'vscode-languageserver/node';
/* eslint-disable curly */


import { TextDocument } from 'vscode-languageserver-textdocument';
import { promisify } from "util";
import { exec } from "child_process";

const connection: ProposedFeatures.Connection = createConnection(ProposedFeatures.all);

const documents: TextDocuments<TextDocument> = new TextDocuments(TextDocument);

const execPromise = promisify(exec);
const VALIDATE_BUILD_DEBOUNCE_MS = 100;
let validateBuildTimer: NodeJS.Timeout | undefined;
let workspaceRoot: string | null = null;

enum SymbolType {
  EQU = "equ",
  LABEL = "label"
}
interface Symbol {
  name: string;
  value: string;
  type: SymbolType;
  line: number;
  description?: string;
}

let documentSymbols = new Map<string, Symbol[]>();

console.log('sBPF Assembly Language Server is starting...');

const NUM_REGISTERS = 11;
const registers = "|"+ new Array(NUM_REGISTERS).fill(0).map((_, n) => "r" + n).join(",") + "|";
const dst = '${1'+registers+'}';
const off = '${1:+0x}';
const dst_imm = '${1'+registers+'}, ${2:0x}';
const dst_end = '${1'+registers+'}, ${2|0x10,0x20,0x40|}';
const dst_src = '${1'+registers+'}, ${2'+registers+'}';
const dst_src_off = '${1'+registers+'}, [${2'+registers+'}+${3:0x}]';
const dst_off_imm = '[${1'+registers+'}+${2:0x}], ${3:0x0}';
const dst_off_src = '[${1'+registers+'}+${2:0x}], ${3'+registers+'}';
const src_imm_off =  '${1'+registers+'}, ${2:0x}, +${3:0x}';
const src_dst_off = '${1'+registers+'}, ${2'+registers+'}, +${3:0x}';

let snippets = {
  // dst, imm
  ld: dst_imm,
  // dst, [src+off]
  ldx: dst_src_off,
  // [dst+off], imm
  st: dst_off_imm,
  // [dst+off], src
  stx: dst_off_src,
  // dst, imm
  alu_imm: dst_imm,
  // dst, src
  alu_reg: dst_src,
  // dst
  neg: dst,
  // +off
  ja: off,
  // src, imm, +off
  ja_imm: src_imm_off,
  // src, dst, +off
  ja_reg: src_dst_off,
  // dst, imm
  alu64_imm: dst_imm,
  // dst, src
  alu64_reg: dst_src,
  // dst, imm[16, 32, 64]
  end: dst_end,
  exit: "",
  call: "${1|abort,sol_log_,sol_log_64_,sol_log_compute_units_,sol_log_pubkey,sol_create_program_address,sol_try_find_program_address,sol_sha256,sol_keccak256,sol_secp256k1_recover,sol_blake3,sol_get_clock_sysvar,sol_get_epoch_schedule_sysvar,sol_get_fees_sysvar,sol_get_rent_sysvar,sol_get_last_restart_slot,sol_memcpy_,sol_memmove_,sol_memcmp_,sol_memset_,sol_invoke_signed_c,sol_invoke_signed_rust,sol_set_return_data,sol_get_return_data,sol_log_data,sol_get_processed_sibling_instruction,sol_get_stack_height,sol_curve_validate_point,sol_curve_group_op,sol_curve_multiscalar_mul,sol_curve_pairing_map,sol_alt_bn128_group_op,sol_big_mod_exp,sol_get_epoch_rewards_sysvar,sol_poseidon,sol_remaining_compute_units,sol_alt_bn128_compression|}"
};

let opcodes = [
  { code: 'lddw', label: 'lddw_imm', description: 'lddw dst, imm\n\ndst = imm', snippet: snippets.ld },
  { code: 'ldxb', label: 'ldxb_reg', description: 'ldxb dst, [src + off]\n\ndst = (src + off) as u8', snippet: snippets.ldx },
  { code: 'ldxh', label: 'ldxh_reg', description: 'ldxh dst, [src + off]\n\ndst = (src + off) as u16', snippet: snippets.ldx },
  { code: 'ldxw', label: 'ldxw_reg', description: 'ldxw dst, [src + off]\n\ndst = (src + off) as u32', snippet: snippets.ldx },
  { code: 'ldxdw', label: 'ldxdw_reg', description: 'ldxdw dst, [src + off]\n\ndst = (src + off) as u64', snippet: snippets.ldx },
  { code: 'stb', label: 'stb_imm', description: 'stb [dst + off], imm\n\n(dst + offset) as u8 = imm', snippet: snippets.st },
  { code: 'sth', label: 'sth_imm', description: 'sth [dst + off], imm\n\n(dst + offset) as u16 = imm', snippet: snippets.st },
  { code: 'stw', label: 'stw_imm', description: 'stw [dst + off], imm\n\n(dst + offset) as u32 = imm', snippet: snippets.st },
  { code: 'stdw', label: 'stdw_imm', description: 'stdw [dst + off], imm\n\n(dst + offset) as u64 = imm', snippet: snippets.st },
  { code: 'stxb', label: 'stxb_reg', description: 'stxb [dst + off], src\n\n(dst + offset) as u8 = src', snippet: snippets.stx },
  { code: 'stxh', label: 'stxh_reg', description: 'stxh [dst + off], src\n\n(dst + offset) as u16 = src', snippet: snippets.stx },
  { code: 'stxw', label: 'stxw_reg', description: 'stxw [dst + off], src\n\n(dst + offset) as u32 = src', snippet: snippets.stx },
  { code: 'stxdw', label: 'stxdw_reg', description: 'stxdw [dst + off], src\n\n(dst + offset) as u64 = src', snippet: snippets.stx },
  { code: 'add32', label: 'add32_imm', description: 'add32 dst, imm\n\ndst += imm', snippet: snippets.alu_imm },
  { code: 'add32', label: 'add32_reg', description: 'add32 dst, src\n\ndst += src', snippet: snippets.alu_reg },
  { code: 'sub32', label: 'sub32_imm', description: 'sub32 dst, imm\n\ndst = imm - dst', snippet: snippets.alu_imm },
  { code: 'sub32', label: 'sub32_reg', description: 'sub32 dst, src\n\ndst -= src', snippet: snippets.alu_reg },
  { code: 'mul32', label: 'mul32_imm', description: 'mul32 dst, imm\n\ndst *= imm', snippet: snippets.alu_imm },
  { code: 'mul32', label: 'mul32_reg', description: 'mul32 dst, src\n\ndst *= src', snippet: snippets.alu_reg },
  { code: 'div32', label: 'div32_imm', description: 'div32 dst, imm\n\ndst /= imm', snippet: snippets.alu_imm },
  { code: 'div32', label: 'div32_reg', description: 'div32 dst, src\n\ndst /= src', snippet: snippets.alu_reg },
  { code: 'or32', label: 'or32_imm', description: 'or32 dst, imm\n\ndst |= imm', snippet: snippets.alu_imm },
  { code: 'or32', label: 'or32_reg', description: 'or32 dst, src\n\ndst |= src', snippet: snippets.alu_reg },
  { code: 'and32', label: 'and32_imm', description: 'and32 dst, imm\n\ndst &= imm', snippet: snippets.alu_imm },
  { code: 'and32', label: 'and32_reg', description: 'and32 dst, src\n\ndst &= src', snippet: snippets.alu_reg },
  { code: 'lsh32', label: 'lsh32_imm', description: 'lsh32 dst, imm\n\ndst <<= imm', snippet: snippets.alu_imm },
  { code: 'lsh32', label: 'lsh32_reg', description: 'lsh32 dst, src\n\ndst <<= src', snippet: snippets.alu_reg },
  { code: 'rsh32', label: 'rsh32_imm', description: 'rsh32 dst, imm\n\ndst >>= imm', snippet: snippets.alu_imm },
  { code: 'rsh32', label: 'rsh32_reg', description: 'rsh32 dst, src\n\ndst >>= src', snippet: snippets.alu_reg },
  { code: 'neg32', label: 'neg32_reg', description: 'neg32 dst\n\ndst = -dst', snippet: snippets.neg },
  { code: 'mod32', label: 'mod32_imm', description: 'mod32 dst, imm\n\ndst %= imm', snippet: snippets.alu_imm },
  { code: 'mod32', label: 'mod32_reg', description: 'mod32 dst, src\n\ndst %= src', snippet: snippets.alu_reg },
  { code: 'xor32', label: 'xor32_imm', description: 'xor32 dst, imm\n\ndst ^= imm', snippet: snippets.alu_imm },
  { code: 'xor32', label: 'xor32_reg', description: 'xor32 dst, src\n\ndst ^= src', snippet: snippets.alu_reg },
  { code: 'mov32', label: 'mov32_imm', description: 'mov32 dst, imm\n\ndst = imm', snippet: snippets.alu_imm },
  { code: 'mov32', label: 'mov32_reg', description: 'mov32 dst, src\n\ndst = src', snippet: snippets.alu_reg },
  { code: 'arsh32', label: 'arsh32_imm', description: 'arsh32 dst, imm\n\ndst >>= imm (arithmetic)', snippet: snippets.alu_imm },
  { code: 'arsh32', label: 'arsh32_reg', description: 'arsh32 dst, src\n\ndst >>= src (arithmetic)', snippet: snippets.alu_reg },
  { code: 'lmul32', label: 'lmul32_imm', description: 'lmul32 dst, imm\n\ndst *= (dst * imm) as u32', snippet: snippets.alu_imm },
  { code: 'lmul32', label: 'lmul32_reg', description: 'lmul32 dst, src\n\ndst *= (dst * src) as u32', snippet: snippets.alu_reg },
  { code: 'uhmul32', label: 'uhmul32_imm', description: 'uhmul32 dst, imm\n\ndst = (dst * imm) as u64', snippet: snippets.alu_imm },
  { code: 'udiv32', label: 'udiv32_reg', description: 'udiv32 dst, src\n\ndst /= src', snippet: snippets.alu_reg },
  { code: 'urem32', label: 'urem32_imm', description: 'urem32 dst, imm\n\ndst %= imm', snippet: snippets.alu_imm },
  { code: 'urem32', label: 'urem32_reg', description: 'urem32 dst, src\n\ndst %= src', snippet: snippets.alu_reg },
  { code: 'shmul32', label: 'shmul32_imm', description: 'shmul32 dst, imm\n\ndst = (dst * imm) as i64', snippet: snippets.alu_imm },
  { code: 'sdiv32', label: 'sdiv32_reg', description: 'sdiv32 dst, src\n\ndst /= src', snippet: snippets.alu_reg },
  { code: 'srem32', label: 'srem32_imm', description: 'srem32 dst, imm\n\ndst %= imm', snippet: snippets.alu_imm },
  { code: 'srem32', label: 'srem32_reg', description: 'srem32 dst, src\n\ndst %= src', snippet: snippets.alu_reg },
  { code: 'le', label: 'le', description: 'le dst\n\ndst = htole<imm>(dst), with imm in {16, 32, 64}', snippet: snippets.end },
  { code: 'be', label: 'be', description: 'be dst\n\ndst = htobe<imm>(dst), with imm in {16, 32, 64}', snippet: snippets.end, disabled: true },
  { code: 'add64', label: 'add64_imm', description: 'add64 dst, imm\n\ndst += imm', snippet: snippets.alu64_imm },
  { code: 'add64', label: 'add64_reg', description: 'add64 dst, src\n\ndst += src', snippet: snippets.alu64_reg },
  { code: 'sub64', label: 'sub64_imm', description: 'sub64 dst, imm\n\ndst -= imm', snippet: snippets.alu64_imm },
  { code: 'sub64', label: 'sub64_reg', description: 'sub64 dst, src\n\ndst -= src', snippet: snippets.alu64_reg },
  { code: 'mul64', label: 'mul64_imm', description: 'mul64 dst, imm\n\ndst *= imm', snippet: snippets.alu64_imm },
  { code: 'mul64', label: 'mul64_reg', description: 'mul64 dst, src\n\ndst *= src', snippet: snippets.alu64_reg },
  { code: 'div64', label: 'div64_imm', description: 'div64 dst, imm\n\ndst /= imm', snippet: snippets.alu64_imm },
  { code: 'div64', label: 'div64_reg', description: 'div64 dst, src\n\ndst /= src', snippet: snippets.alu64_reg },
  { code: 'or64', label: 'or64_imm', description: 'or64 dst, imm\n\ndst |= imm', snippet: snippets.alu64_imm },
  { code: 'or64', label: 'or64_reg', description: 'or64 dst, src\n\ndst |= src', snippet: snippets.alu64_reg },
  { code: 'and64', label: 'and64_imm', description: 'and64 dst, imm\n\ndst &= imm', snippet: snippets.alu64_imm },
  { code: 'and64', label: 'and64_reg', description: 'and64 dst, src\n\ndst &= src', snippet: snippets.alu64_reg },
  { code: 'lsh64', label: 'lsh64_imm', description: 'lsh64 dst, imm\n\ndst <<= imm', snippet: snippets.alu64_imm },
  { code: 'lsh64', label: 'lsh64_reg', description: 'lsh64 dst, src\n\ndst <<= src', snippet: snippets.alu64_reg },
  { code: 'rsh64', label: 'rsh64_imm', description: 'rsh64 dst, imm\n\ndst >>= imm', snippet: snippets.alu64_imm },
  { code: 'rsh64', label: 'rsh64_reg', description: 'rsh64 dst, src\n\ndst >>= src', snippet: snippets.alu64_reg },
  { code: 'neg64', label: 'neg64_reg', description: 'neg64 dst\n\ndst = -dst', snippet: snippets.neg },
  { code: 'mod64', label: 'mod64_imm', description: 'mod64 dst, imm\n\ndst %= imm', snippet: snippets.alu64_imm },
  { code: 'mod64', label: 'mod64_reg', description: 'mod64 dst, src\n\ndst %= src', snippet: snippets.alu64_reg },
  { code: 'xor64', label: 'xor64_imm', description: 'xor64 dst, imm\n\ndst ^= imm', snippet: snippets.alu64_imm },
  { code: 'xor64', label: 'xor64_reg', description: 'xor64 dst, src\n\ndst ^= src', snippet: snippets.alu64_reg },
  { code: 'mov64', label: 'mov64_imm', description: 'mov64 dst, imm\n\ndst = imm', snippet: snippets.alu64_imm },
  { code: 'mov64', label: 'mov64_reg', description: 'mov64 dst, src\n\ndst = src', snippet: snippets.alu64_reg },
  { code: 'arsh64', label: 'arsh64_imm', description: 'arsh64 dst, imm\n\ndst >>= imm (arithmetic)', snippet: snippets.alu64_imm },
  { code: 'arsh64', label: 'arsh64_reg', description: 'arsh64 dst, src\n\ndst >>= src (arithmetic)', snippet: snippets.alu64_reg },
  { code: 'hor64', label: 'hor64_imm', description: 'hor64 dst, imm\n\ndst |= imm << 32', snippet: snippets.alu64_imm },
  { code: 'lmul64', label: 'lmul64_imm', description: 'lmul64 dst, imm\n\ndst = (dst * imm) as u64', snippet: snippets.alu64_imm },
  { code: 'lmul64', label: 'lmul64_reg', description: 'lmul64 dst, src\n\ndst = (dst * src) as u64', snippet: snippets.alu64_reg },
  { code: 'uhmul64', label: 'uhmul64_imm', description: 'uhmul64 dst, imm\n\ndst = (dst * imm) >> 64', snippet: snippets.alu64_imm },
  { code: 'uhmul64', label: 'uhmul64_reg', description: 'uhmul64 dst, src\n\ndst = (dst * src) >> 64', snippet: snippets.alu64_reg },
  { code: 'udiv64', label: 'udiv64_imm', description: 'udiv64 dst, imm\n\ndst /= imm', snippet: snippets.alu64_imm },
  { code: 'udiv64', label: 'udiv64_reg', description: 'udiv64 dst, src\n\ndst /= src', snippet: snippets.alu64_reg },
  { code: 'urem64', label: 'urem64_imm', description: 'urem64 dst, imm\n\ndst %= imm', snippet: snippets.alu64_imm },
  { code: 'urem64', label: 'urem64_reg', description: 'urem64 dst, src\n\ndst %= src', snippet: snippets.alu64_reg },
  { code: 'shmul64', label: 'shmul64_imm', description: 'shmul64 dst, imm\n\ndst = (dst * imm) >> 64', snippet: snippets.alu64_imm },
  { code: 'shmul64', label: 'shmul64_reg', description: 'shmul64 dst, src\n\ndst = (dst * src) >> 64', snippet: snippets.alu64_reg },
  { code: 'sdiv64', label: 'sdiv64_imm', description: 'sdiv64 dst, imm\n\ndst /= imm', snippet: snippets.alu64_imm },
  { code: 'sdiv64', label: 'sdiv64_reg', description: 'sdiv64 dst, src\n\ndst /= src', snippet: snippets.alu64_reg },
  { code: 'srem64', label: 'srem64_imm', description: 'srem64 dst, imm\n\ndst %= imm', snippet: snippets.alu64_imm },
  { code: 'srem64', label: 'srem64_reg', description: 'srem64 dst, src\n\ndst %= src', snippet: snippets.alu64_reg },
  { code: 'ja', label: 'ja_reg', description: 'ja +off\n\nPC += off', snippet: snippets.ja },
  { code: 'jeq', label: 'jeq_imm', description: 'jeq dst, imm, +off\n\nPC += off if dst == imm', snippet: snippets.ja_imm },
  { code: 'jeq', label: 'jeq_reg', description: 'jeq dst, src, +off\n\nPC += off if dst == src', snippet: snippets.ja_reg },
  { code: 'jgt', label: 'jgt_imm', description: 'jgt dst, imm, +off\n\nPC += off if dst > imm', snippet: snippets.ja_imm },
  { code: 'jgt', label: 'jgt_reg', description: 'jgt dst, src, +off\n\nPC += off if dst > src', snippet: snippets.ja_reg },
  { code: 'jge', label: 'jge_imm', description: 'jge dst, imm, +off\n\nPC += off if dst >= imm', snippet: snippets.ja_imm },
  { code: 'jge', label: 'jge_reg', description: 'jge dst, src, +off\n\nPC += off if dst >= src', snippet: snippets.ja_reg },
  { code: 'jlt', label: 'jlt_imm', description: 'jlt dst, imm, +off\n\nPC += off if dst < imm', snippet: snippets.ja_imm },
  { code: 'jlt', label: 'jlt_reg', description: 'jlt dst, src, +off\n\nPC += off if dst < src', snippet: snippets.ja_reg },
  { code: 'jle', label: 'jle_imm', description: 'jle dst, imm, +off\n\nPC += off if dst <= imm', snippet: snippets.ja_imm },
  { code: 'jle', label: 'jle_reg', description: 'jle dst, src, +off\n\nPC += off if dst <= src', snippet: snippets.ja_reg },
  { code: 'jset', label: 'jset_imm', description: 'jset dst, imm, +off\n\nPC += off if dst & imm', snippet: snippets.ja_imm },
  { code: 'jset', label: 'jset_reg', description: 'jset dst, src, +off\n\nPC += off if dst & src', snippet: snippets.ja_reg },
  { code: 'jne', label: 'jne_imm', description: 'jne dst, imm, +off\n\nPC += off if dst != imm', snippet: snippets.ja_imm },
  { code: 'jne', label: 'jne_reg', description: 'jne dst, src, +off\n\nPC += off if dst != src', snippet: snippets.ja_reg },
  { code: 'jsgt', label: 'jsgt_imm', description: 'jsgt dst, imm, +off\n\nPC += off if dst > imm (signed)', snippet: snippets.ja_imm },
  { code: 'jsgt', label: 'jsgt_reg', description: 'jsgt dst, src, +off\n\nPC += off if dst > src (signed)', snippet: snippets.ja_reg },
  { code: 'jsge', label: 'jsge_imm', description: 'jsge dst, imm, +off\n\nPC += off if dst >= imm (signed)', snippet: snippets.ja_imm },
  { code: 'jsge', label: 'jsge_reg', description: 'jsge dst, src, +off\n\nPC += off if dst >= src (signed)', snippet: snippets.ja_reg },
  { code: 'jslt', label: 'jslt_imm', description: 'jslt dst, imm, +off\n\nPC += off if dst < imm (signed)', snippet: snippets.ja_imm },
  { code: 'jslt', label: 'jslt_reg', description: 'jslt dst, src, +off\n\nPC += off if dst < src (signed)', snippet: snippets.ja_reg },
  { code: 'jsle', label: 'jsle_imm', description: 'jsle dst, imm, +off\n\nPC += off if dst <= imm (signed)', snippet: snippets.ja_imm },
  { code: 'jsle', label: 'jsle_reg', description: 'jsle dst, src, +off\n\nPC += off if dst <= src (signed)', snippet: snippets.ja_reg },
  { code: 'call', label: 'call', description: 'call imm\n\nsyscall function call to syscall with key imm', snippet: snippets.call },
  { code: 'exit', label: 'exit', description: 'exit\n\nreturn r0', snippet: snippets.exit },
];

// Taken from: https://github.com/solana-labs/solana/blob/27eff8408b7223bb3c4ab70523f8a8dca3ca6645/sdk/program/src/syscalls/definitions.rs#L39
// Syscall descriptions taken from: https://web.archive.org/web/20231004144333/https://bpf.wtf/sol-0x04-syscalls/
// TODO: Check for updates from https://github.com/anza-xyz/agave/blob/master/sdk/program/src/syscalls/definitions.rs
let syscalls = [
  { label: 'abort', description: `panic!()\n\nAborts the VM with SyscallError::Abort and never returns.` },
  { label: 'sol_log_', description: `fn sol_log_(message: *const u8, len: u64)\n\nWrites a log entry to the Sealevel logging facility.` },
  { label: 'sol_log_64_', description: 'fn sol_log_64_(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64)\n\nWrites a log entry containing five 64-bit integers to the Sealevel logging facility.' },
  { label: 'sol_log_compute_units_', description: 'fn sol_log_compute_units_()\n\nWrites the current compute unit consumption to the Sealevel logging facility.' },
  { label: 'sol_log_pubkey', description: 'fn sol_log_pubkey(pubkey_addr: *const u8)\n\nWrites a log entry with a Base58-encoded Solana public key.' },
  { label: 'sol_create_program_address', description: 'fn sol_create_program_address(seeds_addr: *const u8, seeds_len: u64, program_id_addr: *const u8, address_bytes_addr: *const u8) -> u64)\n\nCalculates a program-derived address (PDA) from the given program ID and seed list.' },
  { label: 'sol_try_find_program_address', description: 'fn sol_try_find_program_address(seeds_addr: *const u8, seeds_len: u64, program_id_addr: *const u8, address_bytes_addr: *const u8, bump_seed_addr: *const u8) -> u64)\n\nCalculates a program-derived address (PDA) and bump seed from the given program ID and seed list.' },
  { label: 'sol_sha256', description: 'fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)\n\nCalculates the SHA-256 hash for the given byte inputs.' },
  { label: 'sol_keccak256', description: 'fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)\n\nCalculates the Keccak-256 hash for the given byte inputs.' },
  { label: 'sol_secp256k1_recover', description: 'fn sol_secp256k1_recover(hash: *const u8, recovery_id: u64, signature: *const u8, result: *mut u8) -> u64)\n\nRecovers a secp256k1 public key from a signed message.' },
  { label: 'sol_blake3', description: 'fn sol_blake3(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)\n\nCalculates the BLAKE3 hash for the given byte inputs.' },
  { label: 'sol_get_clock_sysvar', description: 'fn sol_get_clock_sysvar(addr: *mut u8) -> u64)\n\nWrites the clock sysvar to the pointer in r1.' },
  { label: 'sol_get_epoch_schedule_sysvar', description: 'fn sol_get_epoch_schedule_sysvar(addr: *mut u8) -> u64)\n\nWrites the epoch schedule sysvar to the pointer in r1.' },
  { label: 'sol_get_fees_sysvar', description: 'fn sol_get_fees_sysvar(addr: *mut u8) -> u64)\n\nWrites the fees sysvar to the pointer in r1.' },
  { label: 'sol_get_rent_sysvar', description: 'fn sol_get_rent_sysvar(addr: *mut u8) -> u64)\n\nWrites the rent sysvar to the pointer in r1.' },
  { label: 'sol_get_last_restart_slot', description: `fn sol_get_last_restart_slot(addr: *mut u8) -> u64)\n\nWrites the last restart slot to the pointer in r1` },
  { label: 'sol_memcpy_', description: 'fn sol_memcpy_(dst: *mut u8, src: *const u8, n: u64)\n\nCopies n bytes from memory area src to memory area dest. The memory areas must NOT overlap.' },
  { label: 'sol_memmove_', description: 'fn sol_memmove_(dst: *mut u8, src: *const u8, n: u64)\n\nCopies n bytes from memory area src to memory area dest. The memory areas may overlap.' },
  { label: 'sol_memcmp_', description: 'fn sol_memcmp_(s1: *const u8, s2: *const u8, n: u64, result: *mut i32\n\nCompares the first n bytes (each interpreted as unsigned char) of the memory areas s1 and s2.)' },
  { label: 'sol_memset_', description: 'fn sol_memset_(s: *mut u8, c: u8, n: u64)\n\nFills the first n bytes of the memory area pointed to by s with the constant byte c.' },
  { label: 'sol_invoke_signed_c', description: 'fn sol_invoke_signed_c(instruction_addr: *const u8, account_infos_addr: *const u8, account_infos_len: u64, signers_seeds_addr: *const u8, signers_seeds_len: u64) -> u64)\n\nExecutes a cross-program invocation (CPI) given a Sealevel instruction, account infos and a list of seed list to derive signers. Each seed list determines one PDA to set as a signer.' },
  { label: 'sol_invoke_signed_rust', description: 'fn sol_invoke_signed_rust(instruction_addr: *const u8, account_infos_addr: *const u8, account_infos_len: u64, signers_seeds_addr: *const u8, signers_seeds_len: u64) -> u64)\n\nExecutes a cross-program invocation (CPI) given a Sealevel instruction, account infos and a list of seed list to derive signers. Each seed list determines one PDA to set as a signer.' },
  { label: 'sol_set_return_data', description: 'fn sol_set_return_data(data: *const u8, length: u64)\n\nSets the return data of the current instruction. This data can be retrieved with sol_get_return_data in the parent instruction`s context.' },
  { label: 'sol_get_return_data', description: 'fn sol_get_return_data(data: *mut u8, length: u64, program_id: *mut Pubkey) -> u64)\n\nRetrieves the return data of the CPI that has last returned back to the current context.' },
  { label: 'sol_log_data', description: 'fn sol_log_data(data: *const u8, data_len: u64)\n\nWrites a log entry containing Base64-encoded to the Sealevel logging facility.' },
  { label: 'sol_get_processed_sibling_instruction', description: 'fn sol_get_processed_sibling_instruction(index: u64, meta: *mut ProcessedSiblingInstruction, program_id: *mut Pubkey, data: *mut u8, accounts: *mut AccountMeta) -> u64)\n\nCopies data of a processed sibling Sealevel instruction to memory. For transaction-level instructions, the list of sibling instructions are the programs that have been invoked previously in the same transaction. Otherwise, it is the list of CPIs that the parent instruction has executed.' },
  { label: 'sol_get_stack_height', description: 'fn sol_get_stack_height() -> u64)\n\nReturns the height of the Sealevel invocation stack, which is 1 at transaction level and increases for every cross-program invocation. Note that this is unrelated to the SBF call stack.' },
  { label: 'sol_curve_validate_point', description: 'fn sol_curve_validate_point(curve_id: u64, point_addr: *const u8, result: *mut u8) -> u64)\n\nValidates an elliptic curve point. Returns 0 if the point is valid, otherwise 1.' },
  { label: 'sol_curve_group_op', description: 'fn sol_curve_group_op(curve_id: u64, group_op: u64, left_input_addr: *const u8, right_input_addr: *const u8, result_point_addr: *mut u8) -> u64)\n\nProvides elliptic curve group operations. Returns 0 on success, otherwise 1.' },
  { label: 'sol_curve_multiscalar_mul', description: 'fn sol_curve_multiscalar_mul(curve_id: u64, scalars_addr: *const u8, points_addr: *const u8, points_len: u64, result_point_addr: *mut u8) -> u64)' }, //Needs Description
  { label: 'sol_curve_pairing_map', description: 'fn sol_curve_pairing_map(curve_id: u64, point: *const u8, result: *mut u8) -> u64)' }, //Needs Description
  { label: 'sol_alt_bn128_group_op', description: 'fn sol_alt_bn128_group_op(group_op: u64, input: *const u8, input_size: u64, result: *mut u8) -> u64)' }, //Needs Description
  { label: 'sol_big_mod_exp', description: `fn sol_big_mod_exp(params: *const u8, result: *mut u8) -> u64)\n\nPerforms Bignumber Modular Exponentiation. Takes in a pointer to BigModExpParams and writes output to a mutable pointer with length of modulus_len. BigModExpParams is defined as follows:
    
#[repr(C)]
pub struct BigModExpParams {
    pub base: *const u8,
    pub base_len: u64,
    pub exponent: *const u8,
    pub exponent_len: u64,
    pub modulus: *const u8,
    pub modulus_len: u64,
}` },
  { label: 'sol_get_epoch_rewards_sysvar', description: `fn sol_get_epoch_rewards_sysvar(addr: *mut u8) -> u64)
    
Writes EpochRewards to the pointer in r1. EpochRewards is defined as:

#[repr(C)]
pub struct EpochRewards {
    pub total_rewards: u64,
    pub distributed_rewards: u64,
    pub distribution_complete_block_height: u64,
}` },
  { label: 'sol_poseidon', description: 'fn sol_poseidon(parameters: u64, endianness: u64, vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64)' }, //Needs Description
  { label: 'sol_remaining_compute_units', description: 'fn sol_remaining_compute_units() -> u64)\n\nWrites remaining compute units to the pointer in r1' },
  { label: 'sol_alt_bn128_compression', description: 'fn sol_alt_bn128_compression(op: u64, input: *const u8, input_size: u64, result: *mut u8) -> u64)' }, //Needs Description
];

connection.onInitialize((params: InitializeParams) => {
  console.log('sBPF Language server initialized.');

  if (params.workspaceFolders && params.workspaceFolders.length > 0) {
    workspaceRoot = params.workspaceFolders[0].uri.replace("file://", "");
  }

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
  parseDocumentSymbols(e.document);
});

connection.onCompletion(
  (textDocumentPosition: TextDocumentPositionParams): CompletionItem[] => {
    const completions: CompletionItem[] = [];

    opcodes.forEach((opcode) => {
      completions.push({
        label: opcode.label,
        kind: CompletionItemKind.Snippet,
        insertText: [opcode.code, opcode.snippet].join(" ").trim(),
        insertTextFormat: InsertTextFormat.Snippet,
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

    const document = documents.get(textDocumentPosition.textDocument.uri);
    if (document) {
      const symbols = documentSymbols.get(document.uri) || [];
      symbols.forEach((symbol) => {
        completions.push({
          label: symbol.name,
          kind: symbol.type === SymbolType.EQU ? CompletionItemKind.Constant : CompletionItemKind.Reference,
          data: symbol.name,
          detail: symbol.type === SymbolType.EQU ? `Constant: ${symbol.value}` : `Label: ${symbol.value}`,
          documentation: symbol.description
        });
      });
    }

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

  if (item.data && typeof item.data === 'string') {
    for (const [uri, symbols] of documentSymbols.entries()) {
      const symbol = symbols.find(s => s.name === item.data);
      if (symbol) {
        item.detail = symbol.type === SymbolType.EQU ? `Constant: ${symbol.value}` : `Jump label`;
        item.documentation = symbol.description;
        return item;
      }
    }
  }

  return item;
});

connection.onHover((params) => {
  const document = documents.get(params.textDocument.uri);
  if (!document) { return null; }
  const position = params.position;

  const wordRange = getWordRangeAtPosition(document, position);
  const word = document.getText(wordRange);
  let header: string | null = null;

  const opcode = opcodes.find((o) => o.code === word);
  if (opcode) header = `**${opcode.label}**\n\n${opcode.description}`;

  const syscall = syscalls.find((s) => s.label === word);
  if (syscall) header = `**${syscall.label}**\n\n${syscall.description}`;

  const lineText = document.getText({
    start: { line: position.line, character: 0 },
    end: { line: position.line, character: Number.MAX_SAFE_INTEGER }
  });
  const extended = getInstructionHover(lineText);

  if (header || extended) {
    const parts: string[] = [];
    if (header) parts.push(header);
    if (extended) {
      const ext = extended.contents as any;
      const md = typeof ext === 'string' ? ext : (ext.value ?? '');
      if (md) parts.push(md);
    }
    return { contents: { kind: 'markdown', value: parts.join('\n\n') } } as Hover;
  }

  const symbols = documentSymbols.get(document.uri);
  if (symbols) {
    const symbol = symbols.find((s) => s.name === word);
    if (symbol) {
      return {
        contents: {
          kind: 'markdown',
          value: `**${symbol.name}**\n\n${symbol.description}\n\nValue: ${symbol.value}`
        }
      };
    }
  }

  return null;
});

function parseDocumentSymbols(document: TextDocument): void {
  const text = document.getText();
  const lines = text.split('\n');
  const symbols: Symbol[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Parse .equ directives.
    const equMatch = line.match(/^\.equ\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*(.+)$/);
    if (equMatch) {
      const name = equMatch[1];
      const value = equMatch[2].trim();
      symbols.push({
        name,
        value,
        type: SymbolType.EQU,
        line: i,
        description: `Constant definition`
      });
    }
    
    // Parse jump labels (i.e. identifiers followed by colon).
    const labelMatch = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*):\s*(?:$|#.*$)/);
    if (labelMatch) {
      const name = labelMatch[1];
      symbols.push({
        name,
        value: `jump target at line ${i + 1}`,
        type: SymbolType.LABEL,
        line: i,
        description: `Jump label`
      });
    }
  }

  documentSymbols.set(document.uri, symbols);
}

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

type ParsedInstruction = {
  opcode: string;
  variant?: string;
  dst?: number;
  src?: number;
  offset?: number | string;
  imm?: number | string;
  size?: 8 | 16 | 32 | 64;
};

function getInstructionHover(rawLine: string) {
  const parsed = parseInstruction(rawLine);
  if (!parsed) return null;

  const summary = describeInstruction(parsed);
  const meta = formatFields(parsed);
  if (!meta) return null;

  return {
    contents: {
      kind: 'markdown',
      value: `\n\`\`\`text\n${meta}\n\`\`\``
    }
  } as Hover;
}

function splitArgs(s: string): string[] {
  if (!s) return [];
  const out: string[] = [];
  let cur = '';
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '[') depth++;
    if (ch === ']') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function parseInstruction(line: string): ParsedInstruction | null {
  let l = line.replace(/\/\*.*?\*\//g, '').replace(/\/\/.*$/, '');
  l = l.replace(/^[A-Za-z_]\w*:\s*/, '').trim();
  if (!l) return null;

  const m = l.match(/^(\w+)\b\s*(.*)$/);
  if (!m) return null;
  const opcode = m[1].toLowerCase();
  const rest = (m[2] || '').trim();
  const args = splitArgs(rest);

  const regNum = (t: string) => {
    const rm = t.trim().match(/^r(\d{1,2})$/i);
    return rm ? Number(rm[1]) : undefined;
  };
  const parseNum = (t: string): number | undefined => {
    const s = t.trim();
    if (/^[+-]?0x[0-9a-f]+$/i.test(s)) return Number(BigInt(s));
    if (/^[+-]?\d+$/.test(s)) return Number(s);
    return undefined;
  };
  const parseOffset = (t: string): number | undefined => parseNum(t?.replace(/^\+/, ''));

  const mem = (t: string) => {
    const txt = t.trim();
    const mm = txt.match(/^\[\s*(r\d{1,2})\s*([+-])\s*([^\]]+)\s*\]$/i) || txt.match(/^\[\s*(r\d{1,2})\s*\+\s*([^\]]+)\s*\]$/i);
    if (!mm) return null;
    const base = regNum(mm[1])!;
    const sign = mm[2] === '-' ? -1 : 1;
    const offRaw = (mm[3] ?? '').trim();
    const offNum = parseNum(offRaw);
    const off = offNum !== undefined ? sign * offNum : undefined;
    const offSym = offNum === undefined ? (sign === -1 ? `-${offRaw}` : offRaw) : undefined;
    return { base, off, offSym } as { base: number; off?: number; offSym?: string };
  };

  const loadSize: Record<string, 8|16|32|64> = { ldxb:8, ldxh:16, ldxw:32, ldxdw:64 };
  const storeSize: Record<string, 8|16|32|64> = { stb:8, sth:16, stw:32, stdw:64, stxb:8, stxh:16, stxw:32, stxdw:64 };

  if (opcode in loadSize) {
    if (args.length === 2) {
      const dst = regNum(args[0]);
      const m1 = mem(args[1]);
      if (dst !== undefined && m1) {
        return { opcode, variant: 'mem', dst, src: m1.base, offset: (m1.off ?? m1.offSym), size: loadSize[opcode] };
      }
    }
    return null;
  }

  if (opcode in storeSize) {
    if (args.length === 2) {
      const m1 = mem(args[0]);
      if (!m1) return null;
      const srcReg = regNum(args[1]);
      const imm = parseNum(args[1]) ?? args[1].trim();
      const isReg = srcReg !== undefined && opcode.startsWith('stx');
      return {
        opcode,
        variant: isReg ? 'mem_reg' : 'mem_imm',
        dst: m1.base,
        src: isReg ? srcReg : undefined,
        imm: isReg ? undefined : imm,
        offset: (m1.off ?? m1.offSym),
        size: storeSize[opcode]
      };
    }
    return null;
  }

  if (opcode === 'lddw' && args.length === 2) {
    const dst = regNum(args[0]);
    const imm = parseNum(args[1]) ?? args[1].trim();
    if (dst !== undefined) return { opcode, variant: 'imm', dst, imm, size: 64 };
    return null;
  }

  if ((opcode === 'neg32' || opcode === 'neg64') && args.length === 1) {
    const dst = regNum(args[0]);
    if (dst !== undefined) return { opcode, variant: 'unary', dst };
    return null;
  }

  if ((/^mov(32|64)$/.test(opcode)) && args.length === 2) {
    const dst = regNum(args[0]);
    const src = regNum(args[1]);
    const imm = parseNum(args[1]) ?? args[1].trim();
    if (dst !== undefined) return { opcode, variant: src !== undefined ? 'reg' : 'imm', dst, src, imm };
    return null;
  }

  if ((opcode === 'be' || opcode === 'le') && args.length === 2) {
    const dst = regNum(args[0]);
    const imm = parseNum(args[1]) ?? args[1].trim();
    if (dst !== undefined) return { opcode, variant: 'imm', dst, imm };
    return null;
  }

  if (opcode === 'call' || opcode === 'callx') {
    if (args.length === 1) {
      const immOrReg = regNum(args[0]);
      const imm = parseNum(args[0]) ?? args[0].trim();
      return { opcode, variant: immOrReg !== undefined ? 'reg' : 'imm', src: immOrReg, imm };
    }
    return null;
  }
  if (opcode === 'exit' || opcode === 'return') {
    return { opcode, variant: 'none' };
  }

  const jops = ['ja','jeq','jgt','jge','jset','jne','jsgt','jsge','jlt','jle','jslt','jsle'];
  if (jops.includes(opcode)) {
    if (opcode === 'ja' && args.length === 1) {
      const off = parseOffset(args[0]);
      if (off !== undefined) return { opcode, variant: 'off', offset: off };
      return null;
    }
    if (args.length === 3) {
      const dst = regNum(args[0]);
      const srcReg = regNum(args[1]);
      const imm = parseNum(args[1]) ?? args[1].trim();
      const off = parseOffset(args[2]);
      if (dst !== undefined && off !== undefined) {
        return { opcode, variant: srcReg !== undefined ? 'reg' : 'imm', dst, src: srcReg, imm: srcReg !== undefined ? undefined : imm, offset: off };
      }
    }
    return null;
  }

  if (/^(add|sub|mul|div|sdiv|mod|smod|lsh|rsh|xor|or|and|arsh)(32|64)$/.test(opcode) && args.length === 2) {
    const dst = regNum(args[0]);
    const src = regNum(args[1]);
    const imm = parseNum(args[1]) ?? args[1].trim();
    if (dst !== undefined) return { opcode, variant: src !== undefined ? 'reg' : 'imm', dst, src, imm };
    return null;
  }

  if (opcode === 'hor64' && args.length === 2) {
    const dst = regNum(args[0]);
    const imm = parseNum(args[1]) ?? args[1].trim();
    if (dst !== undefined) return { opcode, variant: 'imm', dst, imm };
    return null;
  }

  return null;
}

function describeInstruction(p: ParsedInstruction): { title: string; text: string } | null {
  const jmap: Record<string,string> = {
    jeq: '==', jne: '!=', jgt: '>', jge: '>=', jlt: '<', jle: '<=',
    jsgt: '>(signed)', jsge: '>=(signed)', jslt: '<(signed)', jsle: '<=(signed)'
  };
  if (p.opcode === 'ja' && typeof p.offset === 'number') {
    const dir = p.offset >= 0 ? 'forward' : 'back';
    return { title: 'ja (jump)', text: `Jump ${dir} ${Math.abs(p.offset)} instructions` };
  }
  if (p.opcode in jmap && p.dst !== undefined && typeof p.offset === 'number') {
    const cmp = jmap[p.opcode];
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    const dir = p.offset >= 0 ? 'forward' : 'back';
    return { title: `${p.opcode} (conditional jump)`, text: `If r${p.dst} ${cmp} ${rhs}, jump ${dir} ${Math.abs(p.offset)} instructions` };
  }
  if (p.opcode === 'jset' && p.dst !== undefined && typeof p.offset === 'number') {
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    const dir = p.offset >= 0 ? 'forward' : 'back';
    return { title: 'jset (bit test jump)', text: `If (r${p.dst} & ${rhs}) != 0, jump ${dir} ${Math.abs(p.offset)} instructions` };
  }

  const sizes: Record<number,string> = { 8:'u8', 16:'u16', 32:'u32', 64:'u64' };
  if (/^ldx[bhwd]w?$|^ldxdw$/.test(p.opcode) && p.dst !== undefined && p.src !== undefined) {
    const typ = sizes[p.size!];
    const off = p.offset !== undefined ? ` + ${typeof p.offset === 'number' ? formatNum(p.offset) : p.offset}` : '';
    return { title: `${p.opcode} (load)`, text: `r${p.dst} = [r${p.src}${off}] as ${typ}` };
  }
  if (/^st[bhwd]$/.test(p.opcode) && p.dst !== undefined) {
    const typ = sizes[p.size!];
    const off = p.offset !== undefined ? ` + ${typeof p.offset === 'number' ? formatNum(p.offset) : p.offset}` : '';
    return { title: `${p.opcode} (store imm)`, text: `[r${p.dst}${off}] as ${typ} = ${p.imm}` };
  }
  if (/^stx[bhwd]$/.test(p.opcode) && p.dst !== undefined && p.src !== undefined) {
    const typ = sizes[p.size!];
    const off = p.offset !== undefined ? ` + ${typeof p.offset === 'number' ? formatNum(p.offset) : p.offset}` : '';
    return { title: `${p.opcode} (store reg)`, text: `[r${p.dst}${off}] as ${typ} = r${p.src}` };
  }
  if (p.opcode === 'lddw' && p.dst !== undefined) {
    return { title: 'lddw (load 64-bit imm)', text: `r${p.dst} = ${p.imm}` };
  }

  const sym: Record<string,string> = {
    add: '+=', sub: '-=', mul: '*=', div: '/=', sdiv: '/=', mod: '%=', smod: '%=',
    lsh: '<<=', rsh: '>>=', arsh: '>>= (arith)', xor: '^=', or: '|=', and: '&='
  };
  const alu = p.opcode.match(/^(add|sub|mul|div|sdiv|mod|smod|lsh|rsh|xor|or|and|arsh)(32|64)$/);
  if (alu && p.dst !== undefined) {
    const s = sym[alu[1]];
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    return { title: `${p.opcode} (ALU)`, text: `r${p.dst} ${s} ${rhs}` };
  }
  if ((p.opcode === 'mov32' || p.opcode === 'mov64') && p.dst !== undefined) {
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    return { title: `${p.opcode} (move)`, text: `r${p.dst} = ${rhs}` };
  }
  if ((p.opcode === 'neg32' || p.opcode === 'neg64') && p.dst !== undefined) {
    return { title: `${p.opcode} (negate)`, text: `r${p.dst} = -r${p.dst}` };
  }
  if (p.opcode === 'hor64' && p.dst !== undefined) {
    return { title: 'hor64 (hi-or)', text: `r${p.dst} |= (${p.imm}) << 32` };
  }

  if ((p.opcode === 'be' || p.opcode === 'le') && p.dst !== undefined) {
    return { title: `${p.opcode} (byte swap)`, text: `r${p.dst} = ${p.opcode}(${p.imm})` };
  }

  if (p.opcode === 'call' || p.opcode === 'callx') {
    const target = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    return { title: `${p.opcode} (call)`, text: `Call ${target}` };
  }
  if (p.opcode === 'exit' || p.opcode === 'return') {
    return { title: 'exit', text: 'Return r0' };
  }

  return null;
}

function formatFields(p: ParsedInstruction): string {
  let opcode: string;
  if (p.opcode.startsWith('j')) {
    opcode = jumpVariant(p);
  } else if (/^(add|sub|mul|div|sdiv|mod|smod|lsh|rsh|xor|or|and|arsh)/.test(p.opcode)) {
    opcode = `${p.opcode}_${p.variant}`;
  } else {
    opcode = p.opcode;
  }
  const kv: string[] = [
    `opcode=${opcode}`,
    `dst=${p.dst ?? 'unused'}`,
    `src=${p.src ?? 'unused'}`,
    `offset=${p.offset ?? 'unused'}`,
    `imm=${p.imm ?? 'unused'}`
  ];
  return kv.join(', ');
}

function jumpVariant(p: ParsedInstruction): string {
  const base = p.opcode === 'ja' ? 'jump' : `jump_${({
    jeq: 'eq', jne: 'ne', jgt: 'gt', jge: 'ge', jlt: 'lt', jle: 'le',
    jsgt: 'sgt', jsge: 'sge', jslt: 'slt', jsle: 'sle', jset: 'set'
  } as any)[p.opcode]}`;
  if (p.opcode === 'ja') return base;
  return `${base}_${p.variant === 'reg' ? 'reg' : 'imm'}`;
}

function formatNum(n: number): string {
  return (n < 0 ? '-' : '') + '0x' + Math.abs(n).toString(16);
}

// Listen for document changes
documents.onDidChangeContent((change) => {
  parseDocumentSymbols(change.document);
  validateTextDocument(change.document);
  validateBuild(change.document);
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

// Listen for document save
documents.onDidSave((event) => {
  parseDocumentSymbols(event.document);
  validateBuild(event.document);
});

async function validateBuild(document: TextDocument): Promise<void> {
  if (validateBuildTimer) {
    clearTimeout(validateBuildTimer);
  }

  validateBuildTimer = setTimeout(async () => {
    const diagnostics: Diagnostic[] = [];

    try {
      if (!workspaceRoot) {
        console.warn("No workspace root found");
        return;
      }

      const { stderr } = await execPromise("sbpf build", {
        cwd: workspaceRoot,
      }).catch((error) => error);
      const lines = stderr.split("\n");
      for (let i = 0; i < lines.length - 1; i++) {
        const line = lines[i];
        
        // Match error message.
        const errorMatch = line.match(/^error: (.+)$/);
        if (errorMatch) {
          let message = errorMatch[1];
          
          // Match location.
          const locationMatch = lines[i + 1]?.match(/┌─ (.+):(\d+):(\d+)$/);
          if (locationMatch) {
            const [_, file, lineStr, colStr] = locationMatch;
            const lineNum = parseInt(lineStr) - 1;
            const col = parseInt(colStr) - 1;

            // Match additional error details.
            for (let j = i + 2; j < lines.length; j++) {
              const detailMatch = lines[j]?.match(/\^+\s*(.+)$/);
              if (detailMatch) {
                message += '\n\n' + detailMatch[1];
                break;
              }
            }

            if (document.uri.endsWith(file)) {
              const position = Position.create(lineNum, col);
              const range = getWordRangeAtPosition(document, position);

              diagnostics.push({
                severity: DiagnosticSeverity.Error,
                range,
                message,
                source: "solana-ebpf",
                code: "build-error",
              });
            }
          }
        }
      }
    } catch (error) {
      // Ignore error
    }

    connection.sendDiagnostics({ uri: document.uri, diagnostics });
  }, VALIDATE_BUILD_DEBOUNCE_MS);
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