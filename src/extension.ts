import path from 'path';
import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind
} from 'vscode-languageclient/node';
/* eslint-disable curly */

let client: LanguageClient;

export function activate(context: vscode.ExtensionContext) {
  // Server executable (we'll use the extension itself as the server)
  let serverModule = context.asAbsolutePath(path.join('out', 'server.js'));
  let debugOptions = { execArgv: ['--nolazy', '--inspect=6009'] };

  // Server options
  let serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: { module: serverModule, transport: TransportKind.ipc, options: debugOptions }
  };

  // Client options
  let clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: 'file', language: 'sbpf-asm' }],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher('**/.clientrc')
    }
  };

  // Create the language client and start the client.
  client = new LanguageClient(
    'sbpfLanguageServer',
    'sBPF Assembly Language Server',
    serverOptions,
    clientOptions
  );

  client.start();

  // Highlight the current line and append an end-of-line explanation for sbpf-asm documents
  const activeLineDecoration = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    backgroundColor: new vscode.ThemeColor('editor.hoverHighlightBackground'),
  });
  context.subscriptions.push(activeLineDecoration);

  const eolInfoDecoration = vscode.window.createTextEditorDecorationType({
    after: {
      color: new vscode.ThemeColor('editorGhostText.foreground'),
      margin: '  1rem',
    },
    rangeBehavior: vscode.DecorationRangeBehavior.ClosedOpen,
  });
  context.subscriptions.push(eolInfoDecoration);

  let debounceTimer: NodeJS.Timeout | undefined;

  function scheduleUpdate(editor?: vscode.TextEditor) {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => updateDecorations(editor ?? vscode.window.activeTextEditor), 60);
  }

  function updateDecorations(editor?: vscode.TextEditor) {
    if (!editor || editor.document.languageId !== 'sbpf-asm') {
      return;
    }

    const cfg = vscode.workspace.getConfiguration('sbpf-asm');
    const showEol = cfg.get<boolean>('showEolInfo', true);

    // Highlight current line
    const sel = editor.selection.active;
    const activeRange = new vscode.Range(sel.line, 0, sel.line, 0);
    editor.setDecorations(activeLineDecoration, [activeRange]);

    // End-of-line explanation for current line
    const lineText = editor.document.lineAt(sel.line).text;
    const parsed = parseInstruction(lineText);
    const decoOptions: vscode.DecorationOptions[] = [];

    if (parsed && showEol) {
      const summary = describeInstruction(parsed);
      const meta = formatFields(parsed);
      const parts: string[] = [];
      if (summary) {
        parts.push(`# ${summary.text}`);
      }
      if (meta) parts.push(`; ${meta}`);
      const content = parts.join('    ');
      if (content) {
        decoOptions.push({
          range: new vscode.Range(sel.line, lineText.length, sel.line, lineText.length),
          renderOptions: { after: { contentText: '  ' + content } },
        });
      }
    }

    editor.setDecorations(eolInfoDecoration, decoOptions);
  }

  function onEditorChanged(editor?: vscode.TextEditor) {
    if (!editor || editor.document.languageId !== 'sbpf-asm') {
      return;
    }
    scheduleUpdate(editor);
  }

  function onDocChanged(e: vscode.TextDocumentChangeEvent) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== e.document) return;
    if (editor.document.languageId !== 'sbpf-asm') return;
    scheduleUpdate(editor);
  }

  updateDecorations(vscode.window.activeTextEditor);
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(onEditorChanged),
    vscode.window.onDidChangeTextEditorSelection(e => onEditorChanged(e.textEditor)),
    vscode.workspace.onDidChangeTextDocument(onDocChanged),
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('sbpf-asm.showEolInfo')) {
        updateDecorations(vscode.window.activeTextEditor);
      }
    }),
  );
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
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
  const parseNum = (t: string): number | string | undefined => {
    const s = t.trim();
    const toDecString = (bi: bigint): string => bi.toString(10);
    if (/^[+-]?0x[0-9a-f]+$/i.test(s)) {
      const bi = BigInt(s);
      const abi = bi < 0n ? -bi : bi;
      if (abi <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(bi);
      return toDecString(bi);
    }
    if (/^[+-]?\d+$/.test(s)) {
      const bi = BigInt(s);
      const abi = bi < 0n ? -bi : bi;
      if (abi <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(bi);
      return toDecString(bi);
    }
    return undefined;
  };
  const parseOffset = (t: string): number | undefined => {
    const v = parseNum(t?.replace(/^\+/, ''));
    return typeof v === 'number' ? v : undefined;
  };

  const mem = (t: string) => {
    const txt = t.trim();
    const mm = txt.match(/^\[\s*(r\d{1,2})\s*([+-])\s*([^\]]+)\s*\]$/i) || txt.match(/^\[\s*(r\d{1,2})\s*\+\s*([^\]]+)\s*\]$/i);
    if (!mm) return null;
    const base = regNum(mm[1])!;
    const sign = mm[2] === '-' ? -1 : 1;
    const offRaw = (mm[3] ?? '').trim();
    const offParsed = parseNum(offRaw);
    const offNum = typeof offParsed === 'number' ? offParsed : undefined;
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
    if (dst !== undefined) return { opcode, variant: src !== undefined ? 'reg' : 'imm',  dst, src, imm: src !== undefined ? undefined : imm };
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
    if (dst !== undefined) return { opcode, variant: src !== undefined ? 'reg' : 'imm', dst, src, imm: src !== undefined ? undefined : imm };
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
    return { title: 'ja', text: `Jump ${dir} ${Math.abs(p.offset)} instructions unconditionally` };
  }
  if (p.opcode in jmap && p.dst !== undefined && p.offset !== undefined) {
    const cmp = jmap[p.opcode];
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    const offNum = typeof p.offset === 'number' ? p.offset : 0;
    const dir = offNum >= 0 ? 'forward' : 'back';
    return { title: p.opcode, text: `If r${p.dst} ${cmp} ${rhs}, jump ${dir} ${Math.abs(offNum)} instructions` };
  }
  if (p.opcode === 'jset' && p.dst !== undefined && p.offset !== undefined) {
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    const offNum = typeof p.offset === 'number' ? p.offset : 0;
    const dir = offNum >= 0 ? 'forward' : 'back';
    return { title: 'jset', text: `If (r${p.dst} & ${rhs}) != 0, jump ${dir} ${Math.abs(offNum)} instructions` };
  }

  const sizes: Record<number,string> = { 8:'8', 16:'16', 32:'32', 64:'64' };
  if (/^ldx[bhwd]w?$|^ldxdw$/.test(p.opcode) && p.dst !== undefined && p.src !== undefined) {
    const off = (() => {
      if (p.offset === undefined) return '';
      if (typeof p.offset === 'number') {
        return p.offset >= 0 ? `+ ${p.offset}` : `- ${Math.abs(p.offset)}`;
      }
      const s = p.offset.toString();
      return s.startsWith('-') ? `- ${s.slice(1)}` : `+ ${s}`;
    })();
    return { title: p.opcode, text: `Load ${sizes[p.size!]} bits from [r${p.src} ${off}] into r${p.dst}` };
  }
  if (/^st(?:b|h|w|dw)$/.test(p.opcode) && p.dst !== undefined) {
    const off = (() => {
      if (p.offset === undefined) return '';
      if (typeof p.offset === 'number') {
        return p.offset >= 0 ? `+ ${p.offset}` : `- ${Math.abs(p.offset)}`;
      }
      const s = p.offset.toString();
      return s.startsWith('-') ? `- ${s.slice(1)}` : `+ ${s}`;
    })();
    return { title: p.opcode, text: `Store ${typeof p.imm === 'undefined' ? 'imm' : p.imm} to memory at [r${p.dst} ${off}]`};
  }
  if (/^stx(?:b|h|w|dw)$/.test(p.opcode) && p.dst !== undefined && p.src !== undefined) {
    const off = (() => {
      if (p.offset === undefined) return '';
      if (typeof p.offset === 'number') {
        return p.offset >= 0 ? `+ ${p.offset}` : `- ${Math.abs(p.offset)}`;
      }
      const s = p.offset.toString();
      return s.startsWith('-') ? `- ${s.slice(1)}` : `+ ${s}`;
    })();
    return { title: p.opcode, text: `Store r${p.src} to memory at [r${p.dst} ${off}]` };
  }
  if (p.opcode === 'lddw' && p.dst !== undefined) {
    return { title: 'lddw', text: `Put immediate value ${p.imm} into r${p.dst}` };
  }

  const sym: Record<string,string> = {
    add: 'r{dst} = r{dst} + {rhs}',
    sub: 'r{dst} = r{dst} - {rhs}',
    mul: 'r{dst} = r{dst} * {rhs}',
    div: 'r{dst} = r{dst} / {rhs}',
    sdiv: 'r{dst} = r{dst} / {rhs}',
    mod: 'r{dst} = r{dst} % {rhs}',
    smod: 'r{dst} = r{dst} % {rhs}',
    lsh: 'r{dst} = r{dst} << {rhs}',
    rsh: 'r{dst} = r{dst} >> {rhs}',
    arsh: 'r{dst} = r{dst} >> (arith) {rhs}',
    xor: 'r{dst} = r{dst} ^ {rhs}',
    or: 'r{dst} = r{dst} | {rhs}',
    and: 'r{dst} = r{dst} & {rhs}',
  };
  const alu = p.opcode.match(/^(add|sub|mul|div|sdiv|mod|smod|lsh|rsh|xor|or|and|arsh)(32|64)$/);
  if (alu && p.dst !== undefined) {
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    const text = sym[alu[1]].replaceAll('{dst}', String(p.dst)).replace('{rhs}', rhs);
    return { title: p.opcode, text };
  }
  if ((p.opcode === 'mov32' || p.opcode === 'mov64') && p.dst !== undefined) {
    if (p.variant === 'imm') {
      return { title: p.opcode, text: `Put immediate value ${p.imm} into r${p.dst}` };
    }
    const rhs = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    return { title: p.opcode, text: `Move ${rhs} into r${p.dst}` };
  }
  if ((p.opcode === 'neg32' || p.opcode === 'neg64') && p.dst !== undefined) {
    return { title: p.opcode, text: `r${p.dst} = -r${p.dst}` };
  }
  if ((p.opcode === 'be' || p.opcode === 'le') && p.dst !== undefined) {
    return { title: p.opcode, text: `Byte swap ${p.imm} bits of r${p.dst}` };
  }
  if (p.opcode === 'hor64' && p.dst !== undefined) {
    return { title: 'hor64', text: `r${p.dst} |= (${p.imm}) << 32` };
  }
  if (p.opcode === 'call' || p.opcode === 'callx') {
    const target = p.variant === 'reg' ? `r${p.src}` : `${p.imm}`;
    return { title: p.opcode, text: `Call ${target}` };
  }
  if (p.opcode === 'exit' || p.opcode === 'return') {
    return { title: 'exit', text: 'Return r0' };
  }

  return null;
}

function jumpVariant(p: ParsedInstruction): string {
  const base = p.opcode === 'ja' ? 'jump' : `jump_${({
    jeq: 'eq', jne: 'ne', jgt: 'gt', jge: 'ge', jlt: 'lt', jle: 'le',
    jsgt: 'sgt', jsge: 'sge', jslt: 'slt', jsle: 'sle', jset: 'set'
  } as any)[p.opcode]}`;
  if (p.opcode === 'ja') return base;
  return `${base}_${p.variant === 'reg' ? 'reg' : 'imm'}`;
}

function formatFields(p: ParsedInstruction): string {
  let opcode: string;
  if (p.opcode.startsWith('j')) {
    opcode = jumpVariant(p);
  } else if (/^(add|sub|mul|div|sdiv|mod|smod|lsh|rsh|xor|or|and|arsh)/.test(p.opcode)) {
    opcode = `${p.opcode.replace(/(32|64)$/,'')}_${p.variant}`;
  } else if (p.opcode.startsWith('ldx')) {
    opcode = `load${p.size}`;
  } else if (p.opcode.startsWith('stx')) {
    opcode = `store${p.size}`;
  } else if (p.opcode.startsWith('st')) {
    opcode = `store${p.size}`;
  } else if (p.opcode.startsWith('ldd')) {
    opcode = 'load64';
  } else if (p.opcode.startsWith('mov')) {
    opcode = `move_${p.variant}`;
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
