import path from 'path';
import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind
} from 'vscode-languageclient/node';

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
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
