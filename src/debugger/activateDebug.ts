import * as vscode from "vscode";
import { ProviderResult } from "vscode";
import { SbpfDebugSession } from "./sbpfDebugSession";

export function activateDebug(
  context: vscode.ExtensionContext,
  factory?: vscode.DebugAdapterDescriptorFactory,
) {
  // Register a configuration provider for 'sbpf' debug type
  const provider = new SbpfConfigurationProvider();
  context.subscriptions.push(
    vscode.debug.registerDebugConfigurationProvider("sbpf", provider),
  );

  // Register the debug adapter descriptor factory
  if (!factory) {
    factory = new InlineDebugAdapterFactory();
  }
  context.subscriptions.push(
    vscode.debug.registerDebugAdapterDescriptorFactory("sbpf", factory),
  );
  if ("dispose" in factory) {
    context.subscriptions.push(factory as vscode.Disposable);
  }
}

/**
 * Configuration provider that resolves debug configurations
 * before a debug session is started.
 */
class SbpfConfigurationProvider implements vscode.DebugConfigurationProvider {
  resolveDebugConfiguration(
    folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
    token?: vscode.CancellationToken,
  ): ProviderResult<vscode.DebugConfiguration> {
    // Create a default configuration if launch.json is missing or empty.
    if (!config.type && !config.request && !config.name) {
      const editor = vscode.window.activeTextEditor;
      if (editor && editor.document.languageId === "sbpf-asm") {
        config.type = "sbpf";
        config.name = "Debug";
        config.request = "launch";
        config.program = "${file}";
        config.stopOnEntry = true;
      }
    }

    if (!config.program) {
      return vscode.window
        .showInformationMessage("Cannot find a program to debug")
        .then(() => {
          return undefined; // abort launch
        });
    }

    return config;
  }
}

/**
 * Factory to create an inline debug adapter.
 * This runs the debug adapter in the same process as the extension.
 */
class InlineDebugAdapterFactory
  implements vscode.DebugAdapterDescriptorFactory
{
  createDebugAdapterDescriptor(
    _session: vscode.DebugSession,
  ): ProviderResult<vscode.DebugAdapterDescriptor> {
    return new vscode.DebugAdapterInlineImplementation(new SbpfDebugSession());
  }
}
