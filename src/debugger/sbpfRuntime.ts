import { EventEmitter } from "events";
import { spawn, ChildProcess } from "child_process";
import * as vscode from "vscode";

let nextRequestId = 1;

export interface ISbpfBreakpoint {
  id?: number;
  line: number;
  verified: boolean;
  file?: string;
  error?: string;
}

export interface ISbpfStackFrame {
  index: number;
  name: string;
  file: string;
  line: number;
  column: number;
  instruction?: number;
}

export interface ISbpfVariable {
  name: string;
  value: string;
  address?: string;
  type?: string;
}

export interface ISbpfRegister {
  name: string;
  value: string;
  type: string;
}

export interface ISbpfMemoryRegion {
  address: number;
  size: number;
  data: number[];
}

export interface ISbpfDebugInfo {
  hasDwarf: boolean;
  sourceFiles: string[];
  functions: Array<{ name: string; address: number }>;
}

export interface ISbpfLaunchConfig {
  program: string;
  input?: object;
  computeUnitLimit?: number;
  maxCallDepth?: number;
  heapSize?: number;
  stopOnEntry?: boolean;
}

export interface ISbpfCommand {
  command: string;
  args?: unknown[];
  requestId?: number;
}

export interface ISbpfResponse {
  success: boolean;
  data?: unknown;
  error?: string;
  requestId?: number;
}

export interface ISbpfStepEvent {
  type: "next" | "breakpoint" | "exit" | "error";
  pc?: number;
  line?: number | null;
  code?: number;
  message?: string;
  compute_units?: {
    total: number;
    used: number;
    remaining: number;
  };
}

export class SbpfRuntime extends EventEmitter {
  private debuggerProcess: ChildProcess | undefined;
  private pendingRequests: Map<number, (resp: ISbpfResponse) => void> =
    new Map();
  private buffer = "";
  private _breakpointQueue: (() => Promise<void>)[] = [];
  private _backendReady: boolean = false;

  constructor() {
    super();
  }

  private isElfFile(program: string): boolean {
    const lowerProgram = program.toLowerCase();
    return (
      lowerProgram.endsWith(".so") ||
      lowerProgram.endsWith(".o") ||
      lowerProgram.endsWith(".elf")
    );
  }

  public async start(config: ISbpfLaunchConfig): Promise<void> {
    return new Promise((resolve, reject) => {
      // Get the sbpf CLI path from configuration
      const sbpfConfig = vscode.workspace.getConfiguration("sbpf-asm");
      const sbpfPath = sbpfConfig.get<string>("sbpfPath", "sbpf");

      // Build command arguments for `sbpf debug`
      const args: string[] = ["debug"];

      // Add file argument based on type
      if (this.isElfFile(config.program)) {
        args.push("--elf", config.program);
      } else {
        args.push("--asm", config.program);
      }

      // Add input
      if (config.input) {
        args.push("--input", JSON.stringify(config.input));
      }

      // Add compute unit limit
      if (config.computeUnitLimit !== undefined) {
        args.push("--compute-unit-limit", config.computeUnitLimit.toString());
      }

      // Add max call depth
      if (config.maxCallDepth !== undefined) {
        args.push("--max-call-depth", config.maxCallDepth.toString());
      }

      // Add heap size
      if (config.heapSize !== undefined) {
        args.push("--heap-size", config.heapSize.toString());
      }

      // Enable adapter mode for DAP
      args.push("--adapter");

      this.debuggerProcess = spawn(sbpfPath, args, {
        stdio: ["pipe", "pipe", "pipe"],
      });

      if (!this.debuggerProcess.stdout || !this.debuggerProcess.stdin) {
        reject(new Error("Failed to create debugger process"));
        return;
      }

      this.debuggerProcess.stdout.on("data", (data) => {
        this.handleDebuggerOutput(data.toString());
      });

      this.debuggerProcess.stderr?.on("data", (data) => {
        const errorMsg = data.toString().trim();
        if (errorMsg) {
          this.emit("output", "stderr", errorMsg);
        }
      });

      this.debuggerProcess.on("close", (code) => {
        if (typeof code === "number" && code !== 0) {
          this.emit(
            "error",
            new Error(`Debugger process exited with code ${code}`),
          );
        }
        this.emit("exit");
      });

      this.debuggerProcess.on("error", (error) => {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          this.emit(
            "error",
            new Error(
              `Could not find sbpf CLI at '${sbpfPath}'. ` +
                `Please ensure sbpf is installed and available in PATH, ` +
                `or configure the path in settings (sbpf-asm.sbpfPath).`,
            ),
          );
        } else {
          this.emit("error", error);
        }
      });

      // Wait for backend to be ready
      setTimeout(async () => {
        if (config.stopOnEntry) {
          this.emit("entry");
        } else {
          this.continue();
        }
        this._backendReady = true;

        // Flush queued breakpoint operations
        for (const op of this._breakpointQueue) {
          await op();
        }
        this._breakpointQueue = [];
        resolve();
      }, 1000);
    });
  }

  private handleDebuggerOutput(output: string): void {
    this.buffer += output;
    let newlineIdx;
    while ((newlineIdx = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, newlineIdx).trim();
      this.buffer = this.buffer.slice(newlineIdx + 1);
      if (!line) {
        continue;
      }

      // Handle program log messages
      if (line.startsWith("Program log:")) {
        const logMsg = line.trim();
        this.emit("output", "stdout", logMsg);
        continue;
      }

      // Handle error messages from the backend
      if (line.startsWith("error:")) {
        const errorMsg = line.substring(6).trim();
        this.emit("error", new Error(`Runtime error: ${errorMsg}`));
        this.emit("output", "stderr", errorMsg);
        continue;
      }

      let response: ISbpfResponse;
      try {
        response = JSON.parse(line);
      } catch {
        continue;
      }

      // Check for error responses from the backend
      if (response.success === false) {
        const errorMsg =
          response.error || "Unknown error from debugger backend";
        this.emit("error", new Error(errorMsg));
        continue;
      }

      // Check for exit/error events in the response data
      if (response.data && typeof response.data === "object") {
        const data = response.data as ISbpfStepEvent;
        if (data.type === "exit") {
          this.emit(
            "output",
            "stdout",
            `Program exited with code: ${data.code}`,
          );
          // Log compute units usage
          if (data.compute_units) {
            this.emit(
              "output",
              "stdout",
              `Program consumed ${data.compute_units.used} of ${data.compute_units.total} compute units`,
            );
          }
          this.emit("exit");
        } else if (data.type === "error") {
          const errorMsg = data.message || "Runtime error occurred";
          this.emit("error", new Error(errorMsg));
        }
      }

      if (response.requestId && this.pendingRequests.has(response.requestId)) {
        const cb = this.pendingRequests.get(response.requestId)!;
        this.pendingRequests.delete(response.requestId);
        cb(response);
      } else {
        this.emit("event", response);
      }
    }
  }

  private sendCommand(cmd: ISbpfCommand): Promise<ISbpfResponse> {
    if (!this.debuggerProcess || !this.debuggerProcess.stdin) {
      return Promise.reject(new Error("Debugger not connected"));
    }
    const requestId = nextRequestId++;
    cmd.requestId = requestId;
    const commandStr = JSON.stringify(cmd) + "\n";
    return new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, (response) => {
        if (response.success === false) {
          reject(new Error(response.error || "Command failed"));
        } else {
          resolve(response);
        }
      });
      this.debuggerProcess!.stdin!.write(commandStr);
    });
  }

  public async continue(): Promise<ISbpfStepEvent> {
    const resp = await this.sendCommand({ command: "continue" });
    return resp.data as ISbpfStepEvent;
  }

  public async next(): Promise<ISbpfStepEvent> {
    const resp = await this.sendCommand({ command: "next" });
    return resp.data as ISbpfStepEvent;
  }

  public async clearBreakpoints(file: string): Promise<void> {
    if (!this._backendReady) {
      this._breakpointQueue.push(() => this.clearBreakpoints(file));
      return;
    }
    await this.sendCommand({ command: "clearBreakpoints", args: [file] });
  }

  public async setBreakpoint(
    file: string,
    line: number,
  ): Promise<ISbpfBreakpoint> {
    if (!this._backendReady) {
      return new Promise((resolve, reject) => {
        this._breakpointQueue.push(async () => {
          try {
            const result = await this.setBreakpoint(file, line);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      });
    }
    const resp = await this.sendCommand({
      command: "setBreakpoint",
      args: [file, line],
    });
    if (resp.success && resp.data) {
      const data = resp.data as {
        type: string;
        file: string;
        line: number;
        verified: boolean;
        error?: string;
      };
      return {
        line: data.line,
        verified: data.verified,
        file: data.file,
        error: data.error,
      };
    }
    throw new Error(resp.error || "Failed to set breakpoint");
  }

  public async removeBreakpoint(file: string, line: number): Promise<void> {
    if (!this._backendReady) {
      this._breakpointQueue.push(() => this.removeBreakpoint(file, line));
      return;
    }
    await this.sendCommand({ command: "removeBreakpoint", args: [file, line] });
  }

  public async getStackFrames(): Promise<ISbpfStackFrame[]> {
    const resp = await this.sendCommand({ command: "getStackFrames" });
    if (resp.success && resp.data) {
      const data = resp.data as { frames: ISbpfStackFrame[] };
      return data.frames || [];
    }
    return [];
  }

  public async getRegisters(): Promise<ISbpfRegister[]> {
    const resp = await this.sendCommand({ command: "getRegisters" });
    if (resp.success && resp.data) {
      const data = resp.data as { registers: ISbpfRegister[] };
      return data.registers || [];
    }
    return [];
  }

  public async getRodata(): Promise<ISbpfVariable[]> {
    const resp = await this.sendCommand({ command: "getRodata" });
    if (resp.success && resp.data) {
      const data = resp.data as {
        rodata: Array<{ name: string; address: string; value: string }>;
      };
      // Map the backend format to ISbpfVariable
      return (data.rodata || []).map((item) => ({
        name: item.name,
        value: item.value,
        address: item.address,
      }));
    }
    return [];
  }

  public async getMemory(
    address: number,
    size: number,
  ): Promise<ISbpfMemoryRegion> {
    const resp = await this.sendCommand({
      command: "getMemory",
      args: [address, size],
    });
    if (resp.success && resp.data) {
      return resp.data as ISbpfMemoryRegion;
    }
    throw new Error(resp.error || "Failed to get memory");
  }

  public async setRegister(index: number, value: number): Promise<void> {
    const resp = await this.sendCommand({
      command: "setRegister",
      args: [index, value],
    });
    if (resp.success && resp.data) {
      const data = resp.data as { success: boolean; error?: string };
      if (!data.success) {
        throw new Error(data.error || "Failed to set register");
      }
    }
  }

  public async getComputeUnits(): Promise<{
    total: number;
    used: number;
    remaining: number;
  }> {
    const resp = await this.sendCommand({ command: "getComputeUnits" });
    if (resp.success && resp.data) {
      const d = resp.data as { total: number; used: number; remaining: number };
      return {
        total: typeof d.total === "number" ? d.total : 0,
        used: typeof d.used === "number" ? d.used : 0,
        remaining: typeof d.remaining === "number" ? d.remaining : 0,
      };
    }
    return { total: 0, used: 0, remaining: 0 };
  }

  public async shutdown(): Promise<void> {
    if (this.debuggerProcess) {
      try {
        await this.sendCommand({ command: "quit" });
      } catch {
        // Ignore errors during shutdown
      }
      this.debuggerProcess.kill();
      this.debuggerProcess = undefined;
    }
  }
}
