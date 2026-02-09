import {
  LoggingDebugSession,
  InitializedEvent,
  StoppedEvent,
  TerminatedEvent,
  StackFrame,
  Breakpoint,
  Source,
  Thread,
  OutputEvent,
  Scope,
  Handles,
} from "@vscode/debugadapter";
import { DebugProtocol } from "@vscode/debugprotocol";
import { SbpfRuntime, ISbpfLaunchConfig } from "./sbpfRuntime";

/**
 * Launch request arguments for sBPF debugger.
 */
interface ILaunchRequestArguments extends DebugProtocol.LaunchRequestArguments {
  /** Absolute path to the assembly file (.s) or ELF file (.so/.o) */
  program: string;
  /** Program input (JSON object with instruction and accounts) */
  input?: object;
  /** Compute unit limit */
  computeUnitLimit?: number;
  /** Stack size in bytes */
  stackSize?: number;
  /** Heap size in bytes */
  heapSize?: number;
  /** Automatically stop target after launch */
  stopOnEntry?: boolean;
}

export class SbpfDebugSession extends LoggingDebugSession {
  private static threadID = 1;
  private _runtime: SbpfRuntime;
  private _configurationDoneResolve!: () => void;
  private _configurationDone = new Promise<void>((resolve) => {
    this._configurationDoneResolve = resolve;
  });
  private _variableHandles = new Handles<string>();
  private _runtimeReady: Promise<void> = Promise.resolve();

  public constructor() {
    super("sbpf-debug.txt");
    this.setDebuggerLinesStartAt1(false);
    this.setDebuggerColumnsStartAt1(false);
    this._runtime = new SbpfRuntime();

    // Handle entry event (stop on entry)
    this._runtime.on("entry", () => {
      this.sendEvent(new StoppedEvent("entry", SbpfDebugSession.threadID));
    });

    // Handle program exit
    this._runtime.on("exit", () => {
      this.sendEvent(new TerminatedEvent());
    });

    // Handle output from the debugger
    this._runtime.on("output", (type: string, text: string) => {
      const category =
        type === "stderr"
          ? "stderr"
          : type === "console"
          ? "console"
          : "stdout";

      // Check if this is a JSON exit event from the backend
      try {
        const maybeJson = JSON.parse(text);
        if (
          maybeJson &&
          maybeJson.type === "exit" &&
          typeof maybeJson.code !== "undefined"
        ) {
          this.sendEvent(
            new OutputEvent(
              `Program exited with code: ${maybeJson.code}\n`,
              "stdout",
            ),
          );
          this.sendEvent(new TerminatedEvent());
          return;
        }
      } catch {
        // Not JSON, just regular output
      }

      const e: DebugProtocol.OutputEvent = new OutputEvent(
        `${text}\n`,
        category,
      );
      this.sendEvent(e);
    });

    // Handle runtime errors
    this._runtime.on("error", (error: Error) => {
      console.error("Runtime error:", error.message);
      this.sendEvent(new OutputEvent(`Error: ${error.message}\n`, "stderr"));
      this.sendEvent(new StoppedEvent("exception", SbpfDebugSession.threadID));
    });
  }

  protected async initializeRequest(
    response: DebugProtocol.InitializeResponse,
    args: DebugProtocol.InitializeRequestArguments,
  ): Promise<void> {
    // Build and return the capabilities of this debug adapter
    response.body = response.body || {};

    // The adapter implements the configurationDone request
    response.body.supportsConfigurationDoneRequest = true;

    // Make VS Code use 'evaluate' when hovering over source
    response.body.supportsEvaluateForHovers = true;

    // Make VS Code show a 'step back' button (not supported)
    response.body.supportsStepBack = false;

    // Make VS Code support data breakpoints
    response.body.supportsDataBreakpoints = true;

    // Make VS Code support completion in REPL
    response.body.supportsCompletionsRequest = true;
    response.body.completionTriggerCharacters = [".", "["];

    // Make VS Code send cancel request
    response.body.supportsCancelRequest = true;

    // Make VS Code send the breakpointLocations request
    response.body.supportsBreakpointLocationsRequest = true;

    // Make VS Code provide "Step in Target" functionality (not supported)
    response.body.supportsStepInTargetsRequest = false;

    // Exception filter configuration
    response.body.supportsExceptionFilterOptions = true;
    response.body.exceptionBreakpointFilters = [
      {
        filter: "namedException",
        label: "Named Exception",
        description: `Break on named exceptions. Enter the exception's name as the Condition.`,
        default: false,
        supportsCondition: true,
        conditionDescription: `Enter the exception's name`,
      },
      {
        filter: "otherExceptions",
        label: "Other Exceptions",
        description: "This is a other exception",
        default: true,
        supportsCondition: false,
      },
    ];

    // Make VS Code send exceptionInfo request
    response.body.supportsExceptionInfoRequest = true;

    // Make VS Code send setVariable request
    response.body.supportsSetVariable = true;

    // Make VS Code send setExpression request
    response.body.supportsSetExpression = true;

    // Make VS Code send disassemble request
    response.body.supportsDisassembleRequest = true;
    response.body.supportsSteppingGranularity = true;
    response.body.supportsInstructionBreakpoints = true;

    // Make VS Code able to read and write variable memory
    response.body.supportsReadMemoryRequest = true;
    response.body.supportsWriteMemoryRequest = true;

    response.body.supportSuspendDebuggee = true;
    response.body.supportTerminateDebuggee = true;
    response.body.supportsFunctionBreakpoints = true;
    response.body.supportsDelayedStackTraceLoading = false;

    this.sendResponse(response);

    // Send initialized event to signal that breakpoints can be set
    this.sendEvent(new InitializedEvent());
  }

  /**
   * Called at the end of the configuration sequence.
   * Indicates that all breakpoints etc. have been sent to the DA and that the 'launch' can start.
   */
  protected configurationDoneRequest(
    response: DebugProtocol.ConfigurationDoneResponse,
    args: DebugProtocol.ConfigurationDoneArguments,
  ): void {
    super.configurationDoneRequest(response, args);
    // Notify the launchRequest that configuration has finished
    this._configurationDoneResolve();
  }

  protected async launchRequest(
    response: DebugProtocol.LaunchResponse,
    args: ILaunchRequestArguments,
  ): Promise<void> {
    try {
      // Wait until configuration has finished (with 1s timeout)
      await Promise.race([
        this._configurationDone,
        new Promise<void>((resolve) => setTimeout(resolve, 1000)),
      ]);

      const config: ISbpfLaunchConfig = {
        program: args.program,
        input: args.input,
        computeUnitLimit: args.computeUnitLimit,
        stackSize: args.stackSize,
        heapSize: args.heapSize,
        stopOnEntry: args.stopOnEntry,
      };

      this._runtimeReady = this._runtime.start(config);
      await this._runtimeReady;
      this.sendResponse(response);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown launch error";
      this.sendErrorResponse(response, {
        id: 1001,
        format: `Failed to launch debugger: ${errorMessage}`,
        showUser: true,
      });
    }
  }

  protected async setBreakPointsRequest(
    response: DebugProtocol.SetBreakpointsResponse,
    args: DebugProtocol.SetBreakpointsArguments,
  ): Promise<void> {
    try {
      await this._runtimeReady;
      const path = args.source.path as string;
      const clientLines = args.lines || [];

      // Clear all breakpoints for this file
      if ("clearBreakpointsForFile" in this._runtime) {
        await (
          this._runtime as unknown as {
            clearBreakpointsForFile: (path: string) => Promise<void>;
          }
        ).clearBreakpointsForFile(path);
      } else if ("clearBreakpoints" in this._runtime) {
        await this._runtime.clearBreakpoints(path);
      }

      // Set and verify breakpoint locations
      const breakpoints: DebugProtocol.Breakpoint[] = [];
      for (const line of clientLines) {
        try {
          await this._runtime.setBreakpoint(path, line);
          breakpoints.push(new Breakpoint(true, line));
        } catch {
          breakpoints.push(new Breakpoint(false, line));
        }
      }

      response.body = { breakpoints };
      this.sendResponse(response);
    } catch (error) {
      const errorMessage =
        error instanceof Error
          ? error.message
          : "Unknown error setting breakpoints";
      this.sendErrorResponse(response, {
        id: 1004,
        format: `Failed to set breakpoints: ${errorMessage}`,
        showUser: true,
      });
    }
  }

  protected async continueRequest(
    response: DebugProtocol.ContinueResponse,
    args: DebugProtocol.ContinueArguments,
  ): Promise<void> {
    try {
      await this._runtime.continue();
      this.sendResponse(response);
      this.sendEvent(new StoppedEvent("breakpoint", SbpfDebugSession.threadID));
    } catch (error) {
      const errorMessage =
        error instanceof Error
          ? error.message
          : "Unknown error during continue";
      this.sendErrorResponse(response, {
        id: 1002,
        format: `Continue failed: ${errorMessage}`,
        showUser: true,
      });
    }
  }

  protected async nextRequest(
    response: DebugProtocol.NextResponse,
    args: DebugProtocol.NextArguments,
  ): Promise<void> {
    try {
      await this._runtime.step();
      this.sendResponse(response);
      this.sendEvent(new StoppedEvent("step", SbpfDebugSession.threadID));
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error during step";
      this.sendErrorResponse(response, {
        id: 1003,
        format: `Step failed: ${errorMessage}`,
        showUser: true,
      });
    }
  }

  protected stepInRequest(
    response: DebugProtocol.StepInResponse,
    args: DebugProtocol.StepInArguments,
  ): void {
    this.sendResponse(response);
    this.sendEvent(new StoppedEvent("step", SbpfDebugSession.threadID));
  }

  protected stepOutRequest(
    response: DebugProtocol.StepOutResponse,
    args: DebugProtocol.StepOutArguments,
  ): void {
    this.sendResponse(response);
    this.sendEvent(new StoppedEvent("step", SbpfDebugSession.threadID));
  }

  protected threadsRequest(response: DebugProtocol.ThreadsResponse): void {
    response.body = {
      threads: [new Thread(SbpfDebugSession.threadID, "thread 1")],
    };
    this.sendResponse(response);
  }

  protected async stackTraceRequest(
    response: DebugProtocol.StackTraceResponse,
    args: DebugProtocol.StackTraceArguments,
  ): Promise<void> {
    const frames = await this._runtime.getStackFrames();
    response.body = {
      stackFrames: frames.map(
        (f) =>
          new StackFrame(
            f.index,
            f.name,
            new Source(
              f.file ? f.file.split(/[\\/]/).pop() || f.file : "program",
              f.file,
            ),
            f.line,
            f.column,
          ),
      ),
      totalFrames: frames.length,
    };
    this.sendResponse(response);
  }

  protected scopesRequest(
    response: DebugProtocol.ScopesResponse,
    args: DebugProtocol.ScopesArguments,
  ): void {
    response.body = {
      scopes: [
        new Scope("Registers", this._variableHandles.create("registers"), true),
        new Scope("Rodata", this._variableHandles.create("rodata"), true),
        new Scope(
          "Compute Units",
          this._variableHandles.create("compute"),
          true,
        ),
      ],
    };
    this.sendResponse(response);
  }

  protected async variablesRequest(
    response: DebugProtocol.VariablesResponse,
    args: DebugProtocol.VariablesArguments,
  ): Promise<void> {
    const variables: DebugProtocol.Variable[] = [];
    const v = this._variableHandles.get(args.variablesReference);

    if (v === "registers") {
      const regs = (await this._runtime.getRegisters()) || [];
      for (const reg of regs) {
        variables.push({
          name: reg.name,
          value: reg.value,
          type: reg.type,
          variablesReference: 0,
        });
      }
    } else if (v === "rodata") {
      const rodata = (await this._runtime.getRodata()) || [];
      for (const item of rodata) {
        variables.push({
          name: item.name,
          value: item.value,
          type: item.address || "rodata",
          variablesReference: 0,
        });
      }
    } else if (v === "compute") {
      const cu = await this._runtime.getComputeUnits();
      variables.push({
        name: "Used",
        value: cu.used.toString(),
        type: "u64",
        variablesReference: 0,
      });
      variables.push({
        name: "Remaining",
        value: cu.remaining.toString(),
        type: "u64",
        variablesReference: 0,
      });
    }

    response.body = { variables };
    this.sendResponse(response);
  }

  protected setVariableRequest(
    response: DebugProtocol.SetVariableResponse,
    args: DebugProtocol.SetVariableArguments,
  ): void {
    const v = this._variableHandles.get(args.variablesReference);

    if (v === "registers") {
      // Register name is like 'r0', 'r1', etc.
      const match = /^r(\d+)$/.exec(args.name);
      if (match) {
        const regIndex = parseInt(match[1], 10);
        // Try to parse value as hex or decimal
        const value = args.value.trim();
        let numValue: number | undefined = undefined;
        if (value.startsWith("0x") || value.startsWith("0X")) {
          numValue = parseInt(value, 16);
        } else {
          numValue = parseInt(value, 10);
        }
        if (!isNaN(numValue)) {
          this._runtime
            .setRegister(regIndex, numValue)
            .then(() => {
              response.body = {
                value: `0x${numValue!.toString(16)}`,
                type: "u64",
                variablesReference: 0,
              };
              this.sendResponse(response);
            })
            .catch((err: unknown) => {
              this.sendErrorResponse(response, {
                id: 1004,
                format: `Failed to set register: ${err}`,
                showUser: true,
              });
            });
          return;
        } else {
          this.sendErrorResponse(response, {
            id: 1005,
            format: `Invalid value for register: ${args.value}`,
            showUser: true,
          });
          return;
        }
      } else {
        this.sendErrorResponse(response, {
          id: 1006,
          format: `Invalid register name: ${args.name}`,
          showUser: true,
        });
        return;
      }
    } else if (v === "rodata") {
      this.sendErrorResponse(response, {
        id: 1007,
        format: `Cannot set value of .rodata symbol`,
        showUser: true,
      });
      return;
    } else {
      this.sendErrorResponse(response, {
        id: 1008,
        format: `Cannot set value of this variable`,
        showUser: true,
      });
      return;
    }
  }

  protected async disconnectRequest(
    response: DebugProtocol.DisconnectResponse,
    args: DebugProtocol.DisconnectArguments,
  ): Promise<void> {
    await this._runtime.shutdown();
    this.sendResponse(response);
  }

  protected exceptionInfoRequest(
    response: DebugProtocol.ExceptionInfoResponse,
    args: DebugProtocol.ExceptionInfoArguments,
  ): void {
    response.body = {
      exceptionId: "sbpf-runtime-error",
      description: "An error occurred during program execution",
      breakMode: "always",
      details: {
        message: "The sBPF program encountered an error during execution",
        typeName: "SBPFRuntimeError",
        stackTrace: "See the debug console for detailed error information",
      },
    };
    this.sendResponse(response);
  }
}
