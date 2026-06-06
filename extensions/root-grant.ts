import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	createBashToolDefinition,
	createEditToolDefinition,
	createReadToolDefinition,
	createWriteToolDefinition,
	ExtensionInputComponent,
	SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";

const MAX_DURATION_MS = 15 * 60 * 1000;
const DEFAULT_DURATION = "5m";
const STATUS_KEY = "root-grant";
const READ_LIMIT_BYTES = 50 * 1024;

interface GrantState {
	expiresAt: number;
	password?: string;
	timer?: ReturnType<typeof setTimeout>;
}

interface ToolResult {
	content: Array<{ type: "text"; text: string }>;
	details: Record<string, unknown>;
	isError?: boolean;
}

const readSchema = Type.Object({
	path: Type.String({ description: "Path to the file to read (relative or absolute)" }),
	offset: Type.Optional(Type.Number({ description: "Line number to start reading from (1-indexed)" })),
	limit: Type.Optional(Type.Number({ description: "Maximum number of lines to read" })),
});

const writeSchema = Type.Object({
	path: Type.String({ description: "Path to the file to write (relative or absolute)" }),
	content: Type.String({ description: "Content to write to the file" }),
});

const editSchema = Type.Object({
	path: Type.String({ description: "Path to the file to edit (relative or absolute)" }),
	edits: Type.Array(
		Type.Object({
			oldText: Type.String({ description: "Exact text to replace; must match uniquely" }),
			newText: Type.String({ description: "Replacement text" }),
		}),
		{ description: "One or more non-overlapping exact replacements" },
	),
});

const bashSchema = Type.Object({
	command: Type.String({ description: "Bash command to execute" }),
	timeout: Type.Optional(Type.Number({ description: "Timeout in seconds" })),
});

function detectImageMimeType(buffer: Buffer): string | null {
	if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
	if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "image/jpeg";
	if (buffer.length >= 6) {
		const signature = buffer.subarray(0, 6).toString("ascii");
		if (signature === "GIF87a" || signature === "GIF89a") return "image/gif";
	}
	if (buffer.length >= 12 && buffer.subarray(0, 4).toString("ascii") === "RIFF" && buffer.subarray(8, 12).toString("ascii") === "WEBP") return "image/webp";
	return null;
}

function parseDuration(input: string): number | null {
	const trimmed = input.trim().toLowerCase();
	const match = /^(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)?$/.exec(trimmed);
	if (!match) return null;
	const value = Number(match[1]);
	if (!Number.isFinite(value) || value <= 0) return null;
	const unit = match[2] ?? "m";
	const factor = unit.startsWith("s") ? 1000 : unit.startsWith("h") ? 60 * 60 * 1000 : 60 * 1000;
	return Math.min(Math.round(value * factor), MAX_DURATION_MS);
}

function formatDuration(ms: number): string {
	const seconds = Math.max(0, Math.ceil(ms / 1000));
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.floor(seconds / 60);
	const rest = seconds % 60;
	return rest ? `${minutes}m${rest}s` : `${minutes}m`;
}

function textResult(text: string, details: Record<string, unknown> = {}, isError = false): ToolResult {
	return { content: [{ type: "text", text }], details, isError };
}

function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function isActive(grant: GrantState | null): grant is GrantState {
	return !!grant && Date.now() < grant.expiresAt;
}

async function run(pi: ExtensionAPI, command: string, args: string[], timeout = 30_000) {
	return pi.exec(command, args, { timeout });
}

function absolutePath(cwd: string, path: string): string {
	return resolve(cwd, path);
}

async function promptPassword(ctx: any, reason: string): Promise<string | undefined> {
	return ctx.ui.custom((tui: any, _theme: any, _kb: any, done: (value: string | undefined) => void) => {
		const component: any = new ExtensionInputComponent(
			`sudo password required\n\n${reason}\n\nPassword is masked and sent only to sudo via stdin.`,
			"",
			(value: string) => done(value),
			() => done(undefined),
			{ tui },
		);
		const input = component.input;
		if (input?.render && input?.getValue) {
			input.render = function (width: number): string[] {
				const prompt = "> ";
				const availableWidth = Math.max(0, width - prompt.length);
				const count = Math.min(this.getValue().length, Math.max(0, availableWidth - 1));
				const bullets = "•".repeat(count);
				const cursor = "\x1b[7m \x1b[27m";
				const padding = " ".repeat(Math.max(0, availableWidth - count - 1));
				return [prompt + bullets + cursor + padding];
			};
		}
		return component;
	});
}

async function sudoSpawnWithPassword(password: string, args: string[], timeoutMs = 60_000): Promise<{ code: number | null; stdout: string; stderr: string; killed: boolean }> {
	const result = await sudoSpawnBuffer(password, args, timeoutMs);
	return {
		code: result.code,
		stdout: result.stdout.toString(),
		stderr: result.stderr.toString(),
		killed: result.killed,
	};
}

async function sudoSpawnBuffer(password: string | undefined, args: string[], timeoutMs = 60_000): Promise<{ code: number | null; stdout: Buffer; stderr: Buffer; killed: boolean }> {
	return new Promise((resolve) => {
		const child = spawn("sudo", ["-S", "-p", "", ...args], { stdio: ["pipe", "pipe", "pipe"] });
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		let killed = false;
		const timer = setTimeout(() => {
			killed = true;
			child.kill("SIGTERM");
		}, timeoutMs);

		child.stdout.on("data", (chunk) => { stdout.push(Buffer.from(chunk)); });
		child.stderr.on("data", (chunk) => { stderr.push(Buffer.from(chunk)); });
		child.on("close", (code) => {
			clearTimeout(timer);
			resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), killed });
		});
		child.stdin.end(password ? `${password}\n` : "\n");
	});
}

async function sudoValidateWithPassword(password: string, timeoutMs = 60_000): Promise<{ code: number | null; stdout: string; stderr: string }> {
	const result = await sudoSpawnWithPassword(password, ["-v"], timeoutMs);
	return { code: result.code, stdout: result.stdout, stderr: result.stderr };
}

function applyLineWindow(content: string, offset?: number, limit?: number): string {
	if (!offset && !limit) return content;
	const lines = content.split("\n");
	const start = offset ? Math.max(0, offset - 1) : 0;
	const end = limit ? start + limit : lines.length;
	return lines.slice(start, end).join("\n");
}

function truncateForRead(content: string): { text: string; truncated: boolean } {
	const bytes = Buffer.byteLength(content, "utf8");
	if (bytes <= READ_LIMIT_BYTES) return { text: content, truncated: false };
	return { text: `${content.slice(0, READ_LIMIT_BYTES)}\n\n[Output truncated at 50KB]`, truncated: true };
}

async function normalRead(path: string, offset?: number, limit?: number): Promise<ToolResult> {
	try {
		const content = await readFile(path, "utf8");
		const selected = applyLineWindow(content, offset, limit);
		const { text, truncated } = truncateForRead(selected);
		return textResult(text, { root: false, truncated });
	} catch (error: any) {
		return textResult(`Error reading file: ${error.message}`, { root: false, error: true }, true);
	}
}

async function normalWrite(path: string, content: string): Promise<ToolResult> {
	try {
		await mkdir(dirname(path), { recursive: true });
		await writeFile(path, content, "utf8");
		return textResult(`Wrote ${Buffer.byteLength(content, "utf8")} bytes to ${path}`, { root: false });
	} catch (error: any) {
		return textResult(`Error writing file: ${error.message}`, { root: false, error: true }, true);
	}
}

function applyEdits(content: string, edits: Array<{ oldText: string; newText: string }>): { content?: string; error?: string } {
	const ranges: Array<{ start: number; end: number; newText: string }> = [];

	for (const edit of edits) {
		if (!edit.oldText) return { error: "oldText must not be empty" };
		const first = content.indexOf(edit.oldText);
		if (first === -1) return { error: `oldText not found: ${JSON.stringify(edit.oldText.slice(0, 80))}` };
		const second = content.indexOf(edit.oldText, first + edit.oldText.length);
		if (second !== -1) return { error: `oldText is not unique: ${JSON.stringify(edit.oldText.slice(0, 80))}` };
		ranges.push({ start: first, end: first + edit.oldText.length, newText: edit.newText });
	}

	ranges.sort((a, b) => a.start - b.start);
	for (let i = 1; i < ranges.length; i++) {
		if (ranges[i].start < ranges[i - 1].end) return { error: "Edits overlap" };
	}

	let next = "";
	let cursor = 0;
	for (const range of ranges) {
		next += content.slice(cursor, range.start);
		next += range.newText;
		cursor = range.end;
	}
	next += content.slice(cursor);
	return { content: next };
}

async function normalEdit(path: string, edits: Array<{ oldText: string; newText: string }>): Promise<ToolResult> {
	try {
		const content = await readFile(path, "utf8");
		const applied = applyEdits(content, edits);
		if (applied.error) return textResult(`Error editing file: ${applied.error}`, { root: false, error: true }, true);
		await writeFile(path, applied.content!, "utf8");
		return textResult(`Applied ${edits.length} edit(s) to ${path}`, { root: false, edits: edits.length });
	} catch (error: any) {
		return textResult(`Error editing file: ${error.message}`, { root: false, error: true }, true);
	}
}

async function sudoRawRead(pi: ExtensionAPI, path: string, password?: string): Promise<ToolResult> {
	const symlink = password
		? await sudoSpawnWithPassword(password, ["test", "-L", path], 5_000)
		: await run(pi, "sudo", ["test", "-L", path], 5_000);
	if (symlink.code === 0) return textResult(`Refusing to read symlink as root: ${path}`, { root: true, blocked: true }, true);

	const result = password
		? await sudoSpawnWithPassword(password, ["bash", "-lc", "cat -- \"$1\"", "bash", path])
		: await run(pi, "sudo", ["bash", "-lc", "cat -- \"$1\"", "bash", path]);
	if (result.code !== 0) {
		return textResult(`Error reading file as root: ${result.stderr || result.stdout}`, { root: true, error: true, code: result.code }, true);
	}
	return textResult(result.stdout, { root: true });
}

async function sudoRead(pi: ExtensionAPI, path: string, offset?: number, limit?: number, password?: string): Promise<ToolResult> {
	const raw = await sudoRawRead(pi, path, password);
	if (raw.isError) return raw;
	const selected = applyLineWindow(raw.content[0]?.text ?? "", offset, limit);
	const { text, truncated } = truncateForRead(selected);
	return textResult(text, { root: true, truncated });
}

async function sudoWrite(pi: ExtensionAPI, path: string, content: string, password?: string): Promise<ToolResult> {
	const tempDir = await mkdtemp(`${tmpdir()}/pi-root-grant-`);
	const tempFile = `${tempDir}/content`;
	try {
		await writeFile(tempFile, content, "utf8");
		const symlink = password
			? await sudoSpawnWithPassword(password, ["test", "-L", path], 5_000)
			: await run(pi, "sudo", ["test", "-L", path], 5_000);
		if (symlink.code === 0) return textResult(`Refusing to write symlink as root: ${path}`, { root: true, blocked: true }, true);

		const parent = dirname(path);
		const mkdir = password
			? await sudoSpawnWithPassword(password, ["mkdir", "-p", parent])
			: await run(pi, "sudo", ["mkdir", "-p", parent]);
		if (mkdir.code !== 0) return textResult(`Error creating parent directory as root: ${mkdir.stderr || mkdir.stdout}`, { root: true, error: true }, true);

		const copy = password
			? await sudoSpawnWithPassword(password, ["cp", tempFile, path])
			: await run(pi, "sudo", ["cp", tempFile, path]);
		if (copy.code !== 0) return textResult(`Error writing file as root: ${copy.stderr || copy.stdout}`, { root: true, error: true, code: copy.code }, true);
		return textResult(`Wrote ${Buffer.byteLength(content, "utf8")} bytes to ${path} as root`, { root: true });
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
}

async function sudoEdit(pi: ExtensionAPI, path: string, edits: Array<{ oldText: string; newText: string }>, password?: string): Promise<ToolResult> {
	const read = await sudoRawRead(pi, path, password);
	if (read.isError) return read;
	const content = read.content[0]?.text ?? "";
	const applied = applyEdits(content, edits);
	if (applied.error) return textResult(`Error editing file as root: ${applied.error}`, { root: true, error: true }, true);
	return sudoWrite(pi, path, applied.content!, password);
}

function throwSudoError(action: string, result: { stderr: Buffer | string; stdout: Buffer | string; code: number | null }): never {
	const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString() : result.stderr;
	const stdout = Buffer.isBuffer(result.stdout) ? result.stdout.toString() : result.stdout;
	throw new Error(`Error ${action} as root: ${stderr || stdout || `exit code ${result.code}`}`);
}

async function sudoCheckNotSymlink(path: string, password?: string): Promise<void> {
	const symlink = await sudoSpawnBuffer(password, ["test", "-L", path], 5_000);
	if (symlink.code === 0) throw new Error(`Refusing to operate on symlink as root: ${path}`);
}

function createRootReadOperations(password?: string) {
	return {
		async access(path: string) {
			const result = await sudoSpawnBuffer(password, ["test", "-r", path], 5_000);
			if (result.code !== 0) throwSudoError("checking read access", result);
		},
		async readFile(path: string) {
			await sudoCheckNotSymlink(path, password);
			const result = await sudoSpawnBuffer(password, ["bash", "-lc", "cat -- \"$1\"", "bash", path]);
			if (result.code !== 0) throwSudoError("reading file", result);
			return result.stdout;
		},
		async detectImageMimeType(path: string) {
			await sudoCheckNotSymlink(path, password);
			const result = await sudoSpawnBuffer(password, ["bash", "-lc", "head -c 4100 -- \"$1\"", "bash", path], 10_000);
			if (result.code !== 0) throwSudoError("detecting file type", result);
			return detectImageMimeType(result.stdout);
		},
	};
}

function createRootWriteOperations(password?: string) {
	return {
		async mkdir(path: string) {
			const result = await sudoSpawnBuffer(password, ["mkdir", "-p", path]);
			if (result.code !== 0) throwSudoError("creating directory", result);
		},
		async writeFile(path: string, content: string) {
			await sudoCheckNotSymlink(path, password);
			const tempDir = await mkdtemp(`${tmpdir()}/pi-root-grant-`);
			const tempFile = `${tempDir}/content`;
			try {
				await writeFile(tempFile, content, "utf8");
				const result = await sudoSpawnBuffer(password, ["cp", tempFile, path]);
				if (result.code !== 0) throwSudoError("writing file", result);
			} finally {
				await rm(tempDir, { recursive: true, force: true });
			}
		},
	};
}

function createRootEditOperations(password?: string) {
	const readOps = createRootReadOperations(password);
	const writeOps = createRootWriteOperations(password);
	return {
		readFile: readOps.readFile,
		writeFile: writeOps.writeFile,
		async access(path: string) {
			const result = await sudoSpawnBuffer(password, ["bash", "-lc", "test -r \"$1\" && test -w \"$1\"", "bash", path], 5_000);
			if (result.code !== 0) throwSudoError("checking read/write access", result);
		},
	};
}

function getReadToolOptions(cwd: string, operations?: ReturnType<typeof createRootReadOperations>) {
	return {
		autoResizeImages: SettingsManager.create(cwd).getImageAutoResize(),
		...(operations ? { operations } : {}),
	};
}

function createRootBashOperations(password?: string) {
	return {
		exec(command: string, cwd: string, options: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number; env?: NodeJS.ProcessEnv }) {
			return new Promise<{ exitCode: number | null }>((resolve, reject) => {
				const child = spawn("sudo", ["-S", "-p", "", "bash", "-lc", `cd ${shellQuote(cwd)} && ${command}`], {
					cwd: "/",
					env: options.env,
					stdio: ["pipe", "pipe", "pipe"],
				});
				let timedOut = false;
				const timeoutHandle = options.timeout && options.timeout > 0
					? setTimeout(() => {
						timedOut = true;
						child.kill("SIGTERM");
					}, options.timeout * 1000)
					: undefined;
				const onAbort = () => child.kill("SIGTERM");
				if (options.signal?.aborted) onAbort();
				else options.signal?.addEventListener("abort", onAbort, { once: true });
				child.stdout.on("data", options.onData);
				child.stderr.on("data", options.onData);
				child.on("error", (error) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					options.signal?.removeEventListener("abort", onAbort);
					reject(error);
				});
				child.on("close", (code) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					options.signal?.removeEventListener("abort", onAbort);
					if (options.signal?.aborted) reject(new Error("aborted"));
					else if (timedOut) reject(new Error(`timeout:${options.timeout}`));
					else resolve({ exitCode: code });
				});
				child.stdin.end(password ? `${password}\n` : "\n");
			});
		},
	};
}

export default function rootGrant(pi: ExtensionAPI) {
	let grant: GrantState | null = null;

	function clearStatus(ctx?: { ui?: { setStatus?: (key: string, value?: string) => void } }) {
		ctx?.ui?.setStatus?.(STATUS_KEY, undefined);
	}

	function revoke(ctx?: { ui?: { setStatus?: (key: string, value?: string) => void; notify?: (message: string, type?: "info" | "warning" | "error") => void } }, reason = "Root access revoked") {
		const hadGrant = !!grant;
		if (grant?.timer) clearTimeout(grant.timer);
		if (grant?.password) grant.password = "";
		grant = null;
		clearStatus(ctx);
		if (hadGrant) void run(pi, "sudo", ["-k"], 5_000).catch(() => undefined);
		ctx?.ui?.notify?.(reason, "info");
	}

	function expireIfNeeded(ctx: { ui: { setStatus: (key: string, value?: string) => void; notify?: (message: string, type?: "info" | "warning" | "error") => void } }) {
		if (grant && !isActive(grant)) revoke(ctx, "Root access expired");
	}

	function updateStatus(ctx: { ui: { setStatus: (key: string, value?: string) => void } }) {
		if (!isActive(grant)) {
			revoke(ctx, "Root access expired");
			return;
		}
		ctx.ui.setStatus(STATUS_KEY, `ROOT ${formatDuration(grant.expiresAt - Date.now())}`);
	}

	async function enableRoot(durationText: string, reason: string, ctx: any): Promise<ToolResult> {
		const durationMs = parseDuration(durationText);
		if (!durationMs) return textResult(`Invalid duration: ${durationText}`, { granted: false, error: true }, true);

		const capped = durationMs === MAX_DURATION_MS && parseDuration(durationText)! >= MAX_DURATION_MS;
		const displayDuration = formatDuration(durationMs);
		const ok = await ctx.ui.confirm(
			"Enable root access?",
			`Duration: ${displayDuration}${capped ? " (max)" : ""}\nReason: ${reason}\n\nThe agent may run configured tools via sudo during this window.`,
		);
		if (!ok) return textResult("Root access denied by user.", { granted: false });

		let grantPassword: string | undefined;
		let sudo = await run(pi, "sudo", ["-n", "-v"], 10_000);
		if (sudo.code !== 0) {
			const password = await promptPassword(ctx, reason);
			if (!password) return textResult("Root access request cancelled.", { granted: false });
			const auth = await sudoValidateWithPassword(password);
			if (auth.code !== 0) {
				return textResult(
					`sudo authentication failed.\n${auth.stderr || auth.stdout}`,
					{ granted: false, error: true, code: auth.code, needsSudoAuth: true },
					true,
				);
			}
			grantPassword = password;
		}

		if (grant?.timer) clearTimeout(grant.timer);
		grant = {
			expiresAt: Date.now() + durationMs,
			password: grantPassword,
		};
		grant.timer = setTimeout(() => revoke(ctx, "Root access expired"), durationMs);
		updateStatus(ctx);
		ctx.ui.notify(`Root access enabled for ${displayDuration}`, "warning");
		return textResult(`Root access enabled for ${displayDuration}.`, { granted: true, durationMs, expiresAt: grant.expiresAt });
	}

	pi.registerCommand("root", {
		description: "Temporarily grant root access for a duration, e.g. /root 5m",
		handler: async (args, ctx) => {
			if (!ctx.hasUI) {
				ctx.ui.notify("Root grant requires interactive UI", "error");
				return;
			}
			const duration = args.trim() || DEFAULT_DURATION;
			const result = await enableRoot(duration, "User invoked /root", ctx);
			if (result.isError) ctx.ui.notify(result.content[0].text, "error");
		},
	});

	pi.registerCommand("root-off", {
		description: "Revoke temporary root access",
		handler: async (_args, ctx) => {
			revoke(ctx, "Root access revoked");
		},
	});

	pi.registerCommand("root-status", {
		description: "Show temporary root access status",
		handler: async (_args, ctx) => {
			if (!isActive(grant)) {
				revoke(ctx, "Root access is inactive");
				return;
			}
			updateStatus(ctx);
			ctx.ui.notify(`Root access active for ${formatDuration(grant.expiresAt - Date.now())}`, "warning");
		},
	});

	pi.registerTool({
		name: "request_root_access",
		label: "Request Root Access",
		description: "Ask the user to temporarily grant root privileges. Use only when a task genuinely requires root.",
		parameters: Type.Object({
			reason: Type.String({ description: "Why root access is needed" }),
			duration: Type.String({ description: "How long root access should stay enabled, e.g. 1m, 5m, 10m" }),
			suggestedDuration: Type.Optional(Type.String({ description: "Deprecated alias for duration" })),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			if (!ctx.hasUI) return textResult("Cannot request root access without UI.", { granted: false }, true);
			const duration = params.duration || params.suggestedDuration || DEFAULT_DURATION;
			return enableRoot(duration, params.reason, ctx);
		},
	});

	pi.registerTool({
		name: "revoke_root_access",
		label: "Revoke Root Access",
		description: "Revoke temporary root privileges immediately and clear any in-memory sudo password. Use when privileged work is complete.",
		parameters: Type.Object({
			reason: Type.Optional(Type.String({ description: "Why root access is no longer needed" })),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const wasActive = isActive(grant);
			revoke(ctx, params.reason ? `Root access revoked: ${params.reason}` : "Root access revoked by agent");
			return textResult(
				wasActive ? "Root access revoked. In-memory sudo password cleared." : "Root access was already inactive.",
				{ revoked: wasActive, passwordCleared: true },
			);
		},
	});

	const bashTool = createBashToolDefinition(process.cwd());
	pi.registerTool({
		...bashTool,
		description: `${bashTool.description} Uses sudo while temporary root access is active.`,
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			expireIfNeeded(ctx);
			if (!isActive(grant)) return createBashToolDefinition(ctx.cwd).execute(toolCallId, params, signal, onUpdate, ctx);
			updateStatus(ctx);
			return createBashToolDefinition(ctx.cwd, { operations: createRootBashOperations(grant.password) }).execute(toolCallId, params, signal, onUpdate, ctx);
		},
	});

	const readTool = createReadToolDefinition(process.cwd());
	pi.registerTool({
		...readTool,
		description: `${readTool.description} Uses sudo while temporary root access is active.`,
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			expireIfNeeded(ctx);
			if (!isActive(grant)) return createReadToolDefinition(ctx.cwd, getReadToolOptions(ctx.cwd)).execute(toolCallId, params, signal, onUpdate, ctx);
			updateStatus(ctx);
			return createReadToolDefinition(ctx.cwd, getReadToolOptions(ctx.cwd, createRootReadOperations(grant.password))).execute(toolCallId, params, signal, onUpdate, ctx);
		},
	});

	const writeTool = createWriteToolDefinition(process.cwd());
	pi.registerTool({
		...writeTool,
		description: `${writeTool.description} Uses sudo while temporary root access is active.`,
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			expireIfNeeded(ctx);
			if (!isActive(grant)) return createWriteToolDefinition(ctx.cwd).execute(toolCallId, params, signal, onUpdate, ctx);
			updateStatus(ctx);
			return createWriteToolDefinition(ctx.cwd, { operations: createRootWriteOperations(grant.password) }).execute(toolCallId, params, signal, onUpdate, ctx);
		},
	});

	const editTool = createEditToolDefinition(process.cwd());
	pi.registerTool({
		...editTool,
		description: `${editTool.description} Uses sudo while temporary root access is active.`,
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			expireIfNeeded(ctx);
			if (!isActive(grant)) return createEditToolDefinition(ctx.cwd).execute(toolCallId, params, signal, onUpdate, ctx);
			updateStatus(ctx);
			return createEditToolDefinition(ctx.cwd, { operations: createRootEditOperations(grant.password) }).execute(toolCallId, params, signal, onUpdate, ctx);
		},
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		revoke(ctx, "Root access revoked at session shutdown");
	});
}
