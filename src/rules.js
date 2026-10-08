// Capability rules. Severity: info < low < medium < high < critical.

export const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'];
export const rank = (s) => SEVERITY.indexOf(s);

// `$` calls in a mod, keyed "noun.method". Anything not listed is reported as info.
export const CALLS = {
  'fs.read': ['medium', 'reads files'],
  'fs.list': ['low', 'lists directories'],
  'fs.stat': ['low', 'stats files'],
  'fs.exists': ['low', 'checks whether files exist'],
  'fs.ancestors': ['low', 'walks parent directories'],
  'fs.write': ['high', 'writes files'],
  'http.fetch': ['high', 'makes network requests'],
  'process.run': ['high', 'runs host commands'],
  'process.spawn': ['high', 'spawns host processes'],
  'env.get': ['medium', 'reads environment variables'],
  'env.set': ['high', 'changes environment variables'],
  'settings.read': ['medium', 'reads Claude Code settings'],
  'session.messages': ['medium', 'reads the conversation'],
  'session.turns': ['medium', 'reads the conversation turns'],
  'session.send': ['high', 'sends messages into a session'],
  'session.append': ['high', 'appends rows the model reads'],
  'session.authorize': ['high', 'answers session authorization'],
  'session.compact': ['medium', 'compacts the conversation'],
  'prompt.submit': ['high', 'submits prompts that start turns'],
  'prompt.fill': ['medium', 'writes into the prompt box'],
  'prompt.read': ['medium', 'reads the prompt box'],
  'model.complete': ['medium', 'makes model calls (spends tokens)'],
  'model.fork': ['medium', 'asks the model over the full transcript (spends tokens)'],
  'model.classify': ['medium', 'makes model calls (spends tokens)'],
  'tool.call': ['high', 'calls tools (Bash, Edit, ...) itself'],
  'tool.register': ['medium', 'registers tools the model can call'],
  'agent.spawn': ['high', 'starts subagents'],
  'agent.register': ['medium', 'registers agent types'],
  'mcp.call': ['high', 'calls MCP tools'],
  'mcp.connect': ['high', 'connects MCP servers'],
  'command.run': ['medium', 'runs slash commands'],
  'command.register': ['low', 'registers slash commands'],
  'config.set': ['high', 'changes configuration'],
  'ui.ask': ['medium', 'asks the user questions in a dialog'],
  'ui.copy': ['medium', 'writes to the clipboard'],
  'ui.selection': ['medium', 'reads the mouse selection'],
  'store.set': ['low', 'persists data across sessions'],
  'telemetry.log': ['low', 'writes telemetry'],
};

// Events a mod hooks. [severity, plain, severityIfRewritten, plainIfRewritten]
export const EVENTS = {
  'tool.call': ['medium', 'sees and can block tool calls', 'high', 'rewrites tool calls before they run'],
  'tool.check': ['medium', 'takes part in tool permission checks', 'high', 'rewrites tool permission checks'],
  'prompt.submit': ['medium', 'sees every prompt you submit', 'high', 'rewrites your prompts'],
  'prompt.compose': ['high', 'can change the system prompt', 'high', 'changes the system prompt'],
  'prompt.context': ['medium', 'adds context the model reads', 'high', 'rewrites context the model reads'],
  'prompt.section': ['medium', 'adds system prompt sections', 'high', 'rewrites system prompt sections'],
  'session.append': ['high', 'can refuse or rewrite transcript rows', 'high', 'rewrites transcript rows'],
  'session.receive': ['medium', 'sees incoming messages', 'high', 'rewrites incoming messages'],
  'model.complete': ['medium', 'sees model calls', 'high', 'rewrites model calls'],
  'http.fetch': ['high', 'sees other plugins\' network requests', 'high', 'rewrites other plugins\' network requests'],
  'process.run': ['high', 'sees other plugins\' host commands', 'high', 'rewrites other plugins\' host commands'],
  'fs.read': ['medium', 'sees other plugins\' file reads', 'high', 'rewrites other plugins\' file reads'],
  'fs.write': ['high', 'sees other plugins\' file writes', 'high', 'rewrites other plugins\' file writes'],
  'state.set': ['low', 'watches plugin state', 'medium', 'rewrites other plugins\' state'],
  'telemetry.log': ['medium', 'sees telemetry', 'high', 'rewrites or drops telemetry records'],
  'telemetry.mark': ['medium', 'sees telemetry marks', 'high', 'rewrites or drops telemetry marks'],
  'ui.copy': ['medium', 'sees clipboard writes', 'high', 'rewrites clipboard writes'],
  'turn.step': ['medium', 'runs inside every agent step', 'high', 'rewrites agent steps'],
  'config.set': ['medium', 'sees config changes', 'high', 'rewrites config changes'],
};

// Classic (settings-style) hook events. [severity, plain]
export const CLASSIC_EVENTS = {
  PreToolUse: ['medium', 'runs before tool calls and can block them'],
  PermissionRequest: ['medium', 'runs when a permission prompt opens'],
  UserPromptSubmit: ['medium', 'sees every prompt you submit'],
  PostToolUse: ['low', 'sees tool results'],
  SessionStart: ['low', 'runs at session start and can add context'],
};

// ui.render on these components can change what the person reads before approving.
export const SENSITIVE_COMPONENTS = {
  ToolUse: 'tool-call rows (what a command or edit looks like)',
  ToolGroup: 'grouped tool-call rows',
  ToolResult: 'tool results',
  AskUserQuestion: 'the question dialog',
  UserMessage: 'your own messages in the transcript',
  AssistantMessage: 'the assistant\'s replies',
  CommandOutput: 'slash command output',
};

export const SENSITIVE_PATHS = [
  [/\.ssh\b|id_rsa|id_ed25519/, 'SSH keys'],
  [/\.aws\/(?:credentials|config)|aws_secret_access_key|application_default_credentials/, 'cloud credentials'],
  [/\.netrc|\.npmrc|\.pypirc/, 'package/registry tokens'],
  [/\.config\/gh|hosts\.yml/, 'GitHub CLI token'],
  [/\.claude\/(?:history|projects|\.credentials)|\.claude\.json/, 'Claude Code history or credentials'],
  [/(?:^|[\/'"`])\.env(?:\.|['"`]|$)/, '.env files'],
  [/Keychain|security\s+find-(?:generic|internet)-password/, 'the macOS keychain'],
  [/\.gnupg|\.kube\/config|\.docker\/config/, 'other credential stores'],
];
