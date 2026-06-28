import { workflow, node, trigger, languageModel, memory, tool, expr, newCredential } from '@n8n/workflow-sdk';

const chatTrigger = trigger({
  type: '@n8n/n8n-nodes-langchain.chatTrigger',
  version: 1.4,
  config: {
    name: 'Chat Trigger',
    parameters: {
      public: false,
      options: {
        responseMode: 'streaming',
      },
    },
    position: [240, 300],
  },
  output: [{ chatInput: 'user message' }],
});

const openAiModel = languageModel({
  type: '@n8n/n8n-nodes-langchain.lmChatOpenAi',
  version: 1.3,
  config: {
    name: 'OpenAI Model',
    parameters: {
      model: { __rl: true, mode: 'list', value: 'gpt-5-mini' },
      options: {
        temperature: 0.7,
        maxTokens: -1,
      },
    },
    credentials: {
      openAiApi: newCredential('OpenAI'),
    },
    position: [700, 500],
  },
});

const sessionMemory = memory({
  type: '@n8n/n8n-nodes-langchain.memoryBufferWindow',
  version: 1.4,
  config: {
    name: 'Session Memory',
    parameters: {
      sessionIdType: 'fromInput',
      contextWindowLength: 10,
    },
    position: [700, 700],
  },
});

const mcpTool = tool({
  type: '@n8n/n8n-nodes-langchain.mcpClientTool',
  version: 1.3,
  config: {
    name: 'MCP Client Tool',
    parameters: {
      endpointUrl: 'http://127.0.0.1:8000/mcp',
      serverTransport: 'httpStreamable',
      authentication: 'none',
      include: 'all',
    },
    position: [700, 900],
  },
});

const aiAgent = node({
  type: '@n8n/n8n-nodes-langchain.agent',
  version: 3.1,
  config: {
    name: 'AI Research Agent',
    parameters: {
      promptType: 'auto',
      options: {
        systemMessage: `You are a security research agent connected to an MCP gateway at http://127.0.0.1:8000/mcp.

Your available tools come from the MCP gateway. Use them to assist users.

When the user asks about credentials, security audits, or system inventory, use the tool_registry_list tool.
When the user asks you to save or write files, use the filesystem_write tool.
When asked about memory or stored data, use the memory_* tools.
When asked about files, use the filesystem_* tools.

Always use tools by their exact names as provided by the MCP server.`,
        maxIterations: 15,
        enableStreaming: true,
        returnIntermediateSteps: true,
      },
    },
    subnodes: {
      model: openAiModel,
      memory: sessionMemory,
      tools: [mcpTool],
    },
    position: [540, 300],
  },
  output: [{ output: 'AI response' }],
});

export default workflow(
  'mcp-taint-tracker-demo',
  'MCP Taint Tracker Demo',
)
  .add(chatTrigger)
  .to(aiAgent);
