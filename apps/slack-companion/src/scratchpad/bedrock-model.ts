import {
  BedrockRuntimeClient,
  ConverseCommand,
  type ConverseCommandOutput,
} from "@aws-sdk/client-bedrock-runtime";
import type {
  HostedModelPort,
  HostedModelRequest,
  HostedModelResponse,
} from "./hosted-hillclimb.js";

export class BedrockHostedModel implements HostedModelPort {
  private readonly client: BedrockRuntimeClient;

  constructor(region: string) {
    this.client = new BedrockRuntimeClient({ region });
  }

  async converse(request: HostedModelRequest): Promise<HostedModelResponse> {
    const output = await this.client.send(new ConverseCommand({
      inferenceConfig: {
        maxTokens: request.max_tokens,
        temperature: request.temperature,
      },
      messages: [{
        content: [{ text: request.prompt }],
        role: "user",
      }],
      modelId: request.model_id,
      system: [{ text: request.system }],
    }));
    return response(request.model_id, output);
  }

  destroy(): void {
    this.client.destroy();
  }
}

function response(
  modelId: string,
  output: ConverseCommandOutput,
): HostedModelResponse {
  const content = output.output?.message?.content ?? [];
  const outputText = content.flatMap((block) =>
    "text" in block && typeof block.text === "string" ? [block.text] : []
  ).join("\n").trim();
  const inputTokens = output.usage?.inputTokens ?? 0;
  const outputTokens = output.usage?.outputTokens ?? 0;
  return {
    latency_ms: output.metrics?.latencyMs ?? 0,
    model_id: modelId,
    output_text: outputText,
    ...(output.$metadata.requestId === undefined
      ? {}
      : { provider_request_id: output.$metadata.requestId }),
    token_usage: {
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      total_tokens: inputTokens + outputTokens,
    },
  };
}
