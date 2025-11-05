import { HttpStream } from "./httpClient.js";

export interface ServerSentEvent {
  event?: string;
  data: string;
  id?: string;
  retry?: number;
}

export interface ServerSentEventIterator extends AsyncIterable<ServerSentEvent> {
  close(): Promise<void>;
}

interface InternalEventState {
  event?: string;
  data?: string[];
  id?: string;
  retry?: number;
}

export async function* parseServerSentEvents(
  stream: HttpStream,
): AsyncGenerator<ServerSentEvent, void, undefined> {
  let buffer = "";
  let state: InternalEventState = {};

  const flush = (): ServerSentEvent | undefined => {
    if (!state.data || state.data.length === 0) return undefined;
    const payload: ServerSentEvent = {
      event: state.event,
      id: state.id,
      retry: state.retry,
      data: state.data.join("\n"),
    };
    state = {};
    return payload;
  };

  for await (const chunk of stream.text()) {
    buffer += chunk;

    while (true) {
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex === -1) break;

      const rawLine = buffer.slice(0, newlineIndex);
      buffer = buffer.slice(newlineIndex + 1);

      const line = rawLine.replace(/\r$/, "");

      if (line === "") {
        const payload = flush();
        if (payload) {
          yield payload;
        }
        state = {};
        continue;
      }

      const separatorIndex = line.indexOf(":");
      let field: string;
      let value: string;
      if (separatorIndex === -1) {
        field = line;
        value = "";
      } else {
        field = line.slice(0, separatorIndex);
        value = line.slice(separatorIndex + 1).replace(/^ /, "");
      }

      switch (field) {
        case "event":
          state.event = value;
          break;
        case "data":
          if (!state.data) state.data = [];
          state.data.push(value);
          break;
        case "id":
          state.id = value;
          break;
        case "retry":
          if (/^\d+$/.test(value)) {
            state.retry = Number(value);
          }
          break;
        default:
          break;
      }
    }
  }

  const tail = buffer.replace(/\r$/, "");
  if (tail) {
    if (!state.data) state.data = [];
    state.data.push(tail);
  }
  const payload = flush();
  if (payload) {
    yield payload;
  }
}

export function toServerSentEventIterator(stream: HttpStream): ServerSentEventIterator {
  const iterator = parseServerSentEvents(stream);
  return {
    async close() {
      await stream.cancel();
    },
    [Symbol.asyncIterator]() {
      return iterator[Symbol.asyncIterator]();
    },
  };
}
