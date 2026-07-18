export async function respondEphemeral(respond: (message: any) => Promise<unknown>, blocks: any[]): Promise<void> {
  await respond({ response_type: "ephemeral", text: "Cerebro", blocks });
}

export function plainBlocks(message: string): any[] {
  return [{ type: "section", text: { type: "mrkdwn", text: message } }];
}
