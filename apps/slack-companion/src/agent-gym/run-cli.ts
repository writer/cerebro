import { agentGymVersionOutput, parseAgentGymCliCommand } from "./cli.js";

const command = parseAgentGymCliCommand(process.argv.slice(2));
if (command.command === "version") {
  process.stdout.write(agentGymVersionOutput());
} else {
  process.stdout.write(`${JSON.stringify(command)}\n`);
}
