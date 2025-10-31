import { AgentsClient } from "../clients/agents";
import {
  AgentReviewExportRecord,
  ReviewTaskCommentRecord,
  ReviewTaskHistoryRecord,
  ReviewTaskRecord,
} from "../types";

export interface ExportReviewTasksOptions {
  status?: string;
  limit?: number;
  includeComments?: boolean;
  includeHistory?: boolean;
  historyLimit?: number;
}

export class AgentReviewExporter {
  constructor(private readonly agents: AgentsClient) {}

  async exportTasks(orgId: string, options: ExportReviewTasksOptions = {}): Promise<AgentReviewExportRecord[]> {
    const limit = options.limit ?? 100;
    const includeComments = options.includeComments ?? true;
    const includeHistory = options.includeHistory ?? true;
    const historyLimit = options.historyLimit ?? 200;

    const tasks = await this.agents.listReviewTasks({ status: options.status, limit });

    if (tasks.length === 0) {
      return [];
    }

    const exports = await Promise.all(
      tasks.map(async (task) => {
        const [comments, history] = await Promise.all([
          includeComments ? this.agents.listReviewTaskComments(task.taskId) : Promise.resolve<ReviewTaskCommentRecord[]>([]),
          includeHistory
            ? this.agents.listReviewTaskHistory(task.taskId, { limit: historyLimit })
            : Promise.resolve<ReviewTaskHistoryRecord[]>([]),
        ]);

        return {
          task,
          comments,
          history,
        } satisfies AgentReviewExportRecord;
      }),
    );

    return exports;
  }
}
