export class SlotQueue {
  private active = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly maxConcurrent: () => number) {}

  async run<T>(work: () => Promise<T>): Promise<T> {
    if (this.active >= this.maxConcurrent()) {
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active += 1;
    try {
      return await work();
    } finally {
      this.active -= 1;
      this.queue.shift()?.();
    }
  }
}
