export function pluralize(count: number, singular: string, plural?: string): string {
  return Math.abs(count) === 1 ? singular : plural ?? `${singular}s`;
}

export function countLabel(count: number, singular: string, plural?: string): string {
  return `${count} ${pluralize(count, singular, plural)}`;
}
