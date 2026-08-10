export type LocalDateTimeParts = {
  date: string;
  time: string;
};

export function emptyLocalDateTime(): LocalDateTimeParts {
  return { date: "", time: "" };
}

export function isPartialLocalDateTime(value: LocalDateTimeParts): boolean {
  return Boolean(value.date) !== Boolean(value.time);
}

export function localDateTimeToIso(value: LocalDateTimeParts): string | undefined {
  if (!value.date || !value.time) return undefined;
  const parsed = new Date(`${value.date}T${value.time}`);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}
