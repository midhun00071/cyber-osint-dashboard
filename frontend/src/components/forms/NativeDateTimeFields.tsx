import type { LocalDateTimeParts } from "@/utils/localDateTime";
import { isPartialLocalDateTime } from "@/utils/localDateTime";

type NativeDateTimeFieldsProps = {
  id: string;
  label: string;
  name: string;
  value: LocalDateTimeParts;
  onChange: (value: LocalDateTimeParts) => void;
  className?: string;
  disabled?: boolean;
};

export function NativeDateTimeFields({
  id,
  label,
  name,
  value,
  onChange,
  className,
  disabled = false,
}: NativeDateTimeFieldsProps) {
  const partial = isPartialLocalDateTime(value);
  const errorId = `${id}-error`;
  const classes = ["dateTimeField", className].filter(Boolean).join(" ");

  return (
    <fieldset className={classes}>
      <legend>{label}</legend>
      <div className="dateTimePair">
        <label htmlFor={`${id}-date`}>
          <span>Date</span>
          <input
            aria-describedby={partial ? errorId : undefined}
            aria-invalid={partial}
            aria-label={`${label} date`}
            disabled={disabled}
            id={`${id}-date`}
            name={`${name}_date`}
            onChange={(event) => onChange({ ...value, date: event.target.value })}
            type="date"
            value={value.date}
          />
        </label>
        <label htmlFor={`${id}-time`}>
          <span>Time</span>
          <input
            aria-describedby={partial ? errorId : undefined}
            aria-invalid={partial}
            aria-label={`${label} time`}
            disabled={disabled}
            id={`${id}-time`}
            name={`${name}_time`}
            onChange={(event) => onChange({ ...value, time: event.target.value })}
            type="time"
            value={value.time}
          />
        </label>
      </div>
      {partial ? <p className="dateTimeError" id={errorId} role="alert">Enter both a date and time for {label.toLowerCase()}.</p> : null}
    </fieldset>
  );
}
