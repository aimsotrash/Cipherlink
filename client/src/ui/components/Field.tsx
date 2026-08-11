/**
 * Labelled form field.
 *
 * The label element wraps only the label text, and the help text is linked
 * with `aria-describedby` instead of being swept into the accessible name.
 * Nesting the hint inside the label made every input announce as
 * "Passphrase Unlocks the encrypted database on this device. There is no
 * recovery…", which is unusable with a screen reader — and, since assistive
 * technology and automated tests resolve names the same way, is exactly the
 * sort of thing that goes unnoticed without one of them.
 */
import { useId, type InputHTMLAttributes, type ReactNode } from 'react';

export interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> {
  readonly label: string;
  readonly hint?: ReactNode;
}

export function Field({ label, hint, ...inputProps }: FieldProps): JSX.Element {
  const id = useId();
  const hintId = `${id}-hint`;

  return (
    <div className="field">
      <label htmlFor={id}>
        <span>{label}</span>
      </label>
      <input id={id} {...(hint ? { 'aria-describedby': hintId } : {})} {...inputProps} />
      {hint && (
        <span className="hint" id={hintId}>
          {hint}
        </span>
      )}
    </div>
  );
}
