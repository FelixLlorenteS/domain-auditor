/**
 * Text of a finding in two layers:
 * - `title`, `what` and `steps` in plain language, for anyone;
 * - `tech`, the technical detail, folded by default.
 * `detail` carries data (a record, a list of hosts) and is shown as-is.
 */
export interface Message {
  title: string;
  detail?: string;
  what?: string;
  steps?: string[];
  tech?: string;
  /**
   * When the result may be right or wrong depending on things an outside check
   * cannot see (other services, a migration in progress, a deliberate choice).
   */
  context?: string;
}

export type Messages = Record<string, Message>;
