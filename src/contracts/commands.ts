import type { CommandContext, Uuid } from './common';
import type { DomainAcknowledgement } from './acknowledgements';

export interface CommandInput {
  readonly kind: string;
  readonly targetId: Uuid;
  readonly body: Readonly<Record<string, unknown>>;
}
export interface CommandFingerprint {
  readonly policy: 'jls-command-json-v1';
  readonly hash: string;
}

/** Replayable acknowledgements contain identifiers/versions, never answer keys or note bodies. */
export interface CommandAcknowledgement {
  readonly resourceId: Uuid;
  readonly resourceVersion: number;
  readonly jobId?: Uuid;
  readonly conflictId?: Uuid;
  readonly createdRows?: readonly { readonly clientRowId: Uuid; readonly draftId: Uuid }[];
}
export type SafeCommandAcknowledgement = CommandAcknowledgement | DomainAcknowledgement;
export interface CommandReceipt<T> {
  readonly operationId: Uuid;
  readonly datasetEpoch: Uuid;
  readonly data: T;
  readonly rejection?: RetainedCommandProblem;
}
export interface RetainedCommandProblem {
  readonly code: 'version_conflict' | 'execution_conflict';
  readonly status: 409 | 412;
  readonly conflictId: Uuid;
  readonly currentVersion: number;
}
/** A persisted conflict is a committed result, not an exception inside the transaction. */
export interface RetainedCommandConflict<T extends SafeCommandAcknowledgement> {
  readonly kind: 'proposalRetained';
  readonly data: T;
  readonly rejection: RetainedCommandProblem;
}
/** Precise output types require a pure runtime validator bound to the exact command kind. */
export interface CommandOutputContract<T extends SafeCommandAcknowledgement> {
  readonly kind: string;
  parse(input: unknown): T;
}
export type CommandExecutor<T extends SafeCommandAcknowledgement> = (
  context: CommandContext,
  payload: unknown,
  handler: (snapshot: CommandInput) => Promise<T | RetainedCommandConflict<T>>,
) => Promise<CommandReceipt<T>>;
export interface StoredCommandReceipt<T extends SafeCommandAcknowledgement = CommandAcknowledgement> {
  readonly ownerId: Uuid;
  readonly fingerprint: CommandFingerprint;
  readonly receipt: CommandReceipt<T>;
}

/**
 * Adapter obligation: every method and handler mutation uses ONE already-open DB transaction.
 * Authorization locks/revalidates current owner+epoch. Operation locking lasts until commit/rollback.
 * The unit of work commits only after the executor resolves and rolls back when it throws.
 * No implementation is provided here: these methods do not establish durable behavior by themselves.
 */
export interface CommandTransaction {
  authorizeCurrentDataset(context: CommandContext): Promise<void>;
  lockOperation(context: CommandContext): Promise<void>;
  readReceipt(context: CommandContext): Promise<StoredCommandReceipt<SafeCommandAcknowledgement> | null>;
  saveReceipt(context: CommandContext, fingerprint: CommandFingerprint, data: SafeCommandAcknowledgement, rejection?: RetainedCommandProblem): Promise<StoredCommandReceipt<SafeCommandAcknowledgement>>;
}

export class CommandExecutionError extends Error {
  constructor(readonly code: 'invalid_command' | 'idempotency_key_reused' | 'unsafe_command_acknowledgement' | 'receipt_integrity_error' | 'receipt_policy_unsupported', readonly status: 409 | 422 | 503, options?: ErrorOptions) {
    super(code, options);
    this.name = 'CommandExecutionError';
  }
}
