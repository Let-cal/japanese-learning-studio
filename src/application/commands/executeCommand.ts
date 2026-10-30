import { inspectObject, ownField, parseUuid, parseVersion } from '../../contracts/common';
import type { CommandContext } from '../../contracts/common';
import { CommandExecutionError } from '../../contracts/commands';
import type { CommandAcknowledgement, CommandExecutor, CommandFingerprint, CommandOutputContract, CommandReceipt, CommandTransaction, RetainedCommandProblem, SafeCommandAcknowledgement, StoredCommandReceipt } from '../../contracts/commands';
import { domainAcknowledgement, isAcknowledgementKind } from '../../contracts/acknowledgements';
import { createProblem } from '../../contracts/problems';
import { COMMAND_HASH_POLICY, canonicalCommandContext, canonicalCommandJson, prepareCommandInput } from './commandFingerprint';

function safeContainer(input: unknown) {
  try { canonicalCommandJson(input); }
  catch (cause) { throw new CommandExecutionError('unsafe_command_acknowledgement', 503, { cause }); }
}

function acknowledgement(input: unknown): CommandAcknowledgement {
  const fail = (): never => { throw new CommandExecutionError('unsafe_command_acknowledgement', 503); };
  safeContainer(input);
  const { record, errors } = inspectObject(input, ['resourceId', 'resourceVersion', 'jobId', 'conflictId', 'createdRows']);
  if (!record || errors.length) return fail();
  const id = parseUuid(ownField(record, 'resourceId')); const version = parseVersion(ownField(record, 'resourceVersion'));
  if (!id.ok || !version.ok) return fail();
  const result: { resourceId: string; resourceVersion: number; jobId?: string; conflictId?: string; createdRows?: { clientRowId: string; draftId: string }[] } = {
    resourceId: id.value.toLowerCase(), resourceVersion: version.value,
  };
  for (const field of ['jobId', 'conflictId'] as const) {
    if (Object.hasOwn(record, field)) {
      const id = parseUuid(record[field]); if (!id.ok) return fail();
      result[field] = id.value.toLowerCase();
    }
  }
  if (Object.hasOwn(record, 'createdRows')) {
    if (!Array.isArray(record.createdRows) || record.createdRows.length < 1 || record.createdRows.length > 10) return fail();
    result.createdRows = [];
    const ids = new Set<string>();
    for (const row of record.createdRows) {
      const parsed = inspectObject(row, ['clientRowId', 'draftId']);
      if (!parsed.record || parsed.errors.length) return fail();
      const client = parseUuid(ownField(parsed.record, 'clientRowId')); const draft = parseUuid(ownField(parsed.record, 'draftId'));
      if (!client.ok || !draft.ok || ids.has(client.value.toLowerCase())) return fail();
      ids.add(client.value.toLowerCase()); result.createdRows.push({ clientRowId: client.value.toLowerCase(), draftId: draft.value.toLowerCase() });
    }
  }
  return result;
}

function retainedProblem(input: unknown): RetainedCommandProblem {
  safeContainer(input);
  const { record, errors } = inspectObject(input, ['code', 'status', 'conflictId', 'currentVersion']);
  if (!record || errors.length) throw new CommandExecutionError('unsafe_command_acknowledgement', 503);
  const code = ownField(record, 'code'); const status = ownField(record, 'status');
  const id = parseUuid(ownField(record, 'conflictId')); const version = parseVersion(ownField(record, 'currentVersion'));
  if (!id.ok || !version.ok || !((code === 'version_conflict' && status === 412) || (code === 'execution_conflict' && status === 409))) throw new CommandExecutionError('unsafe_command_acknowledgement', 503);
  return { code, status, conflictId: id.value.toLowerCase(), currentVersion: version.value };
}

type AcknowledgementValidator = (input: unknown) => SafeCommandAcknowledgement;
function handlerOutcome(input: unknown, validateData: AcknowledgementValidator): { data: SafeCommandAcknowledgement; rejection?: RetainedCommandProblem } {
  if (input !== null && typeof input === 'object' && Object.hasOwn(input, 'kind')) {
    safeContainer(input);
    const { record, errors } = inspectObject(input, ['kind', 'data', 'rejection']);
    if (!record || errors.length || ownField(record, 'kind') !== 'proposalRetained') throw new CommandExecutionError('unsafe_command_acknowledgement', 503);
    return { data: validateData(ownField(record, 'data')), rejection: retainedProblem(ownField(record, 'rejection')) };
  }
  return { data: validateData(input) };
}

function safeStoredReceipt(stored: StoredCommandReceipt<SafeCommandAcknowledgement>, context: CommandContext, fingerprint: CommandFingerprint, validateData: AcknowledgementValidator): CommandReceipt<SafeCommandAcknowledgement> {
  if (stored === null || typeof stored !== 'object' || stored.ownerId !== context.ownerId ||
      !stored.receipt || stored.receipt.datasetEpoch !== context.datasetEpoch || stored.receipt.operationId !== context.operationId ||
      !stored.fingerprint || typeof stored.fingerprint.hash !== 'string' || !/^[a-f0-9]{64}$/.test(stored.fingerprint.hash)) {
    throw new CommandExecutionError('receipt_integrity_error', 503);
  }
  if (stored.fingerprint.policy !== COMMAND_HASH_POLICY) throw new CommandExecutionError('receipt_policy_unsupported', 503);
  if (stored.fingerprint.hash !== fingerprint.hash) throw new CommandExecutionError('idempotency_key_reused', 409);
  const rejection = Object.hasOwn(stored.receipt, 'rejection') ? retainedProblem(stored.receipt.rejection) : undefined;
  return { operationId: context.operationId, datasetEpoch: context.datasetEpoch, data: validateData(stored.receipt.data), ...(rejection ? { rejection } : {}) };
}

/**
 * Bind inside a unit-of-work callback; handler closes over that SAME transaction's repositories.
 * Handlers consume the supplied immutable snapshot and transaction-scoped repositories.
 * Existing zero-argument handlers remain assignable; do not close over mutable request payloads.
 * The adapter is responsible for real locks, durable uniqueness, atomic commit/rollback and outbox.
 */
function bindExecutor<T extends SafeCommandAcknowledgement>(transaction: CommandTransaction, output: { readonly kind?: string; parse(input: unknown): T }): CommandExecutor<T> {
  const validateData: AcknowledgementValidator = input => {
    safeContainer(input);
    if (output.kind !== undefined && isAcknowledgementKind(output.kind)) {
      try { return domainAcknowledgement(output.kind, input); }
      catch (cause) { throw new CommandExecutionError('unsafe_command_acknowledgement', 503, { cause }); }
    }
    return acknowledgement(input);
  };
  function typedReceipt(receipt: CommandReceipt<SafeCommandAcknowledgement>): CommandReceipt<T> {
    try {
      const typed = output.parse(structuredClone(receipt.data));
      validateData(typed);
      if (canonicalCommandJson(typed) !== canonicalCommandJson(receipt.data)) throw new TypeError('Output validators must not add, remove or transform receipt data.');
      return { ...receipt, data: structuredClone(typed) };
    } catch (cause) {
      throw new CommandExecutionError('receipt_integrity_error', 503, { cause });
    }
  }
  return async function executeCommand(context, payload, handler) {
    const current = canonicalCommandContext(context);
    await transaction.authorizeCurrentDataset(current);
    const prepared = prepareCommandInput(current, payload);
    if (output.kind !== undefined && output.kind !== prepared.command.kind) throw new CommandExecutionError('invalid_command', 422);
    if (output.kind === undefined && isAcknowledgementKind(prepared.command.kind)) throw new CommandExecutionError('invalid_command', 422);
    await transaction.lockOperation(current);
    const fingerprint = Object.freeze(prepared.fingerprint);
    const cached = await transaction.readReceipt(current);
    if (cached !== null) return typedReceipt(safeStoredReceipt(cached, current, fingerprint, validateData));
    // Preconditions/session-state checks belong to the handler and are never run for a replay.
    const outcome = handlerOutcome(await handler(prepared.command), validateData);
    typedReceipt({ operationId: current.operationId, datasetEpoch: current.datasetEpoch, data: outcome.data, ...(outcome.rejection ? { rejection: outcome.rejection } : {}) });
    const expectedOutcome = canonicalCommandJson({ data: outcome.data, rejection: outcome.rejection ?? null });
    const stored = await transaction.saveReceipt(current, fingerprint, outcome.data, outcome.rejection);
    const receipt = safeStoredReceipt(stored, current, fingerprint, validateData);
    if (canonicalCommandJson({ data: receipt.data, rejection: receipt.rejection ?? null }) !== expectedOutcome) throw new CommandExecutionError('receipt_integrity_error', 503);
    return typedReceipt(receipt);
  };
}

export function createCommandExecutor(transaction: CommandTransaction): CommandExecutor<CommandAcknowledgement>;
export function createCommandExecutor<T extends SafeCommandAcknowledgement>(transaction: CommandTransaction, output: CommandOutputContract<T>): CommandExecutor<T>;
export function createCommandExecutor<T extends SafeCommandAcknowledgement>(transaction: CommandTransaction, output?: CommandOutputContract<T>) {
  return output ? bindExecutor(transaction, output) : bindExecutor(transaction, { parse: acknowledgement });
}

/** Project only AFTER the enclosing unit of work has resolved/committed. Never throw inside it. */
export function committedCommandProblem<T>(receipt: CommandReceipt<T>, requestId: string) {
  if (!receipt.rejection) return undefined;
  const problem = retainedProblem(receipt.rejection);
  const request = parseUuid(requestId);
  if (!request.ok) throw new CommandExecutionError('invalid_command', 422);
  return createProblem(problem.code, request.value.toLowerCase(), { conflictId: problem.conflictId, currentVersion: problem.currentVersion });
}
