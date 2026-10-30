import type { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { createCommandExecutor } from '../../src/application/commands/executeCommand';
import type { CommandContext } from '../../src/contracts/common';
import type { CommandAcknowledgement, CommandFingerprint, CommandInput, CommandTransaction, RetainedCommandProblem, SafeCommandAcknowledgement, StoredCommandReceipt } from '../../src/contracts/commands';
import { adapt } from './fixture';
import { inTransaction, type ProofClient } from './protocol';

export class FixtureAuthorizationError extends Error {
  constructor() { super('Fixture owner or active dataset authorization denied.'); this.name = 'FixtureAuthorizationError'; }
}
export interface ExecutionHooks {
  onClient?: (pid: number) => void;
  beforeHandler?: () => Promise<void>;
  afterDomain?: () => Promise<void>;
  afterOutbox?: () => Promise<void>;
  afterReceipt?: () => Promise<void>;
  unsafeAcknowledgement?: boolean;
  simulateLostCommitAcknowledgement?: boolean;
  lockTimeoutMs?: number;
  onHandler?: () => void;
}
class PostgresTransaction implements CommandTransaction {
  constructor(private readonly client: ProofClient, private readonly hooks: ExecutionHooks) {}
  async authorizeCurrentDataset(context: CommandContext): Promise<void> {
    const owner = await this.client.query('SELECT current_epoch FROM jls_command_proof.owners WHERE owner_id=$1 AND active FOR SHARE', [context.ownerId]);
    if (owner.rows[0]?.current_epoch !== context.datasetEpoch) throw new FixtureAuthorizationError();
    const dataset = await this.client.query('SELECT dataset_epoch FROM jls_command_proof.datasets WHERE owner_id=$1 AND dataset_epoch=$2 AND active FOR SHARE', [context.ownerId, context.datasetEpoch]);
    if (dataset.rows.length !== 1) throw new FixtureAuthorizationError();
  }
  async lockOperation(context: CommandContext): Promise<void> {
    // hash collisions only serialize; all subsequent matching and unique identity use full UUIDs.
    await this.client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [JSON.stringify([context.ownerId, context.datasetEpoch, context.operationId])]);
  }
  async readReceipt(context: CommandContext): Promise<StoredCommandReceipt<SafeCommandAcknowledgement> | null> {
    const result = await this.client.query('SELECT owner_id, policy, fingerprint, receipt FROM jls_command_proof.receipts WHERE owner_id=$1 AND dataset_epoch=$2 AND operation_id=$3', [context.ownerId, context.datasetEpoch, context.operationId]);
    const row = result.rows[0];
    return row ? { ownerId: String(row.owner_id), fingerprint: { policy: row.policy as CommandFingerprint['policy'], hash: String(row.fingerprint) }, receipt: row.receipt as StoredCommandReceipt<SafeCommandAcknowledgement>['receipt'] } : null;
  }
  async saveReceipt(context: CommandContext, fingerprint: CommandFingerprint, data: SafeCommandAcknowledgement, rejection?: RetainedCommandProblem): Promise<StoredCommandReceipt<SafeCommandAcknowledgement>> {
    if (!("resourceId" in data)) throw new Error("Fixture accepts only base safe acknowledgements.");
    const receipt = { operationId: context.operationId, datasetEpoch: context.datasetEpoch, data, ...(rejection ? { rejection } : {}) };
    await this.client.query('INSERT INTO jls_command_proof.receipts(owner_id,dataset_epoch,operation_id,aggregate_id,policy,fingerprint,receipt) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)', [context.ownerId, context.datasetEpoch, context.operationId, data.resourceId, fingerprint.policy, fingerprint.hash, JSON.stringify(receipt)]);
    await this.hooks.afterReceipt?.();
    return { ownerId: context.ownerId, fingerprint, receipt };
  }
}
/** Synthetic update/answer/finish conformance only; not the product learning implementation. */
async function fixtureHandler(client: ProofClient, context: CommandContext, snapshot: CommandInput, hooks: ExecutionHooks) {
  hooks.onHandler?.();
  await hooks.beforeHandler?.();
  const result = await client.query('SELECT version::text, state FROM jls_command_proof.aggregates WHERE owner_id=$1 AND dataset_epoch=$2 AND aggregate_id=$3 FOR UPDATE', [context.ownerId, context.datasetEpoch, snapshot.targetId]);
  const aggregate = result.rows[0];
  if (!aggregate) throw new FixtureAuthorizationError();
  const version = Number(aggregate.version);
  if (!Number.isSafeInteger(version) || version < 0) throw new Error('Invalid synthetic aggregate version.');
  const stateConflict = aggregate.state !== 'open';
  if (version !== context.expectedVersion || stateConflict) {
    const conflictId = randomUUID();
    await client.query('INSERT INTO jls_command_proof.proposals VALUES ($1,$2,$3,$4,$5,$6)', [context.ownerId, context.datasetEpoch, conflictId, context.operationId, snapshot.targetId, String(snapshot.body.text)]);
    return { kind: 'proposalRetained' as const, data: { resourceId: snapshot.targetId, resourceVersion: version, conflictId }, rejection: { code: stateConflict ? 'execution_conflict' as const : 'version_conflict' as const, status: stateConflict ? 409 as const : 412 as const, conflictId, currentVersion: version } };
  }
  if (version === Number.MAX_SAFE_INTEGER) throw new Error('Synthetic aggregate version exhausted.');
  const data: CommandAcknowledgement = { resourceId: snapshot.targetId, resourceVersion: version + 1 };
  await client.query('UPDATE jls_command_proof.aggregates SET version=$4, content=$5, state=$6 WHERE owner_id=$1 AND dataset_epoch=$2 AND aggregate_id=$3', [context.ownerId, context.datasetEpoch, snapshot.targetId, version + 1, String(snapshot.body.text), snapshot.kind === 'fixture.finish' ? 'closed' : 'open']);
  await hooks.afterDomain?.();
  await client.query('INSERT INTO jls_command_proof.outbox VALUES ($1,$2,$3,$4,$5::jsonb)', [context.ownerId, context.datasetEpoch, context.operationId, snapshot.targetId, JSON.stringify(data)]);
  await hooks.afterOutbox?.();
  return hooks.unsafeAcknowledgement ? { ...data, proposedText: snapshot.body.text } : data;
}
export async function executeFixture(pool: Pool, context: CommandContext, payload: unknown, hooks: ExecutionHooks = {}, subject = context.ownerId) {
  const client = adapt(await pool.connect());
  return inTransaction(client, subject.toLowerCase(), context.datasetEpoch.toLowerCase(), async tx => {
    const identity = await tx.query('SELECT pg_backend_pid() AS pid, current_user AS actor');
    if (identity.rows[0]?.actor !== 'jls_command_actor') throw new Error('Fixture must execute under restricted actor.');
    hooks.onClient?.(Number(identity.rows[0]?.pid));
    if (hooks.lockTimeoutMs !== undefined) {
      if (!Number.isSafeInteger(hooks.lockTimeoutMs) || hooks.lockTimeoutMs < 1 || hooks.lockTimeoutMs > 3000) throw new Error('Invalid fixture lock timeout.');
      await tx.query("SELECT set_config('lock_timeout', $1, true)", [`${hooks.lockTimeoutMs}ms`]);
    }
    const executor = createCommandExecutor(new PostgresTransaction(tx, hooks));
    return executor(context, payload, snapshot => fixtureHandler(tx, { ...context, ownerId: context.ownerId.toLowerCase(), datasetEpoch: context.datasetEpoch.toLowerCase(), operationId: context.operationId.toLowerCase() }, snapshot, hooks));
  }, hooks);
}
