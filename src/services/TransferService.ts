import { randomBytes } from 'node:crypto';
import { v7 as uuidv7 } from 'uuid';

import {
  ForbiddenError,
  NotFoundError,
  RouteError,
  ValidationError,
} from '#src/common/classes/route-errors.ts';
import { Env } from '#src/common/constants/env.constants.ts';
import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import {
  encryptField,
  verifyP256Signature,
} from '#src/common/utils/crypto.utils.ts';
import { istDayStartIso, istToday } from '#src/common/utils/date.utils.ts';
import {
  generateTxnReference,
  maskMobile,
  paiseToRupees,
} from '#src/common/utils/money.utils.ts';
import type { ApiResponse } from '#src/common/utils/response.utils.ts';
import db, { withWriteTransaction } from '#src/db/client.ts';
import {
  type Approval,
  type ChallengeInput,
  transferHash,
  type TransferInput,
  type TransferPayload,
  transferSigningPayload,
} from '#src/entities/Transfer/index.ts';
import type { AuthContext } from '#src/middleware/auth.ts';
import AuditRepo, { AuditActions } from '#src/repos/AuditRepo.ts';
import DeviceRepo from '#src/repos/DeviceRepo.ts';
import PinRepo from '#src/repos/PinRepo.ts';
import TransferRepo from '#src/repos/TransferRepo.ts';
import WalletRepo from '#src/repos/WalletRepo.ts';

import type { RequestContext } from './AuthService.ts';
import PinService from './PinService.ts';

// ========================================================================= //
//                                   TYPES                                   //
// ========================================================================= //

export interface ChallengeResult {
  challengeId: string;
  nonce: string;
  expiresAt: string;
  approvalMethods: ('BIOMETRIC' | 'PIN')[];
  /** Exact string the biometric key must sign (BIOMETRIC approval). */
  signingPayload: string;
  summary: {
    beneficiaryName: string;
    mobileNumber: string;
    amount: number;
    currency: 'INR';
    remarks: string | null;
  };
}

export interface TransferResult {
  transactionId: string;
  status: 'SUCCESS';
  amount: number;
  currency: 'INR';
  availableBalance: number;
  beneficiaryName: string;
  mobileNumber: string;
  remarks: string | null;
  approvalMethod: 'BIOMETRIC' | 'PIN';
  createdAt: string;
}

export interface TransferOutcome {
  statusCode: number;
  response: ApiResponse<TransferResult>;
  replayed: boolean;
}

// ========================================================================= //
//                                  HELPERS                                  //
// ========================================================================= //

const err = (status: HttpStatusCodes, message: string, code: string) =>
  new RouteError(status, message, code);

const insufficient = () =>
  err(
    HttpStatusCodes.CONFLICT,
    'Insufficient wallet balance',
    'INSUFFICIENT_BALANCE',
  );

const frozen = () =>
  new ForbiddenError(
    'Your wallet is frozen. Please contact support.',
    'WALLET_FROZEN',
  );

const dailyLimit = () =>
  new ForbiddenError(
    `Daily transfer limit of ₹${Env.DAILY_TRANSFER_LIMIT.toLocaleString('en-IN')} reached`,
    'DAILY_LIMIT_EXCEEDED',
  );

function toPayload(i: ChallengeInput | TransferInput): TransferPayload {
  return {
    beneficiaryName: i.beneficiaryName,
    mobileNumber: i.mobileNumber,
    amountPaise: i.amountPaise,
    remarks: i.remarks,
  };
}

/** PIN must exist and not be locked, for either approval method. */
async function assertPinUsable(userId: string): Promise<void> {
  const pin = await PinRepo.find(userId);
  if (!pin) {
    throw new ForbiddenError(PinService.Errors.NOT_SET, 'PIN_NOT_SET');
  }
  if (pin.lockedUntil && Date.parse(pin.lockedUntil) > Date.now()) {
    const hours = Math.max(
      1,
      Math.ceil((Date.parse(pin.lockedUntil) - Date.now()) / 3_600_000),
    );
    throw err(
      HttpStatusCodes.LOCKED,
      PinService.Errors.LOCKED(hours),
      'PIN_LOCKED',
    );
  }
}

/** Checks shared by challenge and transfer, before any money moves. */
function assertWithinLimits(amountPaise: number): void {
  if (amountPaise > Env.MAX_TRANSFER_AMOUNT * 100) {
    throw new ValidationError([
      {
        field: 'amount',
        message: `Maximum per transfer is ₹${Env.MAX_TRANSFER_AMOUNT.toLocaleString('en-IN')}`,
      },
    ]);
  }
}

// ========================================================================= //
//                                 CHALLENGE                                 //
// ========================================================================= //

/**
 * Step 1 — validate the transfer and issue a one-time challenge bound to it.
 * Fails fast on: no PIN / PIN locked, frozen wallet, over limits, insufficient
 * balance. The balance is checked again atomically at transfer time.
 */
async function createChallenge(
  auth: AuthContext,
  input: ChallengeInput,
  ctx: RequestContext,
): Promise<ChallengeResult> {
  const payload = toPayload(input);
  assertWithinLimits(payload.amountPaise);
  await assertPinUsable(auth.userId);

  const wallet = await WalletRepo.findByUserId(auth.userId);
  if (!wallet) throw new NotFoundError('Wallet not found', 'WALLET_NOT_FOUND');
  if (wallet.status !== 'ACTIVE') throw frozen();
  if (wallet.balancePaise < payload.amountPaise) throw insufficient();

  const spentToday = await TransferRepo.sumDebitsSince(
    db,
    auth.userId,
    istDayStartIso(istToday()),
  );
  if (spentToday + payload.amountPaise > Env.DAILY_TRANSFER_LIMIT * 100) {
    throw dailyLimit();
  }

  const now = Date.now();
  const challengeId = uuidv7();
  const nonce = randomBytes(32).toString('base64url');
  const payloadHash = transferHash(payload);
  const expiresAt = new Date(now + Env.CHALLENGE_TTL_SEC * 1000).toISOString();

  await TransferRepo.insertChallenge({
    id: challengeId,
    userId: auth.userId,
    sessionId: auth.sessionId,
    nonce,
    payloadHash,
    expiresAt,
    createdAt: new Date(now).toISOString(),
  });
  await AuditRepo.record({
    userId: auth.userId,
    action: AuditActions.TRANSFER_CHALLENGE,
    ip: ctx.ip,
    deviceId: auth.deviceId,
    requestId: ctx.requestId,
    metadata: { challengeId, amountPaise: payload.amountPaise },
  });

  const biometric =
    auth.deviceId !== null &&
    (await DeviceRepo.isBiometricEnrolled(auth.userId, auth.deviceId));

  return {
    challengeId,
    nonce,
    expiresAt,
    approvalMethods: biometric ? ['BIOMETRIC', 'PIN'] : ['PIN'],
    signingPayload: transferSigningPayload(challengeId, nonce, payloadHash),
    summary: {
      beneficiaryName: payload.beneficiaryName,
      mobileNumber: maskMobile(payload.mobileNumber),
      amount: paiseToRupees(payload.amountPaise),
      currency: 'INR',
      remarks: payload.remarks,
    },
  };
}

// ========================================================================= //
//                                 TRANSFER                                  //
// ========================================================================= //

/** Verify the user's approval (biometric signature or PIN) for this challenge. */
async function verifyApproval(
  auth: AuthContext,
  approval: Approval,
  signingPayload: string,
  ctx: RequestContext,
): Promise<void> {
  if (approval.method === 'PIN') {
    await PinService.verifyPin(auth.userId, approval.pin, {
      ...ctx,
      deviceId: auth.deviceId,
    });
    return;
  }

  // BIOMETRIC: a locked PIN blocks all transfers, like UPI.
  await assertPinUsable(auth.userId);
  const key = auth.deviceId
    ? await DeviceRepo.getBiometricKey(auth.userId, auth.deviceId)
    : null;
  if (!key) {
    throw new ForbiddenError(
      'Biometric approval is not enabled on this device. Use your PIN.',
      'BIOMETRIC_NOT_ENROLLED',
    );
  }
  if (!verifyP256Signature(key, signingPayload, approval.signature)) {
    throw new ForbiddenError(
      'Biometric verification failed',
      'INVALID_SIGNATURE',
    );
  }
}

function replay(stored: {
  responseStatus: number;
  responseBody: string;
}): TransferOutcome {
  return {
    statusCode: stored.responseStatus,
    response: JSON.parse(stored.responseBody) as ApiResponse<TransferResult>,
    replayed: true,
  };
}

/**
 * Step 2 — move the money. Order matters:
 * 1. Idempotency: same key + same body → original result, no second debit;
 *    same key + different body → 409. (Checked first so a lost response can be
 *    retried even though its challenge is already used.)
 * 2. Challenge: exists, belongs to this login, unused, unexpired, and its hash
 *    matches this exact body (nothing changed after approval).
 * 3. Approval: biometric signature over the challenge, or PIN (with lockout).
 * 4. One write transaction: consume challenge, enforce daily limit, debit only
 *    if balance is enough right now, record the transaction and the
 *    idempotency result. All or nothing.
 */
async function transfer(
  auth: AuthContext,
  input: TransferInput,
  idempotencyKey: string,
  ctx: RequestContext,
): Promise<TransferOutcome> {
  const payload = toPayload(input);
  const requestHash = transferHash(payload);
  const audit = {
    userId: auth.userId,
    ip: ctx.ip,
    deviceId: auth.deviceId,
    requestId: ctx.requestId,
  };

  try {
    // 1. Idempotency
    const prior = await TransferRepo.findIdempotency(
      db,
      auth.userId,
      idempotencyKey,
    );
    if (prior) {
      if (prior.requestHash !== requestHash) {
        throw err(
          HttpStatusCodes.CONFLICT,
          'This Idempotency-Key was already used for a different transfer',
          'IDEMPOTENCY_KEY_REUSED',
        );
      }
      await AuditRepo.record({
        ...audit,
        action: AuditActions.TRANSFER_REPLAYED,
      });
      return replay(prior);
    }

    // 2. Challenge
    const challenge = await TransferRepo.findChallenge(input.challengeId);
    if (
      !challenge ||
      challenge.userId !== auth.userId ||
      challenge.familyId !== auth.familyId
    ) {
      throw err(
        HttpStatusCodes.BAD_REQUEST,
        'Invalid transfer challenge',
        'INVALID_CHALLENGE',
      );
    }
    if (challenge.usedAt) {
      throw err(
        HttpStatusCodes.CONFLICT,
        'This transfer was already submitted. Start a new transfer.',
        'CHALLENGE_USED',
      );
    }
    if (Date.parse(challenge.expiresAt) <= Date.now()) {
      throw err(
        HttpStatusCodes.BAD_REQUEST,
        'Approval timed out. Please try again.',
        'CHALLENGE_EXPIRED',
      );
    }
    if (challenge.payloadHash !== requestHash) {
      throw err(
        HttpStatusCodes.BAD_REQUEST,
        'Transfer details do not match what was approved',
        'CHALLENGE_MISMATCH',
      );
    }
    assertWithinLimits(payload.amountPaise);

    // 3. Approval
    await verifyApproval(
      auth,
      input.approval,
      transferSigningPayload(
        challenge.id,
        challenge.nonce,
        challenge.payloadHash,
      ),
      ctx,
    );

    // 4. Atomic money movement
    const outcome = await withWriteTransaction<TransferOutcome>(async (tx) => {
      const raced = await TransferRepo.findIdempotency(
        tx,
        auth.userId,
        idempotencyKey,
      );
      if (raced) {
        if (raced.requestHash !== requestHash) {
          throw err(
            HttpStatusCodes.CONFLICT,
            'This Idempotency-Key was already used for a different transfer',
            'IDEMPOTENCY_KEY_REUSED',
          );
        }
        return replay(raced);
      }

      const nowDate = new Date();
      const now = nowDate.toISOString();
      const consumed = await tx.execute(
        TransferRepo.consumeChallengeStmt(challenge.id, now),
      );
      if (consumed.rowsAffected === 0) {
        throw err(
          HttpStatusCodes.CONFLICT,
          'This transfer was already submitted. Start a new transfer.',
          'CHALLENGE_USED',
        );
      }

      const spentToday = await TransferRepo.sumDebitsSince(
        tx,
        auth.userId,
        istDayStartIso(istToday()),
      );
      if (spentToday + payload.amountPaise > Env.DAILY_TRANSFER_LIMIT * 100) {
        throw dailyLimit();
      }

      const debited = await TransferRepo.debitWallet(
        tx,
        auth.userId,
        payload.amountPaise,
        now,
      );
      if (!debited) {
        const wallet = await WalletRepo.findByUserId(auth.userId);
        if (!wallet) {
          throw new NotFoundError('Wallet not found', 'WALLET_NOT_FOUND');
        }
        throw wallet.status !== 'ACTIVE' ? frozen() : insufficient();
      }

      const reference = generateTxnReference(nowDate);
      const result: TransferResult = {
        transactionId: reference,
        status: 'SUCCESS',
        amount: paiseToRupees(payload.amountPaise),
        currency: 'INR',
        availableBalance: paiseToRupees(debited.balancePaise),
        beneficiaryName: payload.beneficiaryName,
        mobileNumber: maskMobile(payload.mobileNumber),
        remarks: payload.remarks,
        approvalMethod: input.approval.method,
        createdAt: now,
      };
      const response: ApiResponse<TransferResult> = {
        meta: {
          statusCode: HttpStatusCodes.OK,
          message: 'Transfer successful',
        },
        body: result,
      };

      for (const stmt of [
        TransferRepo.insertTransactionStmt({
          id: uuidv7(),
          reference,
          walletId: debited.walletId,
          userId: auth.userId,
          amountPaise: payload.amountPaise,
          counterpartyName: payload.beneficiaryName,
          mobileEnc: encryptField(payload.mobileNumber),
          mobileMasked: maskMobile(payload.mobileNumber),
          remarks: payload.remarks,
          balanceAfterPaise: debited.balancePaise,
          approvalMethod: input.approval.method,
          idempotencyKey,
          createdAt: now,
        }),
        TransferRepo.insertIdempotencyStmt({
          userId: auth.userId,
          key: idempotencyKey,
          requestHash,
          responseStatus: HttpStatusCodes.OK,
          responseBody: JSON.stringify(response),
          createdAt: now,
        }),
        AuditRepo.insertStmt(
          {
            ...audit,
            action: AuditActions.TRANSFER_OK,
            metadata: {
              reference,
              amountPaise: payload.amountPaise,
              approvalMethod: input.approval.method,
            },
          },
          now,
        ),
      ]) {
        await tx.execute(stmt);
      }

      return { statusCode: HttpStatusCodes.OK, response, replayed: false };
    });

    return outcome;
  } catch (e) {
    if (e instanceof RouteError) {
      await AuditRepo.record({
        ...audit,
        action: AuditActions.TRANSFER_REJECTED,
        metadata: { errorCode: e.errorCode, amountPaise: payload.amountPaise },
      });
    }
    throw e;
  }
}

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default {
  createChallenge,
  transfer,
} as const;
