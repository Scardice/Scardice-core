package dice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

var (
	ErrDomainExecutionUnavailable = errors.New("dice: durable execution is unavailable")
	ErrDomainExecutionInProgress  = errors.New("dice: execution is already started")
	ErrDomainExecutionAmbiguous   = errors.New("dice: execution outcome is ambiguous")
	ErrDomainExecutionUnknown     = errors.New("dice: execution outcome is unknown")
)

type domainLeaseResult struct {
	receipt eventstore.ExecutionReceipt
	err     error
}

// WithDomainExecution owns one independent Host invocation. Existing callbacks
// and their children must inherit their transaction instead of calling it.
func (d *Dice) WithDomainExecution(ctx context.Context, identity string, canonicalRequest []byte, run func(*DurableCallbackTransaction) error) error {
	if d == nil || d.DurableStore == nil || run == nil {
		return ErrDomainExecutionUnavailable
	}
	return withDomainExecution(ctx, d.DurableStore, identity, canonicalRequest, func(transaction *DurableCallbackTransaction) error {
		if err := d.ContributeConfigView(transaction.executionContext, transaction.Domain()); err != nil {
			return err
		}
		return run(transaction)
	})
}

func withDomainExecution(ctx context.Context, store eventstore.Store, identity string, canonicalRequest []byte, run func(*DurableCallbackTransaction) error) (err error) {
	if store == nil || run == nil {
		return ErrDomainExecutionUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	repository, ok := store.(eventstore.ExecutionReceiptRepository)
	if !ok {
		return ErrDomainExecutionUnavailable
	}
	digest, err := repository.ExecutionRequestDigest(ctx, canonicalRequest)
	if err != nil {
		return err
	}
	owner, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return err
	}
	receipt, err := repository.AdmitExecution(ctx, eventstore.ExecutionAdmissionRequest{
		Identity: identity, RequestDigest: digest, LeaseOwner: owner,
		LeaseDuration: eventstore.DefaultExecutionLease,
	})
	if err != nil {
		return err
	}
	if !receipt.Admitted {
		switch receipt.Status {
		case eventstore.ExecutionStatusCommitted:
			return nil
		case eventstore.ExecutionStatusStarted:
			return ErrDomainExecutionInProgress
		case eventstore.ExecutionStatusAmbiguous:
			return ErrDomainExecutionAmbiguous
		default:
			return ErrDomainExecutionUnknown
		}
	}

	hostCtx, cancelHost := context.WithCancelCause(ctx)
	defer cancelHost(context.Canceled)
	stop, done := make(chan struct{}), make(chan domainLeaseResult, 1)
	go keepDomainExecutionLease(hostCtx, cancelHost, repository, identity, digest, receipt, stop, done)
	joined := false
	var heartbeat domainLeaseResult
	joinHeartbeat := func() domainLeaseResult {
		if !joined {
			close(stop)
			heartbeat = <-done
			joined = true
			receipt = heartbeat.receipt
		}
		return heartbeat
	}
	var transaction *DurableCallbackTransaction
	committed, submitted := false, false
	var releaseFence func()
	defer func() {
		defer func() {
			if releaseFence != nil {
				releaseFence()
			}
		}()
		joinHeartbeat()
		if committed {
			return
		}
		defer func() {
			if !committed && transaction != nil && transaction.Domain() != nil {
				transaction.Domain().Abort()
			}
		}()
		// This also executes while a Host panic unwinds. Keep the original panic;
		// only its durable started evidence is finalized here.
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		outcome, recoveryErr := reconcileDomainExecution(recoveryCtx, repository, identity, digest, receipt)
		if recoveryErr != nil {
			err = errors.Join(err, ErrDomainExecutionUnknown, recoveryErr)
			return
		}
		switch outcome.Status {
		case eventstore.ExecutionStatusCommitted:
			if submitted {
				committed = true
				err = nil
				if transaction != nil {
					publishDomainCommit(transaction)
					if releaseFence != nil {
						releaseFence()
					}
					notifyDomainCommit(transaction)
				}
			} else {
				err = errors.Join(err, ErrDomainExecutionUnknown)
			}
		case eventstore.ExecutionStatusAmbiguous:
			err = errors.Join(err, ErrDomainExecutionAmbiguous)
		default:
			err = errors.Join(err, ErrDomainExecutionUnknown)
		}
	}()

	metadata := eventstore.Metadata{CommandID: owner, CorrelationID: owner, Producer: "dice/execution", OccurredAt: time.Now().UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err = NewDurableCallbackTransaction(hostCtx, store, collector, metadata)
	if err != nil {
		return err
	}
	if err = run(transaction); err != nil {
		return err
	}
	if err = context.Cause(hostCtx); err != nil {
		return err
	}
	if err = transaction.Finalize(hostCtx); err != nil {
		return err
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		return err
	}

	unlock, err := acquireDomainCommitFence(hostCtx, transaction.callbackCommitFence)
	if err != nil {
		return err
	}
	fenceHeld := true
	releaseFence = func() {
		if fenceHeld {
			unlock()
			fenceHeld = false
		}
	}
	if result := joinHeartbeat(); result.err != nil {
		return result.err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Freeze renewal only after the Host and all preparation finish, then renew
	// once for the bounded handoff to the terminal CAS.
	renewCtx, renewCancel, err := domainLeaseOperationContext(ctx, receipt.LeaseExpiresAt)
	if err != nil {
		return err
	}
	renewed, err := repository.RenewExecution(renewCtx, domainRenewRequest(identity, digest, receipt))
	renewCancel()
	if err != nil {
		return err
	}
	receipt = renewed
	work.Execution = &eventstore.ExecutionAttemptCommit{
		Identity: identity, RequestDigest: digest, AttemptID: receipt.AttemptID,
		ExpectedVersion: receipt.Version, LeaseOwner: receipt.LeaseOwner, LeaseEpoch: receipt.LeaseEpoch,
	}
	if err = eventstore.ValidateUnitOfWork(work); err != nil {
		return err
	}
	commitCtx, commitCancel, err := domainLeaseOperationContext(ctx, receipt.LeaseExpiresAt)
	if err != nil {
		return err
	}
	submitted = true
	_, err = store.Commit(commitCtx, work)
	commitCancel()
	if err != nil {
		return err
	}
	committed = true
	publishDomainCommit(transaction)
	releaseFence()
	notifyDomainCommit(transaction)
	return nil
}

func domainRenewRequest(identity string, digest []byte, receipt eventstore.ExecutionReceipt) eventstore.ExecutionRenewRequest {
	return eventstore.ExecutionRenewRequest{
		Identity: identity, RequestDigest: digest, AttemptID: receipt.AttemptID,
		ExpectedVersion: receipt.Version, LeaseOwner: receipt.LeaseOwner, LeaseEpoch: receipt.LeaseEpoch,
		LeaseDuration: eventstore.DefaultExecutionLease,
	}
}

func domainLeaseOperationContext(parent context.Context, expiry time.Time) (context.Context, context.CancelFunc, error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	// Leave room for cancellation to reach the driver before natural expiry.
	deadline := expiry.Add(-eventstore.DefaultExecutionLease / 20)
	if !deadline.After(time.Now()) {
		return nil, nil, eventstore.ErrStaleLease
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel, nil
}

func keepDomainExecutionLease(ctx context.Context, cancel context.CancelCauseFunc, repository eventstore.ExecutionReceiptRepository, identity string, digest []byte, receipt eventstore.ExecutionReceipt, stop <-chan struct{}, done chan<- domainLeaseResult) {
	ticker := time.NewTicker(eventstore.DefaultExecutionLease / 3)
	defer ticker.Stop()
	result := domainLeaseResult{receipt: receipt}
	defer func() { done <- result }()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			result.err = context.Cause(ctx)
			return
		case <-ticker.C:
			renewCtx, renewCancel, err := domainLeaseOperationContext(ctx, result.receipt.LeaseExpiresAt)
			if err != nil {
				result.err = err
				cancel(err)
				return
			}
			renewed, err := repository.RenewExecution(renewCtx, domainRenewRequest(identity, digest, result.receipt))
			renewCancel()
			if err != nil {
				result.err = err
				cancel(err)
				return
			}
			result.receipt = renewed
		}
	}
}

func reconcileDomainExecution(ctx context.Context, repository eventstore.ExecutionReceiptRepository, identity string, digest []byte, last eventstore.ExecutionReceipt) (eventstore.ExecutionReceipt, error) {
	current, err := repository.LookupExecution(ctx, identity)
	if err != nil {
		return eventstore.ExecutionReceipt{}, err
	}
	if current.Status != eventstore.ExecutionStatusStarted {
		return current, nil
	}
	if current.AttemptID != last.AttemptID || current.LeaseOwner != last.LeaseOwner || current.LeaseEpoch != last.LeaseEpoch {
		return current, eventstore.ErrStaleLease
	}
	current, err = repository.RecoverExecution(ctx, eventstore.ExecutionRecoveryRequest{
		Identity: identity, RequestDigest: digest, AttemptID: current.AttemptID,
		ExpectedVersion: current.Version, LeaseOwner: current.LeaseOwner, LeaseEpoch: current.LeaseEpoch,
	})
	if err == nil {
		return current, nil
	}
	// A lost commit response can race the recovery CAS. A read can prove a
	// terminal outcome; a miss or another error never proves noncommit.
	latest, lookupErr := repository.LookupExecution(ctx, identity)
	if lookupErr == nil && (latest.Status == eventstore.ExecutionStatusCommitted || latest.Status == eventstore.ExecutionStatusAmbiguous) {
		return latest, nil
	}
	return latest, errors.Join(err, lookupErr)
}

func acquireDomainCommitFence(ctx context.Context, fence callbackCommitFence) (func(), error) {
	if fence == nil {
		return func() {}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fence.TryLock() {
		return fence.Unlock, nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-ticker.C:
			if fence.TryLock() {
				return fence.Unlock, nil
			}
		}
	}
}

func publishDomainCommit(transaction *DurableCallbackTransaction) {
	for _, publish := range transaction.callbackPublication {
		publish()
	}
}

func notifyDomainCommit(transaction *DurableCallbackTransaction) {
	for _, notify := range transaction.callbackAfterCommit {
		notify()
	}
}

// DomainExecutionIdentity scopes scheduler-provided identity to its Dice owner.
func (d *Dice) DomainExecutionIdentity(kind, invocation string) string {
	return fmt.Sprintf("%d:%s%d:%s%d:%s", len(d.BaseConfig.Name), d.BaseConfig.Name, len(kind), kind, len(invocation), invocation)
}
