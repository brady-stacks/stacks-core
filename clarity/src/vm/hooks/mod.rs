// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![deny(missing_docs)]

//! Evaluation hooks and call-tracing support for observing Clarity VM execution.

mod internals;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod trace;

pub(crate) use internals::{CallTraceFrame, EvalHookNotifier};

use crate::vm::callables::{DefineType, DefinedFunction};
use crate::vm::contexts::{ExecutionState, InvocationContext, LocalContext};
use crate::vm::errors::VmExecutionError;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{QualifiedContractIdentifier, Value};
use crate::vm::{ExecutionResult, ValueRef};

/// Shared, optional sink for rollback-aware state observations.
pub type SharedStateObserver = std::rc::Rc<std::cell::RefCell<dyn StateObserver>>;

/// Concrete storage namespace and key being mutated.
#[derive(Debug, Clone, Copy)]
pub enum StateKey<'a> {
    /// Consensus key-value data.
    Data(&'a str),
    /// Contract metadata, scoped independently from consensus data.
    Metadata {
        /// Contract owning the metadata.
        contract: &'a QualifiedContractIdentifier,
        /// Canonical metadata key.
        key: &'a str,
    },
}

/// A mutation or rollback-frame transition, in execution order.
#[derive(Debug)]
pub enum StateEvent<'a> {
    /// A rollback frame opened.
    Nest {
        /// Stable identifier within the attached observation.
        frame_id: u64,
        /// Enclosing rollback frame, if any.
        parent_id: Option<u64>,
    },
    /// A frame committed into its parent or backing store.
    Commit {
        /// Frame that committed.
        frame_id: u64,
        /// Parent receiving the edits, if any.
        parent_id: Option<u64>,
    },
    /// A frame's edits were discarded.
    Rollback {
        /// Frame that rolled back.
        frame_id: u64,
        /// Enclosing frame, if any.
        parent_id: Option<u64>,
    },
    /// A successful write to the pending rollback log.
    Write {
        /// Frame owning this write.
        frame_id: u64,
        /// Actual canonical storage key.
        key: StateKey<'a>,
        /// Visible value before the write; an error explicitly marks an incomplete trace.
        before: Result<Option<&'a str>, &'a VmExecutionError>,
        /// Actual serialized value stored by this write.
        after: &'a str,
    },
}

/// Receives state mutations without changing VM execution outcomes.
pub trait StateObserver {
    /// Observe one event synchronously; borrowed values are valid only during this call.
    fn observe(&mut self, event: StateEvent<'_>);
}

// NOTE: Used in the Clarinet repo.
/// Defines the contract for receiving notifications about Clarity evaluation and callable
/// invocation.
pub trait EvalHook {
    /// Called before a top-level execution begins.
    fn will_begin_execution(&mut self) {}

    /// Called after a top-level execution finishes, with its [`ExecutionOutcome`].
    fn did_finish_execution(&mut self, _outcome: ExecutionOutcome) {}

    /// Called before a Clarity expression is evaluated.
    fn will_begin_eval(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _context: &LocalContext,
        _expr: &SymbolicExpression,
    ) {
    }

    /// Called after a Clarity expression has been evaluated.
    fn did_finish_eval<'a>(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &'a InvocationContext,
        _context: &'a LocalContext,
        _expr: &SymbolicExpression,
        _res: &Result<ValueRef<'a>, VmExecutionError>,
    ) {
    }

    /// Completion callback available to external consumers.
    ///
    /// **Note:** The Clarity VM itself never calls this method; `clarinet` invokes it
    /// internally as part of its REPL interpreter.
    fn did_complete(&mut self, _result: Result<&mut ExecutionResult, String>) {}

    /// Called before a callable starts evaluating or consuming its arguments.
    fn will_begin_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        _args: CallArguments,
    ) {
    }

    /// Called when an argument has been evaluated to the value the callable will receive.
    fn did_evaluate_call_argument(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        _arg_index: usize,
        _value: &Value,
    ) {
    }

    /// Called after a callable invocation that triggered [`EvalHook::will_begin_call`] finishes.
    fn did_finish_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        _res: &Result<Value, VmExecutionError>,
    ) {
    }
}

/// Callable invocation observed during Clarity execution.
///
/// Call hooks are emitted before a callable evaluates its arguments, so nested
/// calls that produce argument values can be reconstructed under the call that
/// consumes them. Some VM paths, such as transaction entry points and
/// `apply_evaluated`, already have concrete values when the call starts.
#[derive(Debug, Clone, Copy)]
pub enum CallHook<'a> {
    /// Built-in or special-form callable.
    Builtin {
        /// Clarity source-level function name.
        clarity_name: &'static str,
        /// Rust implementation name.
        rust_name: &'static str,
    },
    /// User-defined contract function.
    UserDefined {
        /// Contract that owns the function.
        contract_identifier: &'a QualifiedContractIdentifier,
        /// Function definition being invoked.
        function: &'a DefinedFunction,
    },
}

impl<'a> CallHook<'a> {
    /// Creates a hook descriptor for a built-in or special-form callable.
    pub fn builtin(clarity_name: &'static str, rust_name: &'static str) -> Self {
        CallHook::Builtin {
            clarity_name,
            rust_name,
        }
    }

    /// Creates a hook descriptor for a user-defined contract function.
    pub fn user_defined(
        contract_identifier: &'a QualifiedContractIdentifier,
        function: &'a DefinedFunction,
    ) -> CallHook<'a> {
        CallHook::UserDefined {
            contract_identifier,
            function,
        }
    }

    /// Clarity source-level function name.
    pub fn clarity_name(&self) -> &str {
        match self {
            CallHook::Builtin { clarity_name, .. } => clarity_name,
            CallHook::UserDefined { function, .. } => function.name(),
        }
    }

    /// Stable category label for trace consumers.
    pub fn kind(&self) -> &'static str {
        match self {
            CallHook::Builtin { .. } => "builtin",
            CallHook::UserDefined { function, .. } => match function.define_type {
                DefineType::Public => "user-public",
                DefineType::Private => "user-private",
                DefineType::ReadOnly => "user-read-only",
            },
        }
    }
}

/// Arguments available when a call hook opens.
///
/// Some call paths still have source expressions, while transaction entry points
/// and `apply_evaluated` already have concrete values.
#[derive(Debug, Clone, Copy)]
pub enum CallArguments<'a> {
    /// Unevaluated argument expressions.
    Expressions(&'a [SymbolicExpression]),
    /// Already evaluated argument values.
    Values(&'a [Value]),
}

impl CallArguments<'_> {
    /// Number of arguments in this call.
    pub fn len(&self) -> usize {
        match self {
            CallArguments::Expressions(args) => args.len(),
            CallArguments::Values(args) => args.len(),
        }
    }

    /// Returns true when the call has no arguments.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Indicates whether a top-level execution returned successfully or with an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Execution returned successfully.
    Success,
    /// Execution returned an error.
    Failure,
}
