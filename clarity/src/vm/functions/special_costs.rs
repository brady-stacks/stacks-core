// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::cmp;

use clarity_types::execution_cost::ExecutionCost;
use crate::vm::types::Value;

/// Cost function for binary comparison operations (geq, leq, less, greater)
/// Uses the minimum size of the two arguments
pub fn cost_binary_comparison(args: &[Value]) -> ExecutionCost {
    if args.len() >= 2 {
        let size_a = args[0].size().unwrap_or(0);
        let size_b = args[1].size().unwrap_or(0);
        let input_size = cmp::min(size_a, size_b) as u64;
        // Use a reasonable base cost for comparison operations
        // This will be refined to use proper cost tables
        ExecutionCost::runtime(input_size.saturating_mul(10).saturating_add(100))
    } else {
        ExecutionCost::runtime(100)
    }
}

/// Cost function for boolean operations (and, or)
/// Uses the number of arguments
pub fn cost_boolean_operation(args: &[Value]) -> ExecutionCost {
    let arg_count = args.len() as u64;
    // Use a reasonable base cost for boolean operations
    ExecutionCost::runtime(arg_count.saturating_mul(50).saturating_add(50))
}

/// Cost function for operations that use argument count
pub fn cost_by_arg_count(args: &[Value]) -> ExecutionCost {
    let arg_count = args.len() as u64;
    ExecutionCost::runtime(arg_count.saturating_mul(100))
}

/// Cost function for operations that use total argument size
pub fn cost_by_total_size(args: &[Value]) -> ExecutionCost {
    let total_size: u64 = args
        .iter()
        .map(|v| v.size().unwrap_or(0) as u64)
        .sum();
    ExecutionCost::runtime(total_size.saturating_mul(10).saturating_add(100))
}

/// Cost function that returns zero cost (for functions that handle costs internally)
pub fn cost_zero(_args: &[Value]) -> ExecutionCost {
    ExecutionCost::ZERO
}

