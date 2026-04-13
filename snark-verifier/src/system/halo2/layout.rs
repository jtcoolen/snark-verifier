//! Shared layout helpers for PLONK protocol builders.

/// Remap phase-annotated columns into `(num_per_phase, index_within_phase)`.
pub fn remap_by_phase(phase: Vec<u8>) -> (Vec<usize>, Vec<usize>) {
    let num_phase = phase.iter().max().copied().unwrap_or_default() as usize + 1;
    remap_by_phase_with_num_phase(phase, num_phase)
}

/// Remap phase-annotated columns into `(num_per_phase, index_within_phase)` using a fixed phase count.
pub fn remap_by_phase_with_num_phase(
    phase: Vec<u8>,
    num_phase: usize,
) -> (Vec<usize>, Vec<usize>) {
    let num = phase.iter().fold(vec![0usize; num_phase], |mut acc, phase| {
        acc[*phase as usize] += 1;
        acc
    });
    let index = phase
        .iter()
        .scan(vec![0usize; num_phase], |state, phase| {
            let index = state[*phase as usize];
            state[*phase as usize] += 1;
            Some(index)
        })
        .collect();
    (num, index)
}

/// Number of permutation grand-product chunks for a given chunk size.
pub fn permutation_chunk_count(
    num_permutation_fixed: usize,
    permutation_chunk_size: usize,
) -> usize {
    if num_permutation_fixed == 0 {
        0
    } else {
        num_permutation_fixed.div_ceil(permutation_chunk_size)
    }
}
