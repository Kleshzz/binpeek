pub fn checked_slice(data: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    let end = offset.checked_add(size)?;
    if end <= data.len() {
        Some(data[offset..end].to_vec())
    } else {
        None
    }
}

pub fn is_new_best(current_best_size: Option<usize>, candidate_size: usize) -> bool {
    match current_best_size {
        None => true,
        Some(best) => candidate_size > best,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_slice_in_bounds() {
        let data = [1u8, 2, 3, 4, 5];
        assert_eq!(checked_slice(&data, 1, 3), Some(vec![2, 3, 4]));
    }

    #[test]
    fn slice_exactly_at_end_is_ok() {
        let data = [1u8, 2, 3];
        assert_eq!(checked_slice(&data, 0, 3), Some(vec![1, 2, 3]));
    }

    #[test]
    fn out_of_bounds_size_returns_none() {
        let data = [1u8, 2, 3];
        assert_eq!(checked_slice(&data, 1, 10), None);
    }

    #[test]
    fn offset_past_end_returns_none() {
        let data = [1u8, 2, 3];
        assert_eq!(checked_slice(&data, 100, 1), None);
    }

    #[test]
    fn overflowing_addition_does_not_panic_and_returns_none() {
        let data = [1u8, 2, 3];
        assert_eq!(checked_slice(&data, usize::MAX, 1), None);
        assert_eq!(checked_slice(&data, usize::MAX - 1, 5), None);
        assert_eq!(checked_slice(&data, 10, usize::MAX), None);
    }

    #[test]
    fn empty_data_and_zero_size_is_empty_slice() {
        let data: [u8; 0] = [];
        assert_eq!(checked_slice(&data, 0, 0), Some(vec![]));
    }

    #[test]
    fn is_new_best_picks_first_when_empty() {
        assert!(is_new_best(None, 0));
        assert!(is_new_best(None, 100));
    }

    #[test]
    fn is_new_best_prefers_larger() {
        assert!(is_new_best(Some(5), 10));
        assert!(!is_new_best(Some(10), 5));
    }

    #[test]
    fn is_new_best_ties_keep_first() {
        assert!(!is_new_best(Some(5), 5));
    }
}
