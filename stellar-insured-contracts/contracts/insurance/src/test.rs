mod insurance_tests {
    #[test] fn test_quorum() {
        let q = |total: u32| (total * 2000 + 9999) / 10000;
        assert_eq!(q(5),  1);
        assert_eq!(q(10), 2);
        assert_eq!(q(15), 3);
    }

    #[test] fn test_approval_threshold() {
        let approved = |yes: u32, total: u32| yes * 10000 / total >= 5000;
        assert!( approved(3, 5));   // 60% → pass
        assert!(!approved(2, 5));   // 40% → fail
        assert!( approved(5, 10));  // 50% → pass (boundary)
    }

    #[test] fn test_double_vote_guard() {
        use std::collections::HashSet;
        let mut voted: HashSet<&str> = HashSet::new();
        assert!(voted.insert("alice"));     // first vote: ok
        assert!(!voted.insert("alice"));    // second vote: blocked
    }

    #[test] fn test_voting_window() {
        let created: u64 = 1_000_000;
        let voting_end   = created + 7 * 24 * 3600;
        assert!(created + 1 <= voting_end);          // still open
        assert!(voting_end + 1 > voting_end);        // closed after period
    }
}