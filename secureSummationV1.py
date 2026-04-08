import random


def generate_pairwise_masks(n, low=-10, high=10):
    """
    Generate shared random masks r_ij for all pairs i < j.
    Returns a dictionary with keys (i, j).
    """
    masks = {}
    for i in range(n):
        for j in range(i + 1, n):
            masks[(i, j)] = random.randint(low, high)
    return masks


def compute_masked_votes(votes, masks):
    """
    Compute each participant's masked vote:
        m_i = v_i + sum_{j>i} r_ij - sum_{j<i} r_ji
    """
    n = len(votes)
    masked_votes = []

    for i in range(n):
        masked = votes[i]

        for j in range(i + 1, n):
            masked += masks[(i, j)]

        for j in range(i):
            masked -= masks[(j, i)]

        masked_votes.append(masked)

    return masked_votes


def tally_votes(masked_votes):
    """
    Sum masked votes. Pairwise masks cancel out,
    leaving the true total number of approvals.
    """
    return sum(masked_votes)


def decision_from_total(total_yes, n):
    """
    Majority-rule decision.
    """
    if total_yes > n / 2:
        return "APPROVE"
    else:
        return "REJECT"


def run_protocol(votes):
    """
    Full protocol simulation.
    votes: list of 0/1 values
    """
    n = len(votes)

    print("=== Privacy-Preserving Group Decision Protocol ===")
    print(f"Number of participants: {n}")
    print()

    # Step 1: Generate pairwise random masks
    masks = generate_pairwise_masks(n)

    print("Pairwise shared random masks:")
    for pair, value in masks.items():
        print(f"  r{pair} = {value}")
    print()

    # Step 2: Compute masked votes
    masked_votes = compute_masked_votes(votes, masks)

    print("Original private votes:")
    for i, vote in enumerate(votes, start=1):
        print(f"  Participant {i}: {vote}")
    print()

    print("Published masked votes:")
    for i, masked in enumerate(masked_votes, start=1):
        print(f"  Participant {i}: {masked}")
    print()

    # Step 3: Compute total
    total_yes = tally_votes(masked_votes)
    decision = decision_from_total(total_yes, n)

    print(f"Total YES votes recovered from masked sum: {total_yes}")
    print(f"Final group decision: {decision}")
    print()

    # Check correctness
    actual_total = sum(votes)
    print(f"Actual YES total (for verification only): {actual_total}")
    print(f"Protocol correct? {'YES' if actual_total == total_yes else 'NO'}")


if __name__ == "__main__":
    # Example: 1 = approve, 0 = reject
    votes = [1, 0, 1, 1]
    run_protocol(votes)
