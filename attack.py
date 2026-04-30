from reference_impl import PublicBulletin, GroupMember

# todo: add explanation comments

def state_mutation():
    board = PublicBulletin(.5, 2)
    alice, bob, charlie = (voters := [GroupMember(i + 1, board) for i in range(3)])

    alice.cast_vote(2)

    attacker = GroupMember(4, board)

    attacker.cast_vote(1)
    bob.cast_vote(1)
    charlie.cast_vote(1)

    alice.submit_subtally()
    bob.submit_subtally()

    board.decrypt_final_vote()


def denial_of_service():
    board = PublicBulletin(.8, 2)
    alice, bob, charlie = (voters := [GroupMember(i + 1, board) for i in range(3)])

    alice.cast_vote(2)

    attacker = GroupMember(4, board)

    bob.cast_vote(1)
    charlie.cast_vote(1)
    attacker.cast_vote(1)

    for voter in voters:
        voter.submit_subtally()

    attacker.submit_subtally()

    board.decrypt_final_vote()

denial_of_service()