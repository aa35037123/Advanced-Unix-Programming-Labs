#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import base64
import zlib
import random
import itertools
from pwn import *
from solpow import solve_pow

def send_msg(r, m):
    zm = zlib.compress(m)
    mlen = len(zm)
    # print(base64.b64encode(mlen.to_bytes(4, 'big') + zm))
    r.sendline(base64.b64encode(mlen.to_bytes(4, 'little') + zm))

def recv_msg(r):
    msg = r.recvline().strip()
    msg = base64.b64decode(msg)
    mlen = int.from_bytes(msg[0:4], 'big')
    if len(msg) - 4 != mlen:
        print("Message length mismatch. Exiting.")
        sys.exit(1)
    m = zlib.decompress(msg[4:])
    return m.decode()

def recv_AB(r):
    msg = r.recvline().strip()
    msg = base64.b64decode(msg)
    mlen = int.from_bytes(msg[0:4], 'big')
    if len(msg) - 4 != mlen:
        print("Message length mismatch. Exiting.")
        sys.exit(1)
    m = zlib.decompress(msg[4:])

    # Extract A and B values
    a = int.from_bytes(m[0:4], 'big')
    b = int.from_bytes(m[5:9], 'big')
    return a, b

def swap(guess, i, j):
    """
    convert guess to list, swap i-th and j-th element, then return as a string.
    """
    guess_list = list(guess)
    guess_list[i], guess_list[j] = guess_list[j], guess_list[i]
    return "".join(guess_list)

def analyze_ab(guess, target):
    # Calculate the A and B count for a guess vs target.
    A = sum(1 for g, t in zip(guess, target) if g == t)
    B = sum(1 for g in guess if g in target) - A
    return A, B

def guess_number(r):
    #response = recv_msg(r)
    #print("[+] Server sent: {response}")
    digits = list("0123456789")
    # random.shuffle(digits)
    guess, prev_guess = "".join(digits[:4]), None
    right_numbers = []  # List of possible numbers
    confirmed_positions = [None] * 4  # length: 4
    possible_indices = [None] * 4
    A, B, prev_A, prev_B = 0, 0, 0, 0
    corrects = 0
    msg0 = recv_msg(r)  # First message (MSG0)
    print(f"[+] Server sent: {msg0}")
    count = 0
    win = False
    special_candidates = []
    special_event = False
    changed_index = None

    possible_combinations = None
    swap_comb_used = None

    while True and count < 10:
        prompt = recv_msg(r)
        print(f"[+] Server prompt: {prompt}")
        send_msg(r, guess.encode())
        print(f"Sent: {guess}")
        
        A, B = recv_AB(r)
        print(f"A: {A}, B: {B}")
        print(f'Digits: {digits}')
        print(f'Right numbers: {right_numbers}')
        print(f'Confirmed positions: {confirmed_positions}')
        print(f'Possible indices: {possible_indices}')
        print(f'Special_candidates: {special_candidates}')
        print(f'prev_guess: {prev_guess}')
        print(f'guess: {guess}')
        print(f'special event: {special_event}')
        print(f"Changed index: {changed_index}")
        if A == 4:  # win condition
            print("You win!")
            print(f"The number is: {guess}")
            win = True
            break

        if (A + B) < 4:
            if A + B == 0:
                print("## A + B == 0")
                guess_list = list(guess)
                for digit in guess_list:
                    if digit in digits:
                        digits.remove(digit)
            
            # only one situation that both A and B are different from the previous one at the same time
            elif (A+B) == (prev_A + prev_B) and prev_guess is not None:
                print("## (A+B) == (prev_A + prev_B)")
                # there are 3 classes of this case
                # 1. A = prev_A, B = prev_B (ex: 1A1B -> 1A1B)
                #    - either prev_guess[changed_index] and guess[changed_index] are right number(wrong position)
                #    - or both are wrong number
                if A == prev_A and B == prev_B and B != 0:
                    print("## A == prev_A and B == prev_B")
                    if not special_event:
                        special_event = True
                        print(f"special candidates appends: {guess[changed_index]} and {prev_guess[changed_index]}")
                        special_candidates.append(guess[changed_index])
                        special_candidates.append(prev_guess[changed_index])
    
                    else: # reset special event
                        if guess[changed_index] not in special_candidates:
                            special_candidates.append(guess[changed_index])
                        # for special_candidate in special_candidates:
                        #     if special_candidate not in right_numbers:
                        #         right_numbers.append(special_candidate)
                        # special_candidates = []
                        
                        # special_event = False

                        # possible_indices[changed_index] = 1

                # 2. A < prev_A, B > prev_B (ex: 1A1B -> 0A2B)
                #    - prev_guess[changed_index] is confirmed number, guess[changed_index] is right number
                elif A < prev_A and B > prev_B:
                    print("## A < prev_A and B > prev_B")
                    confirmed_positions[changed_index] = prev_guess[changed_index]
                    if prev_guess[changed_index] in digits:  # remove confirmed number from digits
                        digits.remove(prev_guess[changed_index])
                    if guess[changed_index] not in right_numbers:
                        right_numbers.append(guess[changed_index])
                    
                    # Reset guess
                    guess_list = list(guess)
                    guess_list[changed_index] = prev_guess[changed_index]
                    guess = "".join(guess_list)

                    A = prev_A  # after reset guess digit, we need to reset A
                    B = prev_B  # after reset guess digit, B value need to -1
                    possible_indices[changed_index] = 1

                # 3. A > prev_A, B < prev_B (ex: 0A2B -> 1A1B)
                #    - guess[changed_index] is confirmed number, prev_guess[changed_index] is right number  
                elif A > prev_A and B < prev_B:
                    print("## A > prev_A and B < prev_B")
                    confirmed_positions[changed_index] = guess[changed_index]
                    if guess[changed_index] in digits:  # remove confirmed number from digits
                        digits.remove(guess[changed_index])
                    if prev_guess[changed_index] not in right_numbers:
                        right_numbers.append(prev_guess[changed_index])
                    # ex: 1A1B -> 2A0B 
                    if special_event:
                        for special_candidate in special_candidates:
                            if special_candidate in digits:
                                # digits.remove(special_candidate)
                                right_numbers.append(special_candidate)

                        special_candidates = []
                        special_event = False
                    possible_indices[changed_index] = 1

            # A value different
            elif A != prev_A and B == prev_B and prev_guess is not None:
                print("## A value different")
                if A < prev_A:
                    confirmed_positions[changed_index] = prev_guess[changed_index]
                    if prev_guess[changed_index] in digits:
                        digits.remove(prev_guess[changed_index])  # remove confirmed number from digits
                    
                    # Reset guess
                    guess_list = list(guess)
                    guess_list[changed_index] = prev_guess[changed_index]
                    guess = "".join(guess_list)

                    A = prev_A  # after reset guess digit, we need to reset A

                elif A > prev_A:
                    confirmed_positions[changed_index] = guess[changed_index]  
                    if guess[changed_index] in digits:
                        digits.remove(guess[changed_index])  
                
                corrects += 1
                possible_indices[changed_index] = 1

                if special_event:  # because in the condition, we don't have enough info
                    special_candidates = []
                    special_event = False

            # B value different
            elif B != prev_B and A == prev_A and prev_guess is not None:
                print("## B value different")
                if B < prev_B:
                    if guess[changed_index] in digits:
                        digits.remove(guess[changed_index])

                    if prev_guess[changed_index] not in right_numbers:
                        right_numbers.append(prev_guess[changed_index])

                    guess_list = list(guess)
                    guess_list[changed_index] = prev_guess[changed_index]
                    guess = "".join(guess_list)

                    B = prev_B  # after reset guess digit, we need to reset B

                    if special_event:
                        for special_candidate in special_candidates:
                            if special_candidate not in right_numbers:
                                right_numbers.append(special_candidate)
                        special_candidates = []
                        special_event = False

                elif B > prev_B:
                    if prev_guess[changed_index] in digits:
                        digits.remove(prev_guess[changed_index])

                    if guess[changed_index] not in right_numbers:
                        right_numbers.append(guess[changed_index])

                    if special_event:
                        for special_candidate in special_candidates:
                            if special_candidate in digits:
                                digits.remove(special_candidate)

                        special_candidates = []
                        special_event = False

                possible_indices[changed_index] = 1
        

        """
        # Start new guessing
        """
        guess = list(guess)
        if prev_guess is not None:
            prev_guess = list(prev_guess)
        # print("Prev guess: ", prev_guess)
        if (A + B) == 4:  # all numbers are correct, adjust position
            print("All numbers are correct, adjusting position...")
            # print(f'Right numbers: {right_numbers}')
            print(f'Confirmed positions: {confirmed_positions}')

            if possible_combinations is None:
                possible_combinations = []
                right_numbers = [guess[i] for i, value in enumerate(confirmed_positions) if value is None]
                none_indices = [i for i, value in enumerate(confirmed_positions) if value is None]
                # print(f'Right numbers: {right_numbers}')
                # print(f'None indices: {none_indices}')
                for perm in itertools.permutations(right_numbers, len(none_indices)):
                    # print("perm: ", perm)
                    new_guess = confirmed_positions[:]   # 複製一份 confirmed_positions
                    for idx, pos in enumerate(none_indices):
                        new_guess[pos] = perm[idx]
                    # print("new_guess: ", new_guess)
                    # Convert new_guess into string and append to possible_combinations
                    possible_combinations.append("".join(new_guess))    
                # possible_combinations = list(itertools.combinations(none_indices, 2))
            # print(f"Before Filter possible combinations: {possible_combinations}")

            possible_combinations = [
                num_str for num_str in possible_combinations if analyze_ab("".join(guess), num_str) == (A, B)
            ]
            print(f"possible combinations: {possible_combinations}")
            
            guess = possible_combinations[0]
            # if A < prev_A:
            #     guess = swap(guess, prev_swap[0], prev_swap[1])
            #     print(f'>> swapping back guess: {guess}')
            # for idx, (i, j) in enumerate(possible_combinations):  # target: (0, 2)
            #     if(swap_comb_used[idx] == 1):
            #         continue
                
            #     guess = swap(guess, i, j)
            #     prev_swap = (i, j)
            #     swap_comb_used[idx] = 1
            #     break
            

        else:  # Some numbers are still wrong
            print("Changing numbers...")
            none_indices = [i for i, value in enumerate(possible_indices) if value is None]
            if not special_event:
                changed_index = random.choice(none_indices)
            d = '-1'
            if right_numbers is not None:
                
                for right_num in right_numbers:
                    if right_num not in guess and right_num not in special_candidates:
                        if prev_guess is not None and right_num not in prev_guess:
                            d = right_num
                            break
                # while d in prev_guess or d < 0:
                #     d = random.choice(right_numbers)
            # If can not find in right_numbers, choose from digits
            if prev_guess is not None:
                while d in prev_guess or d in guess or int(d) < 0:
                    # print('##Hi')
                    d = random.choice(digits)
            else:
                while d in guess or int(d) < 0:
                    d = random.choice(digits)
            
            prev_guess = guess[:]
            guess[changed_index] = d
            guess = ''.join(guess)

        prev_A, prev_B = A, B
        print(recv_msg(r))
        count += 1
        print("------------------------------")

    if not win:
        print("> You lose!")
    else:
        print(recv_msg(r))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r = remote('up.zoolab.org', 10155)
        solve_pow(r)
    else:
        r = process('./guess.dist.py', shell=False)

    guess_number(r)
    r.interactive()
