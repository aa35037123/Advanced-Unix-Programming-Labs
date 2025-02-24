#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import base64
import zlib
import random
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
    while True:
        prompt = recv_msg(r)
        print(f"[+] Server prompt: {prompt}")
        send_msg(r, guess.encode())
        print(f"Sent: {guess}")
        
        A, B = recv_AB(r)
        print(f"A: {A}, B: {B}")
        print(f'Digits: {digits}')
        print(f'Right numbers: {right_numbers}')
        if A == 4:  # win condition
            print("You win!")
            print(f"The number is: {guess}")
            break

        # A value different
        if A != prev_A and B == prev_B and prev_guess is not None:
            if A < prev_A:
                confirmed_positions[changed_index] = prev_guess[changed_index]
                if prev_guess[changed_index] in digits:
                    digits.remove(prev_guess[changed_index])
                
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

        # B value different
        if B != prev_B and A == prev_A and prev_guess is not None:
            if B < prev_B:
                right_numbers.append(prev_guess[changed_index])
                
                guess_list = list(guess)
                guess_list[changed_index] = prev_guess[changed_index]
                guess = "".join(guess_list)

                B = prev_B  # after reset guess digit, we need to reset B

            elif B > prev_B:
                right_numbers.append(guess[changed_index])
                
            possible_indices[changed_index] = 1
        
        # A and B value different(both prev_guess[changed_index] and guess[changed_index] are correct number)
        if A != prev_A and B != prev_B and prev_guess is not None:
            if A > prev_A and B < prev_B:
                confirmed_positions[changed_index] = guess[changed_index]
                if guess[changed_index] in digits:
                    digits.remove(guess[changed_index])
                if prev_guess[changed_index] not in right_numbers:
                    right_numbers.append(prev_guess[changed_index])

            elif A < prev_A and B > prev_B:
                confirmed_positions[changed_index] = prev_guess[changed_index]
                if prev_guess[changed_index] in digits:
                    digits.remove(prev_guess[changed_index])
                if guess[changed_index] not in right_numbers:
                    right_numbers.append(guess[changed_index])
                
                # Reset guess
                guess_list = list(guess)
                guess_list[changed_index] = prev_guess[changed_index]
                guess = "".join(guess_list)

                A = prev_A  # after reset guess digit, we need to reset A

        if A == prev_A and B == prev_B and prev_guess is not None:
            print("Removing impossible numbers...")
            digits = [d for d in digits if d not in [prev_guess[changed_index], guess[changed_index]]]
            if guess[changed_index] in digits:
                digits.remove(guess[changed_index])
            if guess[changed_index] in digits:
                digits.remove(prev_guess[changed_index])

        """
        # Start new guessing
        """
        prev_guess = guess
        guess = list(guess)
        prev_A, prev_B = A, B

        if (A + B) == 4:
            print("All numbers are correct, adjusting position...")
            print(f'Right numbers: {right_numbers}')
            guess = confirmed_positions
            for i, digit in enumerate(guess):
                if digit is None:
                    d = random.choice(right_numbers)
                    while d in guess[:i+1] or d == prev_guess[i]:
                        # print('##Hi')
                        d = random.choice(right_numbers)
                    guess[i] = d
        else:
            print("Changing numbers...")
            none_indices = [i for i, value in enumerate(possible_indices) if value is None]
            changed_index = random.choice(none_indices)
            print(f"Changed index: {changed_index}")
            d = random.choice(digits)
            while d in prev_guess:
                # print('##Hi')
                d = random.choice(digits)
            guess[changed_index] = d
        
        guess = ''.join(guess)
        # score = A + B
        # if score > 0:
        #     if score >= best_score:
        #         best_score = score
        #         print("Add numbers to possible numbers...")
        #         for i in range(4):
        #             right_numbers.add(guess[i])
        #     else:  # kick off numbers that make 

        # else:
        #     print("Removing impossible numbers...")
        #     digits = [d for d in digits if d not in guess]

        # not_in_guess = [d for d in digits if d not in guess]
        print(recv_msg(r))

    print(recv_msg(r))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r = remote('up.zoolab.org', 10155)
        solve_pow(r)
    else:
        r = process('./guess.dist.py', shell=False)

    guess_number(r)
    r.interactive()
