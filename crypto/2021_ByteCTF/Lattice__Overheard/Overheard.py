from Crypto.Util.number import *
from random import SystemRandom
from flag import *
import signal


def handler(signum, frame):
    raise TimeoutError("time out")


signal.signal(signal.SIGALRM, handler)
signal.alarm(10)

random = SystemRandom()

p = 62606792596600834911820789765744078048692259104005438531455193685836606544743
g = 5

bits = 64

a = random.randint(1, p - 1)
Alice = pow(g, a, p)
b = random.randint(1, p - 1)
Bob = pow(g, b, p)
secret = pow(Alice, b, p)


def from_alice():
    print(Alice)


def from_bob():
    print(Bob)


def to_bob(msg):
    tmp_s = pow(msg, b, p)
    leak = tmp_s >> bits
    leak = leak << bits
    print(leak)


def get_flag(s):
    if s == secret:
        print(flag)


menu = '''
1. from Alice
2. from Bob
3. to Bob
4. flag
5. exit\
'''


def main():
    try:
        print("p = {}\ng = {}".format(hex(p), hex(g)))

        while True:
            print(menu)
            choice = input("$ ")

            if choice == "1":
                from_alice()
            elif choice == "2":
                from_bob()
            elif choice == "3":
                msg = input("To Bob: ").strip()
                to_bob(int(msg))
            elif choice == "4":
                msg = input("secret: ").strip()
                get_flag(int(msg))
                return
            elif choice == "5":
                print("Bybe!")
                return
            else:
                print("Invalid choice!")
                continue
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
