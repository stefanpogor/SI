from Crypto import Random
from Crypto.Cipher import AES
import socket
HOST = "127.0.0.1"
PORT = 65432
IV = b"2406170719992000"
def generate_K1(key):
    k = Random.get_random_bytes(16)
    print("K1 = ", k)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return cipher.encrypt(k)

def generate_K2():
    return Random.get_random_bytes(16)


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        connA, addrA = s.accept()
        connB, addrB = s.accept()
        private_key = generate_K2()
        print("1. Generated key (K) =", private_key, "\n")

        with connB:
            print("Node B: connected!", addrB)
            connB.sendall(private_key)

            connB.close()
            print("Node B got the key and is closing!")

        with connA:
            print("Node A: connected!", addrA)
            connA.sendall(private_key)

            print("Comm mode =", connA.recv(1024))
            private_key = generate_K1(private_key)
            connA.sendall(private_key)
            print("Node A received the key and is closing!")

            connA.close()