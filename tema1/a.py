from Crypto.Cipher import AES


import socket


#vectorul de initializare
IV = b"2406170719992000"
HOST = '127.0.0.1'
PORT = 65432
PORT2 = 54321


class nodeA:
  def __init__(self, key):
    self.public_key = key


  def set_communication_mode(self, m):
    self.mode = m


  def get_communication_mode(self):
    return self.mode

    
  def set_operator(self, op):
    self.operator = op


  def set_private_key(self, k):
    cipher = AES.new(self.public_key, AES.MODE_CBC, IV)
    self.private_key = cipher.decrypt(k)


  def encrypt(self, block):
    block = '{}'.format(self._pad(block)).encode()
    if self.mode == b'cfb':
      cript = int.from_bytes(self.operator, byteorder="big") ^ int.from_bytes(self.private_key, byteorder="big")
      cript = cript ^ int.from_bytes(block, byteorder="big")
      cript = cript.to_bytes(max(len(self.operator), len(block)), byteorder="big")
      self.set_operator(cript)
    else: # ecb
      cript = int.from_bytes(block, byteorder="big") ^ int.from_bytes(self.private_key, byteorder="big")
      cript = cript.to_bytes(max(len(self.operator), len(block)), byteorder="big")
      self.set_operator(cript)
    return cript


  def _pad(self, s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


if __name__ == "__main__":
  # comunicare KEY MANAGER
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    public_key = s.recv(1024)
    print("1. Private key (K) from KM:", public_key, "\n")

    node_A = nodeA(public_key)

    print("2. Tasteaza modul de comunicare (cfb/ecb):")
    mode = input()
    print()

    if mode.lower() == "ecb":
      s.sendall(b"ecb")
      node_A.set_communication_mode(b"ecb")
    else:
      s.sendall(b"cfb")
      node_A.set_communication_mode(b"cfb")

    mode = mode.encode()

    private_key = s.recv(1024)
    print("3. Encrypted key from KM =", private_key, "\n")
    
    node_A.set_operator(IV)
    node_A.set_private_key(private_key)

    s.shutdown(socket.SHUT_RDWR)
    s.close()


  # comm NODE B
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
    s2.connect((HOST, PORT2))
    s2.sendall(mode)
    
    # confirm de la B ca putem comunica
    print("4. Confirm =", s2.recv(1024), "\n")
    s2.sendall(private_key)

    file = open('text.txt')

    while True:
      block = file.read(16)
      if not block:
        break

      print("Reading from file:", block)

      # criptez
      data = node_A.encrypt(block)

      # trimit la B
      print("Crypted text:", data)
      s2.sendall(data)