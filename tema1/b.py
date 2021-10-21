from Crypto.Cipher import AES
import socket


# vectorul de initializare
IV = b"2406170719992000"
HOST = "127.0.0.1"
PORT = 65432
PORT2 = 54321


class nodeB:
  def __init__(self, key):
    self.public_key = key


  def set_communication_mode(self, m):
    self.mode = m


  def set_private_key(self, key):
    cipher = AES.new(self.public_key, AES.MODE_CBC, IV)
    self.private_key = cipher.decrypt(key)
    print("Decripted key =", self.private_key)


  def get_communication_mode(self):
    return self.mode


  def set_operator(self, op):
    self.operator = op


  def set_private_key(self, k):
    cipher = AES.new(self.public_key, AES.MODE_CBC, IV)
    self.private_key = cipher.decrypt(k)
    print("Encrypted key =", self.private_key)


  @staticmethod
  def _unpad(s):
      return s[:-ord(s[len(s)-1:])]


  def decrypt(self, block):
    if self.mode == b'cfb':
      plain = int.from_bytes(self.private_key, byteorder="big") ^ int.from_bytes(self.operator, byteorder="big")
      plain = int.from_bytes(block, byteorder="big") ^ plain
      self.set_operator(plain.to_bytes(max(len(self.operator), len(block)), byteorder="big"))
      plain = plain.to_bytes(max(len(self.operator), len(block)), byteorder="big")
    else: # ecb
      plain = int.from_bytes(self.private_key, byteorder="big") ^ int.from_bytes(block, byteorder="big")
      plain = plain.to_bytes(max(len(self.operator), len(block)), byteorder="big")
      self.set_operator(block)

    return self._unpad(plain).decode("utf-8")


if __name__ == "__main__":
  global node_B

  # comunicare KEY MANAGER
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    public_key = s.recv(1024)
    print("1. Private key (K) from KM:", public_key, "\n")

    node_B = nodeB(public_key)

    s.shutdown(socket.SHUT_RDWR)
    s.close()
  
  # comm NODE A
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT2))
    s.listen()
    conn, addr = s.accept()

    with conn:
      print("Node A", addr, "connected.")
      data = conn.recv(1024)

      start_communication = ""
      while start_communication != "ok":
        start_communication = input("Write `ok` to start <<< ")
      conn.sendall(b"ok")

      print("2. Communication mode from A:", data, "\n")
      node_B.set_communication_mode(data)

      print("3. Encrypted key from A:", "\n")
      data = conn.recv(1024)
      node_B.set_private_key(data)
      node_B.set_operator(IV)

      plain_text = ""

      while True:
        data = conn.recv(1024)

        if not data:
          break

        # decriptez de la A
        plain_text += str(node_B.decrypt(data))

      # afisez tot
      print("\nPlain text =", plain_text, "\n")