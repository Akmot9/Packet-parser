"""Provoque un message MessageError (CORBA §15.4.8) du serveur omniORB.

Le stimulus est un Request GIOP 1.2 dont le body s'arrete apres 4 octets : le
serveur ne peut pas lire l'en-tete Request et repond MessageError. Ce
stimulus est le seul message de tout le labo qui ne sorte pas d'un ORB ; la
trame de reference est la **reponse** du serveur (omniORB ferme la connexion
sans repondre a un type, une version ou un magic inconnus)."""
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port)) as s:
    s.sendall(b"GIOP\x01\x02\x00\x00" + (4).to_bytes(4, "big") + bytes(4))
    s.settimeout(3)
    try:
        print("  server answered", s.recv(64).hex())
    except socket.timeout:
        print("  no answer")
