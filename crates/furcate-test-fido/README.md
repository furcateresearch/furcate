# furcate-test-fido

A software FIDO authenticator for OpenSSH (`SecurityKeyProvider`), for tests
only. It makes `sk-ecdsa-sha2-nistp256@openssh.com` keys whose private half is
the key handle, so ssh, ssh-keygen and sshd can be driven end to end without a
hardware authenticator. A real passkey never lets its private key out; this
does, which is why nothing but a test may load it.
