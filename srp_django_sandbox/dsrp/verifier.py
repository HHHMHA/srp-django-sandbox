import srp
from srp._pysrp import calculate_H_AMK, long_to_bytes


def calculate_M(hash_class, A, B, K):
    h = hash_class()
    h.update(long_to_bytes(A))
    h.update(long_to_bytes(B))
    h.update(K)
    return h.digest()


RFC_K_HEX = '5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300'


class Verifier(srp.Verifier):
    """Modify the M definition to match the js package"""

    def __init__(self, username, bytes_s, bytes_v, bytes_A, hash_alg=srp.SHA256, ng_type=srp.NG_4096, n_hex=None, g_hex=None,
                 bytes_b=None, k_hex=RFC_K_HEX):
        super(Verifier, self).__init__(username, bytes_s, bytes_v, bytes_A, hash_alg, ng_type, n_hex, g_hex,
                                       bytes_b, k_hex)
        if not self.safety_failed:
            self.M = calculate_M(self.hash_class, self.A, self.B, self.K)
            self.H_AMK = calculate_H_AMK(self.hash_class, self.A, self.M, self.K)
