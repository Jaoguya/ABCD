"""Construction phases for Ref[52], §III algorithms A–I.

Each phase is in its own numbered module for clarity:

    p1_setup        §III.A  Setup — global parameter generation
    p2_aa_setup     §III.B  AASetup — per-authority key generation
    p3_enroll       §III.C  Enroll — user registration
    p4_revoke       §III.D  Revoke — attribute revocation
    p5_extend       §III.E  Extend — attribute extension
    p6_encrypt      §III.F  Encrypt — ciphertext + search index
    p7_token_gen    §III.G  TokenGen — search token generation
    p8_search       §III.H  Search — server-side keyword matching
    p9_decrypt      §III.I  Decrypt — ciphertext recovery
"""

from .p1_setup import setup, GlobalParams                           # noqa: F401
from .p2_aa_setup import aa_setup, AuthorityPublicKey, AuthorityMasterKey  # noqa: F401
from .p3_enroll import enroll, UserPublicInfo, UserPrivateKey       # noqa: F401
from .p4_revoke import revoke                                       # noqa: F401
from .p5_extend import extend                                       # noqa: F401
from .p6_encrypt import encrypt, Ciphertext, EncryptedIndex         # noqa: F401
from .p7_token_gen import token_gen, SearchToken                    # noqa: F401
from .p8_search import search, SearchResult                         # noqa: F401
from .p9_decrypt import decrypt                                     # noqa: F401
