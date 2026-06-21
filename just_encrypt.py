import base64
from google.cloud import kms
 
KMS_KEY = "projects/MY_PROJECT/locations/global/keyRings/MY_RING/cryptoKeys/MY_KEY"
 
client = kms.KeyManagementServiceClient()
 
 
def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns a base64 token you can store."""
    response = client.encrypt(
        request={"name": KMS_KEY, "plaintext": plaintext.encode()}
    )
    return base64.b64encode(response.ciphertext).decode()
 
 
def decrypt(token: str) -> str:
    """Decrypt a base64 token back to the original string."""
    response = client.decrypt(
        request={"name": KMS_KEY, "ciphertext": base64.b64decode(token)}
    )
    return response.plaintext.decode()
