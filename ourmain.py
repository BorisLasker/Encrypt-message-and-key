import os
import myECElGamal as GL
import binascii
from cfb import CFB
import codecs
from rabin import digital_signature,generate_primes, verification
import glob
import docx
import time

def getText(filename):
    doc = docx.Document(filename)
    fullText = []
    for para in doc.paragraphs:
        fullText.append(para.text)
    return '\n'.join(fullText)



def TwoFishDecryptMessage(decKey, cipher):
    for i in range(len(cipher)):
        cipher[i] = CFB(decKey).decrypt(cipher[i]).decode()
        if (cipher[i].endswith('*' * cutPoint)):
            cipher[i] = cipher[i][:-cutPoint]

    return cipher

def CreateRandomTwoFishKey():
    return os.urandom(16)

def TwoFishEncryptMessage(cipherKey, Ptext):
    for i in range(len(Ptext)):
        Ptext[i] = CFB(cipherKey).encrypt(bytes(Ptext[i], 'utf-8'))
    return Ptext



# Check and complete in case the length of the text is not a multiple of 16
def FixMessage(message):
    lack = len(message) % 16
    if lack != 0:
        # Save the cutoff of the text
        cutPoint = 16 - lack
        # Add * to complete to multiple of 16
        addition = "*" * cutPoint
        message += addition
        return message, cutPoint




files=[]

for file_name in glob.iglob('C:/Users\Boris\Desktop\datasets\*', recursive=True):
    files.append(file_name)  
    
for file_name in files:
    if file_name.endswith( '.docx'):
        message=getText(file_name)
    
    else:
        with open(file_name) as f:
            message = f.read()
        
    
    message, cutPoint = FixMessage(message)
    print("Message before encryption with tailing * is:", message)
    
    # Split the text to units of 16 chars
    TwoFishSplitMessage = [message[i:i + 16] for i in range(0, len(message), 16)]
    
    # Generating random 128 bit key from Operating System
    key=binascii.hexlify(os.urandom(16)).decode()
    key_bytes=codecs.decode(key, 'hex')
    
    # Initializing the parameters of Rabin Signature
    nrabin=int(generate_primes(),16)
    
    # Initializing the parameters of EC EL_GAMAL
    a,b,base_point,mod,order = GL.Initiation_gamal()
    
    # Encrypt the text with TwoFish algorithm
    encryptedMessage = TwoFishEncryptMessage(key_bytes, TwoFishSplitMessage)
    print("Message after encryption is:", ''.join(str(encryptedMessage)))
    
    # Encryption of the Key using Gamal
    c1,c2 = GL.Encryption_key_gamal(key,a,b,base_point,mod,order)
    
    #create Digital Signature with the encrypted Message
    sig,padd=digital_signature(nrabin,encryptedMessage)
    
     
    #check authenticity
    res=verification(encryptedMessage, padd, sig)
    if res:
        dkey=GL.Decryption_key_gamal(c1, c2, a, b, mod, base_point,order)   
        dkey_bytes=codecs.decode(dkey, 'hex')
        decryptedMessage = TwoFishDecryptMessage(dkey_bytes, encryptedMessage)
        print("Message after decryption without tailing * is:", ''.join(decryptedMessage))
    time.sleep(2)

