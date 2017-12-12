# twisted2sv 
# 2 Step Verification TOTP python script with mangled TOTP keys
# so a casual inspection couldn't retrieve them
# 
# by circulosmeos, Dec 2017
# licenced under GPLv3
#
version_string = ( "\n"
    "twisted2sv - 2 Step Verification TOTP python script v1.0\n" )

help_message = ( "\n"
    "$ python3 twisted2sv.py [iterations/action]\n\n"
    "    With no params, script returns #iterations (2) consecutive TOTP tokens\n"
    "in 30s intervals for evey dupla in secret[['name', 'encoded_key'], ... ].\n"
    "    If param is 'e', secrets in secret[] are encoded with xor\n"
    "and printed as base64 ready for reinsertion in secret[].\n"
    "    If param is the string used as xor key, secrets in secret[]\n"
    "are decoded and printed.\n" )

first_use_message = ( "\n"
    "For 1st use:\n"
    "\t* edit this file filling the 'secret' array\n"
    "\t* choose a 'mangling_string'\n"
    "\t* run `python3 twisted2sv.py e`\n"
    "\t* refill your 'secret' array with that/those new values\n" )

# this is the secret[] array you have to first fill with your TOTP key(s)
# and then rewrite after `python3 twisted2sv.py e`
secret = [
    ['',  'MZXW633PN5XW6MZX'], 
    #['site2',    'MZXW633PN5XW6MZY'],
    #['site3',    'MZXW633PN5XW6MZZ'], # ...
        ]

# this is the random key you have to choose to xor your TOTP keys. 
# It's a totally unimportant value with arbitrary length... ASCII only!
mangling_string = '8bJ3f5xn7wgFa9bv'


#.................................................


import hmac, base64, struct, hashlib, time
from sys import argv


# patched from https://stackoverflow.com/questions/8529265/google-authenticator-implementation-in-python
def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)

# xor_crypt_string patched from https://gist.github.com/revolunet/2412240
def xor_crypt_string(data, key='awesomepassword', encode=False, decode=False):
    from sys import byteorder
    import base64
    if decode:
        data = base64.decodestring(bytearray(data, 'ascii'))
    else:
        data = bytearray(data, 'ascii')
    while (len(data)>len(key)):
        key += key
    key = key[:len(data)]
    key = bytearray(key, 'ascii')
    int_data = int.from_bytes(data, byteorder)
    int_key = int.from_bytes(key, byteorder)
    int_enc = int_data ^ int_key
    int_enc = int_enc.to_bytes(len(data), byteorder)
    if encode:
        return base64.encodestring(int_enc).strip()
    return int_enc


iterations = 2
action = ''

# extract params:
if (len(argv)>1):
    if (argv[1] == '-?' or argv[1] == '?'):
        print ( version_string + 
                help_message )
        exit (0)
    else:
        try:
            if (argv[1] == 'e'):
                action = 'e'
            elif (argv[1] == mangling_string):
                action = 'd'
            elif (int(argv[1])>=0):
                iterations = int(argv[1])
        except:
            print ("Iterations must be a positive number, not '%s'\n"%argv[1])
            exit (1)

for i in range(1, iterations + 1):

    for key in secret:
        
        # print key identifier:
        if (len(key[0])!=0):
            print ( "%s:\t"%key[0], end='' )

        if (action == 'e'):
            # encode secret[] keys with mangling_string:
            print ( xor_crypt_string(key[1], mangling_string, encode = True).decode('ascii') )
        elif (action == 'd'):
            # show plain secret[] keys:
            print ( xor_crypt_string(key[1], mangling_string, decode = True).decode('ascii') )
        else:
            try:
                # print 2SV TOTP Code !
                print ( '(%d) %06d'%( i , get_totp_token( xor_crypt_string(key[1], mangling_string, decode = True) ) ) )
            except:
                # secret[] keys have not been yet encoded:
                print (version_string + 
                    first_use_message )
                exit (2)
    
    if ( action != '' ):
        exit (0)

    # funny 30s reverse time counter:
    delay = ((int(time.time())//30+1)*30 - int(time.time()))
    for j in range(delay, 0, -1):
        print ( '(%d) '%j , end="\r" )
        time.sleep(1)
    print ( ' '*10 )
