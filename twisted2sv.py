#!/usr/bin/python3
# twisted2sv 
# 2 Step Verification TOTP Python3 script with mangled TOTP keys
# so a casual inspection couldn't retrieve them.
# 
# by circulosmeos, Dec 2017
# licenced under GPLv3
#
version_string = ( "\n"
    "twisted2sv - 2 Step Verification TOTP python script v3.0\n"
    "             by circulosmeos under GPLv3\n"
    )

help_message = ( "\n"
    "$ python3 twisted2sv.py [iterations/action]\n\n"
    "    With no params or a number, returns #number (2) consecutive TOTP tokens\n"
    "in 30s intervals for every pair in secret[['name', 'key'], ... ].\n\n"
    #"    If param is 'e', secrets in secret[] are encoded with xor\n"
    #"and printed as base64 ready for manual reinsertion in secret[].\n\n"
    "    If param is the string used as xor key, secrets in secret[]\n"
    "are decoded and printed.\n\n"
    "    If param is 'Delete', secrets in secret[] are randomized\n"
    "so the script seems valid BUT TOKENS WON'T BE USEFUL AT ALL.\n\n"
    "    Please, note that on first run this script overwrites itself\n"
    "in order to encrypt the keys you'd have previously written in it.\n"
    )

#.................................................
#.................................................
#.................................................
# This is the secret[] array you have to first fill with your TOTP key(s).
# You can later add new clear keys AFTER THE PREVIOUS ONES: the
# script will detect and encrypt them on the next run
secret = [
    ['site1',    'MZXW633PN5XW6MZX'],
    #['site2',    'MZXW633PN5XW6MZY'],
    #['site3',    'MZXW633PN5XW6MZZ'], # ...
        ]
#.................................................
#.................................................
#.................................................


#.................................................


import hmac, base64, struct, hashlib, time, re
from sys import argv
from string import ascii_letters, digits
from random import choice

# mangling_chars should be safe for command line use (for decryption option)
mangling_chars = ascii_letters + digits + '_'
# This is a random key you have to choose to xor your TOTP keys. 
# Do not modify: the script will generate a new random one on first run,
# and it will overwrite this value
mangling_string = '8bJ3f5xn7wgFa9bv'

DELETE_ACTION_STRING = 'Delete'

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
# and https://stackoverflow.com/questions/29408173/byte-operations-xor-in-python
def xor_crypt_string(data, key='awesomepassword', encode=False, decode=False):
    from sys import byteorder
    import base64
    if decode:
        data = base64.decodebytes(bytearray(data, 'ascii'))
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
        return base64.encodebytes(int_enc).strip()
    return int_enc

# random.choices() exists only since 3.6
def random_choices( mangling_chars, k=1):
    string = ''
    while ( len(string) < k ):
        string += choice(mangling_chars)
    return string

# Auto-phagocytize function:
# It reads this script and replace strings (keys/mangling_string) with their (encrypted/random) counterpart.
# Default action 'e' (encrypt) will encrypt all keys if the key passed is the first key on secret[],
#   or aonly the key passed on any other case.
# Action DELETE_ACTION_STRING will overwrite all keys and the mangling_string with random values.
def auto_phagocytize(key, action='e'):
    # https://stackoverflow.com/questions/9264763/unboundlocalerror-in-python
    global mangling_string
    # may be this is not the first key, so there're already encrypted keys:
    # encrypt just this one!
    key_to_encrypt = ''

    if (action == DELETE_ACTION_STRING):
        print ( "\nDeleting keys !" )
        print ( "\nPlease note that new tokens WON'T BE VALID !\n" )
    elif (secret[0][1] != key[1]):
        key_to_encrypt = key[1]
        print ( "\nNew clear key detected !\n" )

    print ( "Auto-phagocytizing to %s TOTP keys ...\n"% ('wipe out' if (action==DELETE_ACTION_STRING) else 'encrypt') )

    twisted_value = {}
    # generate a new random mangling_string in case there're no previoous keys encrypted
    if (key_to_encrypt == ''):
        new_mangling_string = random_choices(mangling_chars, k=32)
        twisted_value[mangling_string] = new_mangling_string
        mangling_string = new_mangling_string

    # calculate encrypted keys
    for clear_key in secret:
        # but if there were previoously encrypted keys, encrypt just the one detected (key_to_encrypt)
        if (key_to_encrypt != '' and clear_key[1] != key_to_encrypt):
            continue
        if (action == DELETE_ACTION_STRING):
            print ("deleting key %s..."%clear_key[0])
            twisted_value[clear_key[1]] = xor_crypt_string( 
                base64.b32encode(bytearray( random_choices(mangling_chars, k=10), 'ascii')).decode('ascii'), 
                mangling_string, encode = True ).decode('ascii')
        else:
            twisted_value[clear_key[1]] = xor_crypt_string( clear_key[1], 
                mangling_string, encode = True ).decode('ascii')

    # open this script:
    this_very_same_file = open(argv[0], 'r')
    # go line by line, replacing the keys with their encrypted counterpart;
    # also the mangling_string will be overwritten with new_mangling_string value.
    this_very_same_file_modified = ''
    for line in this_very_same_file:
        for previous_value in twisted_value.keys():
            if re.search("'" + previous_value + "'", line):
                this_very_same_file_modified += re.sub(
                    "^(.*')" + previous_value + "('.*)",
                    # https://stackoverflow.com/questions/5984633/python-re-sub-group-number-after-number
                    r"\g<1>" + twisted_value[previous_value] + r"\2", line )
                break
        else:
            this_very_same_file_modified += line
    this_very_same_file.close()

    # now write the new script with the substitued (encrypted) keys:
    this_very_same_file = open (argv[0], 'w')
    this_very_same_file.write( this_very_same_file_modified )
    this_very_same_file.close()
    print ( "Done.\n" )


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
            elif (argv[1] == DELETE_ACTION_STRING):
                action = DELETE_ACTION_STRING
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
        if (action != '' and action != DELETE_ACTION_STRING):
            print ( "%s:\t"%key[0], end='' )

        if (action == 'e'):
            # encode secret[] keys with mangling_string and just print the result:
            print ( xor_crypt_string(key[1], mangling_string, encode = True).decode('ascii') )
        elif (action == 'd'):
            # show plain secret[] keys:
            try:
                print ( xor_crypt_string(key[1], mangling_string, decode = True).decode('ascii') )
            except:
                print ( "This key is in plain text, so no decryption is necessary.\n" )
        elif (action == DELETE_ACTION_STRING):
            auto_phagocytize ( key, action)
            break
        else:
            try:
                # print 2SV TOTP Code !
                print ( "%s:\t(%d) %06d" % ( key[0], i , get_totp_token( xor_crypt_string(key[1], mangling_string, decode = True) ) ) )
            except:
                # secret[] keys have not been yet encoded:
                auto_phagocytize ( key )
                action ='e'
                break
    
    if ( action != '' ):
        exit (0)

    # funny 30s reverse time counter:
    delay = ((int(time.time())//30+1)*30 - int(time.time()))
    for j in range(delay, 0, -1):
        print ( '(%d) '%j , end="\r" )
        time.sleep(1)
    print ( ' '*10 )
