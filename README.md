# twisted2sv 

2 Step Verification TOTP python script with mangled TOTP keys
so a casual inspection couldn't retrieve them
 
    $ python3 twisted2sv.py [iterations/action]

With no params, script returns #iterations (2) consecutive TOTP tokens in 30s intervals for evey dupla in secret[['name', 'encoded_key'], ... ].    

If param is 'e', secrets in secret[] are encoded with xor and printed as base64 ready for reinsertion in secret[].    

If param is the string used as xor key, secrets in secret[] are decoded and printed.\n    


# first use setup

* edit this file filling the 'secret' array
* choose a 'mangling_string'
* run `python3 twisted2sv.py`: the script will rewrite itself with encrypted keys
* ready to use!

# code to fill manually before first run:
    # this is the secret[] array you have to first fill with your TOTP key(s)
    secret = [
        ['',  'MZXW633PN5XW6MZX'], 
        #['site2',    'MZXW633PN5XW6MZY'],
        #['site3',    'MZXW633PN5XW6MZZ'], # ...
            ]

    # this is the random key you have to choose to xor your TOTP keys. 
    # It's a totally unimportant value with arbitrary length... ASCII only!
    mangling_string = '8bJ3f5xn7wgFa9bv'

# licence
[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

# author
by circulosmeos, Dec 2017