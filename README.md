# twisted2sv 

2 Step Verification TOTP python script with mangled TOTP keys
so a casual inspection couldn't retrieve them
 
    $ python3 twisted2sv.py [iterations/action/?]

With no params, script returns #iterations (2) consecutive TOTP tokens in 30s intervals for evey dupla in secret[['name', 'encoded_key'], ... ].    
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

# example of use

    $ vi twisted2sv.py #<-- insert your TOTP key(s)
    $ python3 twisted2sv.py
    Auto-phagocytizing to encrypt TOTP keys ...
    Done.
    $ python3 twisted2sv.py 4 #<-- print 4 sets of tokens (4*30 = 2 minutes time) 
    site1:     (1) 973722 
    my site 2: (1) 008862 

    site1:     (2) 862833 
    my site 2: (2) 274628 
    (13) <-- this decremental counter tells you the seconds until these tokens' death

# licence
[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

# author
by circulosmeos, Dec 2017