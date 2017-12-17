# twisted2sv 

2 Step Verification TOTP python script with mangled TOTP keys
so a casual inspection couldn't retrieve them
 
    $ python3 twisted2sv.py [iterations/action/?]

With no params, script returns #iterations (2) consecutive TOTP tokens in 30s intervals for evey pair in secret[['name', 'encoded_key'], ... ].

If param is the string used as xor key, secrets in secret[] are decoded and printed.
    
If param is 'Delete', secrets in secret[] are randomized so the script seems valid BUT TOKENS WON'T BE USEFUL AT ALL.
    
Please, note that on first run *this script overwrites itself* in order to encrypt the keys you'd have previously written in it.

You can later add new clear keys in secret[] AFTER THE PREVIOUS ONES: the script will detect and encrypt them (rewriting itself again) on the next run.

# first use setup

* edit the script filling the 'secret' array
* run `python3 twisted2sv.py`: the script will rewrite itself with encrypted keys and a random XOR key
* ready to use!

# code to fill manually before first run:
    # This is the secret[] array you have to first fill with your TOTP key(s).
    # You can later add new clear keys AFTER THE PREVIOUS ONES: the
    # script will detect and encrypt them on the next run
    secret = [
        ['',  'MZXW633PN5XW6MZX'], 
        #['site2',    'MZXW633PN5XW6MZY'],
        #['site3',    'MZXW633PN5XW6MZZ'], # ...
            ]

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

# more info

[](https://circulosmeos.wordpress.com/2017/12/16/twisted-2-step-verification-totp-script/)

# licence
[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

# author
by circulosmeos, Dec 2017