🔐 Hash Identifier
A simple Python cybersecurity tool that identifies the possible type of a hash based on its prefix, length, character set, and known format patterns.

This project was created as a learning project to practice Python programming and understand basic concepts related to hash identification.

Note: This tool identifies hash formats. It does not crack passwords or recover the original password.

📌 Features
Identify common hash formats
Check known hash prefixes
Check hash length
Check hexadecimal character sets
Recognize special hash formats
Return confidence levels:
High
Medium
Low
Explain why a hash was identified
Command-line interface
Automated tests using pytest
📂 Project Structure
hash-identifier/
│
├── hash_identifier.py
├── test_hash_identifier.py
└── README.md

hash_identifier.py
The main application that analyzes the input and identifies possible hash types.

test_hash_identifier.py
The testing file that checks whether the main application works correctly.

README.md
Project documentation explaining how the tool works and how to use it.

🧠 How Hash Identification Works
The program analyzes a hash through several stages.

Input Hash
    ↓
Analyze the input
    ↓
Check prefix
    ↓
Check special formats
    ↓
Check length and character set
    ↓
Find possible hash types
    ↓
Display result

The program does not guarantee that a hash is identified correctly.

It provides possible candidates based on recognizable characteristics.

1. Prefix Matching
Some hash formats have recognizable prefixes.

For example:

$2b$

is associated with bcrypt.

The program checks whether the input starts with a known prefix:

text.startswith(prefix)

Example:

$2b$12$...
     ↓
  bcrypt
     ↓
high confidence

Known prefixes include formats such as:

bcrypt
Argon2
SHA-512 crypt
SHA-256 crypt
MD5 crypt
Apache MD5-crypt
yescrypt
phpass
Django password hashes
LDAP password formats
2. Special Formats
The program also checks formats that have recognizable structures.

Examples include:

MySQL5
NetNTLMv1
NetNTLMv2
DES crypt
These formats are checked before normal hexadecimal length matching.

For example, a MySQL5 hash looks like:

*A4B6157319038724E3560894F7F932C8886EBFCF

The program checks for:

*
+
40 uppercase hexadecimal characters

3. Hexadecimal Length
If the input contains only hexadecimal characters, the program checks its length.

For example:

32 hexadecimal characters
        ↓
MD5
NTLM
MD4
RIPEMD-128

Another example:

40 hexadecimal characters
        ↓
SHA-1
RIPEMD-160

And:

64 hexadecimal characters
        ↓
SHA-256
SHA3-256
BLAKE2s-256
RIPEMD-256

Different algorithms can produce hashes with the same length.

Therefore, the program may return multiple candidates.

4. Confidence Levels
The program uses three confidence levels.

High
A known prefix or very specific format matches.

Example:

$2b$

Result:

bcrypt
high confidence

Medium
The input has a strong characteristic, but multiple algorithms can have the same characteristic.

Example:

32 hexadecimal characters

Possible results:

MD5
NTLM
MD4
RIPEMD-128

The program considers the first candidate the most likely.

Low
The program recognizes the general shape of the input but cannot confidently determine the exact algorithm.

For example, a generic PHC-style string that does not match one of the known specific prefixes may receive a low-confidence result.

🧪 Demo Hashes
You can use these hashes to test different identification paths.

Input	Detected As	Reason
5f4dcc3b5aa765d61d8327deb882cf99	MD5	32 hexadecimal characters
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	SHA-256	64 hexadecimal characters
$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G	bcrypt	$2b$ prefix
$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG	Argon2id	$argon2id$ prefix
$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/	Apache MD5-crypt	$apr1$ prefix
*A4B6157319038724E3560894F7F932C8886EBFCF	MySQL5	* followed by 40 uppercase hex characters
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...	JWT	Starts with eyJ
🚀 Installation
Make sure Python is installed.

Check your Python version:

python --version

Install the required package:

pip install rich

To run the tests, install pytest:

pip install pytest

💻 How to Use
Run the main program:

python hash_identifier.py "HASH"

Example: MD5
python hash_identifier.py "5f4dcc3b5aa765d61d8327deb882cf99"

The program analyzes the 32-character hexadecimal input and returns possible candidates.

Example: bcrypt
A bcrypt hash begins with:

$2b$

Run:

python hash_identifier.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

The program identifies:

bcrypt

with:

high

confidence.

⚠️ Important: PowerShell and $
If you are using Windows PowerShell, hashes containing $ should be surrounded by single quotes.

❌ Incorrect
python hash_identifier.py $2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G

PowerShell can interpret $ as a variable.

This can cause Python to receive only part of the hash.

For example, instead of receiving:

$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G

the program might receive:

.uK4Of2T7G

✅ Correct
python hash_identifier.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'

This passes the complete hash to Python.

🧪 Running Tests
The project contains:

test_hash_identifier.py

Run all tests with:

pytest

To see detailed test results:

pytest -v

Pytest automatically discovers functions whose names start with:

test_

A successful result will look similar to:

============================= test session starts =============================

collected 46 items

..............................

============================== 46 passed ==============================

The exact number of tests may change if more tests are added later.

🔍 Example Testing Process
The bcrypt test works like this:

Test input
    ↓
"$2b$12$..."
    ↓
identify()
    ↓
Main file analyzes input
    ↓
Returns HashCandidate
    ↓
Test checks:
    algorithm == "bcrypt"
    confidence == "high"
    ↓
PASS ✅

If the main program accidentally changes the result:

Expected: bcrypt
Received: MD5

the test fails:

FAIL ❌

This helps detect bugs when the project is changed or improved.

🔄 How Both Files Work Together
The two Python files have different jobs.

┌─────────────────────────────┐
│     hash_identifier.py      │
│                             │
│       MAIN PROGRAM          │
│                             │
│  Takes input                │
│       ↓                     │
│  Analyzes hash              │
│       ↓                     │
│  Identifies hash type       │
│       ↓                     │
│  Displays result            │
└──────────────┬──────────────┘
               │
               │ tested by
               ▼
┌─────────────────────────────┐
│   test_hash_identifier.py   │
│                             │
│       TEST PROGRAM          │
│                             │
│  Gives known input          │
│       ↓                     │
│  Calls identify()           │
│       ↓                     │
│  Checks expected result     │
│       ↓                     │
│      PASS ✅ / FAIL ❌      │
└─────────────────────────────┘

Simple explanation
hash_identifier.py
        =
Does the work


test_hash_identifier.py
        =
Checks the work

The test file uses the actual functions from the main file.

It does not create a separate version of the hash identifier.

🧪 What the Tests Check
The test file checks different parts of the application, including:

bcrypt prefix
Argon2id prefix
SHA-512 crypt
Django PBKDF2
Apache MD5-crypt
MySQL5
NetNTLMv1
NetNTLMv2
DES crypt
MD5 length
SHA-1 length
SHA-256 length
Empty input
Invalid input
Whitespace around input
JWT detection
Base64 detection
HashCandidate immutability
Every prefix rule
🛠️ Technologies Used
Technology	Purpose
Python	Main programming language
argparse	Command-line argument handling
sys	Python/system interaction
dataclasses	Structured result objects
typing / Literal	Type hints
Rich	Terminal output
pytest	Automated testing
📚 Python Concepts Used
This project provides practice with:

Variables
Strings
Lists
Tuples
Dictionaries
Loops
if statements
Functions
Classes
dataclass
Type hints
Literal
startswith()
Command-line arguments
assert
Exception handling
Python modules and imports
Automated testing
🔒 Security Note
This project is designed for:

Cybersecurity learning
CTFs
Security labs
Authorized security testing
Understanding hash formats
Python programming practice
This tool does not crack hashes.

It only attempts to identify the possible algorithm or format of the supplied input.

Only analyze hashes that you are authorized to examine.

📌 Limitations
Hash identification cannot always determine the exact algorithm.

For example:

32 hexadecimal characters

could represent multiple algorithms:

MD5
NTLM
MD4
RIPEMD-128

Therefore, the tool may return several candidates and rank them by confidence.

The result should be treated as an identification hint, not absolute proof of the algorithm.

🎯 Project Goal
The goal of this project is to build a simple cybersecurity utility while learning:

Python
   +
Cybersecurity
   +
Hash formats
   +
Command-line tools
   +
Automated testing

The project also demonstrates the difference between:

Application code
        ↓
hash_identifier.py

and:

Testing code
        ↓
test_hash_identifier.py

👨‍💻 Learning Outcome
By completing this project, I practiced building a small Python cybersecurity tool and learned how to:

Analyze hash characteristics
Build a command-line Python program
Organize code into functions and classes
Use dataclasses
Use type hints
Write automated tests
Test different input cases
Debug command-line input problems
Understand how application code and testing code work together
📄 License
See the LICENSE file included in this repository.
