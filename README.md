# Bitcoin Transaction Decoder

This project decodes a raw Bitcoin transaction hex into its components.

## Features

- Supports SegWit transactions
- Parses inputs and outputs
- Decodes witness data
- Handles VarInt encoding
- Displays transaction structure

## Files

manual-decode.md – Manual decoding of the transaction  
decoder.py – Python transaction decoder  
output.txt – Program output  

## How to Run

Install Python if needed.

Run:

python3 decoder.py

To save output:

python3 decoder.py > output.txt
