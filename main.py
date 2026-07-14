# NOT ACTUAL CODE, I JUST WANTED TO SEE THE BITWISE STUFF WORKING

# Same value: 0x12345
# Binary: 1 0010 0011 0100 0101 
val = 0x12345

# Shift right by 16 bits
# Deletes the bottom 16 bits and leaves only what was above them.
overflow_carry = val >> 16

print(f"Original: {hex(val)}")       # 0x12345
print(f"Overflow Carry: {hex(overflow_carry)}") # 0x1 (Only the overflow remains


# Masking with 0xFFFF (16 ones)
# This keeps the bottom 16 bits and turns the rest to 0.
preserved_bottom = val & 0xFFFF       # 0x12345
print(f"Preserved Bottom: {hex(preserved_bottom)}") # 0x2345 (The '1' is gone)

# Example: Adding two large 16-bit numbers that cause an overflow

# Step: Wrap the carry (the 1 at the top) around to the bottom
# (total_sum & 0xFFFF) extracts the bottom 16 bits (0x0000)
# (total_sum >> 16) extracts the overflow carry (0x0001)
total_sum = (val & 0xFFFF) + (val >> 16)

print(f"Final 16-bit Sum: {hex(total_sum)}") # 0x0001

# 0010 0011 0100 0101
# 0000 0000 0000 0001
# 